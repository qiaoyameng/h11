# This contains the main Connection class. Everything in h11 revolves around
# this.
from copy import deepcopy
from dataclasses import dataclass, field
from typing import (
    Any,
    Callable,
    cast,
    Dict,
    Iterable,
    List,
    Optional,
    overload,
    Tuple,
    Type,
    Union,
)

from ._events import (
    ConnectionClosed,
    Data,
    EndOfMessage,
    Event,
    InformationalResponse,
    Request,
    Response,
)
from ._headers import get_comma_header, has_expect_100_continue, set_comma_header
from ._readers import READERS, ReadersType
from ._receivebuffer import ReceiveBuffer
from ._state import (
    _SWITCH_CONNECT,
    _SWITCH_UPGRADE,
    CLIENT,
    ConnectionState,
    DONE,
    ERROR,
    MIGHT_SWITCH_PROTOCOL,
    SEND_BODY,
    SERVER,
    SWITCHED_PROTOCOL,
)
from ._util import (  # Import the internal things we need
    LocalProtocolError,
    RemoteProtocolError,
    Sentinel,
)
from ._writers import (
    ChunkedWriter,
    ContentLengthWriter,
    Http10Writer,
    WRITERS,
    WritersType,
)

# Everything in __all__ gets re-exported as part of the h11 public API.
__all__ = [
    "Connection",
    "NEED_DATA",
    "PAUSED",
    "Framing",
    "SendPreflightEventResult",
    "SendPreflightResult",
]


class NEED_DATA(Sentinel, metaclass=Sentinel):
    pass


class PAUSED(Sentinel, metaclass=Sentinel):
    pass


@dataclass(frozen=True)
class Framing:
    """The framing that h11 predicts it will use for a message body.

    Attributes:
        kind: One of the strings ``"content-length"``, ``"chunked"``, or
            ``"http/1.0"`` -- these are the same framing modes used
            internally by :func:`~h11._connection._body_framing`.
        length: For ``"content-length"`` framing, the declared body length
            in bytes. :data:`None` for the other framing modes, where the
            body length is not known until the body is finished (or
            forever, in the ``"http/1.0"`` close-delimited case).
    """

    kind: str
    length: Optional[int] = None


@dataclass(frozen=True)
class SendPreflightEventResult:
    """The result of checking one event during a
    :meth:`Connection.preflight_send`.

    Attributes:
        index: This event's position in the sequence passed to
            :meth:`~Connection.preflight_send`.
        event: The event that was checked.
        legal: ``True`` if sending this event at this point is legal;
            ``False`` if it would raise :exc:`LocalProtocolError`.
        framing: If this event opens a message with a body (i.e. it's a
            :class:`Request` or :class:`Response` that moves things into
            :data:`SEND_BODY`), this gives the framing predicted for that
            body. Otherwise :data:`None`.
        states_before: The connection's per-role states immediately
            *before* this event.
        states_after: The connection's per-role states immediately *after*
            this event (or in :data:`ERROR` if it failed).
        waiting_for_100_continue_after: The predicted value of
            :attr:`Connection.client_is_waiting_for_100_continue` after
            this event.
    """

    index: int
    event: Event
    legal: bool
    framing: Optional[Framing] = None
    states_before: Dict[Type[Sentinel], Type[Sentinel]] = field(default_factory=dict)
    states_after: Dict[Type[Sentinel], Type[Sentinel]] = field(default_factory=dict)
    waiting_for_100_continue_after: bool = False


@dataclass(frozen=True)
class SendPreflightResult:
    """The result of a :meth:`Connection.preflight_send` check.

    This does not describe any bytes that would be sent -- the preflight
    never generates a body or otherwise touches the payload data.

    Attributes:
        events: The events that were checked, as a fresh tuple. If a
            one-shot iterator was passed to
            :meth:`~Connection.preflight_send`, then that iterator is
            consumed -- use this tuple to perform the actual sends, e.g.
            ``for event in result.events: conn.send(event)``.
        event_results: One :class:`SendPreflightEventResult` per checked
            event, up to and including the first event that failed (if
            any). Events after a failure are not checked, because the
            connection would be in :data:`ERROR` by then.
        failed_at: The index of the first event that would fail, or
            :data:`None` if no event failed.
        error: The :exc:`LocalProtocolError` that the failing event would
            raise, or :data:`None` if no event failed.
        legal: ``True`` if the whole sequence is legal and complete;
            ``False`` if some event is illegal; :data:`None` if every
            event seen so far is legal, but the sequence ends in the
            middle of a body, where the final verdict depends on payload
            that hasn't been seen yet.
        framing: The framing of the last message opened by the sequence,
            if any.
        states: The predicted per-role states after the whole sequence.
        client_is_waiting_for_100_continue: The predicted value of
            :attr:`Connection.client_is_waiting_for_100_continue` after
            the whole sequence.
    """

    events: Tuple[Event, ...]
    event_results: Tuple[SendPreflightEventResult, ...]
    failed_at: Optional[int]
    error: Optional[LocalProtocolError]
    legal: Optional[bool]
    framing: Optional[Framing]
    states: Dict[Type[Sentinel], Type[Sentinel]]
    client_is_waiting_for_100_continue: bool

    @property
    def undetermined(self) -> bool:
        """True if :attr:`legal` is :data:`None` -- all events seen so
        far are legal, but the sequence is incomplete and its final
        legality depends on not-yet-seen body data."""
        return self.legal is None


# If we ever have this much buffered without it making a complete parseable
# event, we error out. The only time we really buffer is when reading the
# request/response line + headers together, so this is effectively the limit on
# the size of that.
#
# Some precedents for defaults:
# - node.js: 80 * 1024
# - tomcat: 8 * 1024
# - IIS: 16 * 1024
# - Apache: <8 KiB per line>
DEFAULT_MAX_INCOMPLETE_EVENT_SIZE = 16 * 1024


# RFC 7230's rules for connection lifecycles:
# - If either side says they want to close the connection, then the connection
#   must close.
# - HTTP/1.1 defaults to keep-alive unless someone says Connection: close
# - HTTP/1.0 defaults to close unless both sides say Connection: keep-alive
#   (and even this is a mess -- e.g. if you're implementing a proxy then
#   sending Connection: keep-alive is forbidden).
#
# We simplify life by simply not supporting keep-alive with HTTP/1.0 peers. So
# our rule is:
# - If someone says Connection: close, we will close
# - If someone uses HTTP/1.0, we will close.
def _keep_alive(event: Union[Request, Response]) -> bool:
    connection = get_comma_header(event.headers, b"connection")
    if b"close" in connection:
        return False
    if getattr(event, "http_version", b"1.1") < b"1.1":
        return False
    return True


def _body_framing(
    request_method: bytes, event: Union[Request, Response]
) -> Tuple[str, Union[Tuple[()], Tuple[int]]]:
    # Called when we enter SEND_BODY to figure out framing information for
    # this body.
    #
    # These are the only two events that can trigger a SEND_BODY state:
    assert type(event) in (Request, Response)
    # Returns one of:
    #
    #    ("content-length", count)
    #    ("chunked", ())
    #    ("http/1.0", ())
    #
    # which are (lookup key, *args) for constructing body reader/writer
    # objects.
    #
    # Reference: https://tools.ietf.org/html/rfc7230#section-3.3.3
    #
    # Step 1: some responses always have an empty body, regardless of what the
    # headers say.
    if type(event) is Response:
        if (
            event.status_code in (204, 304)
            or request_method == b"HEAD"
            or (request_method == b"CONNECT" and 200 <= event.status_code < 300)
        ):
            return ("content-length", (0,))
        # Section 3.3.3 also lists another case -- responses with status_code
        # < 200. For us these are InformationalResponses, not Responses, so
        # they can't get into this function in the first place.
        assert event.status_code >= 200

    # Step 2: check for Transfer-Encoding (T-E beats C-L):
    transfer_encodings = get_comma_header(event.headers, b"transfer-encoding")
    if transfer_encodings:
        assert transfer_encodings == [b"chunked"]
        return ("chunked", ())

    # Step 3: check for Content-Length
    content_lengths = get_comma_header(event.headers, b"content-length")
    if content_lengths:
        return ("content-length", (int(content_lengths[0]),))

    # Step 4: no applicable headers; fallback/default depends on type
    if type(event) is Request:
        return ("content-length", (0,))
    else:
        return ("http/1.0", ())


################################################################
#
# The main Connection class
#
################################################################


class Connection:
    """An object encapsulating the state of an HTTP connection.

    Args:
        our_role: If you're implementing a client, pass :data:`h11.CLIENT`. If
            you're implementing a server, pass :data:`h11.SERVER`.

        max_incomplete_event_size (int):
            The maximum number of bytes we're willing to buffer of an
            incomplete event. In practice this mostly sets a limit on the
            maximum size of the request/response line + headers. If this is
            exceeded, then :meth:`next_event` will raise
            :exc:`RemoteProtocolError`.

    """

    def __init__(
        self,
        our_role: Type[Sentinel],
        max_incomplete_event_size: int = DEFAULT_MAX_INCOMPLETE_EVENT_SIZE,
    ) -> None:
        self._max_incomplete_event_size = max_incomplete_event_size
        # State and role tracking
        if our_role not in (CLIENT, SERVER):
            raise ValueError(f"expected CLIENT or SERVER, not {our_role!r}")
        self.our_role = our_role
        self.their_role: Type[Sentinel]
        if our_role is CLIENT:
            self.their_role = SERVER
        else:
            self.their_role = CLIENT
        self._cstate = ConnectionState()

        # Callables for converting data->events or vice-versa given the
        # current state
        self._writer = self._get_io_object(self.our_role, None, WRITERS)
        self._reader = self._get_io_object(self.their_role, None, READERS)

        # Holds any unprocessed received data
        self._receive_buffer = ReceiveBuffer()
        # If this is true, then it indicates that the incoming connection was
        # closed *after* the end of whatever's in self._receive_buffer:
        self._receive_buffer_closed = False

        # Extra bits of state that don't fit into the state machine.
        #
        # These two are only used to interpret framing headers for figuring
        # out how to read/write response bodies. their_http_version is also
        # made available as a convenient public API.
        self.their_http_version: Optional[bytes] = None
        self._request_method: Optional[bytes] = None
        # This is pure flow-control and doesn't at all affect the set of legal
        # transitions, so no need to bother ConnectionState with it:
        self.client_is_waiting_for_100_continue = False

    @property
    def states(self) -> Dict[Type[Sentinel], Type[Sentinel]]:
        """A dictionary like::

           {CLIENT: <client state>, SERVER: <server state>}

        See :ref:`state-machine` for details.

        """
        return dict(self._cstate.states)

    @property
    def our_state(self) -> Type[Sentinel]:
        """The current state of whichever role we are playing. See
        :ref:`state-machine` for details.
        """
        return self._cstate.states[self.our_role]

    @property
    def their_state(self) -> Type[Sentinel]:
        """The current state of whichever role we are NOT playing. See
        :ref:`state-machine` for details.
        """
        return self._cstate.states[self.their_role]

    @property
    def they_are_waiting_for_100_continue(self) -> bool:
        return self.their_role is CLIENT and self.client_is_waiting_for_100_continue

    def start_next_cycle(self) -> None:
        """Attempt to reset our connection state for a new request/response
        cycle.

        If both client and server are in :data:`DONE` state, then resets them
        both to :data:`IDLE` state in preparation for a new request/response
        cycle on this same connection. Otherwise, raises a
        :exc:`LocalProtocolError`.

        See :ref:`keepalive-and-pipelining`.

        """
        old_states = dict(self._cstate.states)
        self._cstate.start_next_cycle()
        self._request_method = None
        # self.their_http_version gets left alone, since it presumably lasts
        # beyond a single request/response cycle
        assert not self.client_is_waiting_for_100_continue
        self._respond_to_state_changes(old_states)

    def _process_error(self, role: Type[Sentinel]) -> None:
        old_states = dict(self._cstate.states)
        self._cstate.process_error(role)
        self._respond_to_state_changes(old_states)

    def _server_switch_event(self, event: Event) -> Optional[Type[Sentinel]]:
        if type(event) is InformationalResponse and event.status_code == 101:
            return _SWITCH_UPGRADE
        if type(event) is Response:
            if (
                _SWITCH_CONNECT in self._cstate.pending_switch_proposals
                and 200 <= event.status_code < 300
            ):
                return _SWITCH_CONNECT
        return None

    # All events go through here
    def _process_event(self, role: Type[Sentinel], event: Event) -> None:
        # First, pass the event through the state machine to make sure it
        # succeeds.
        old_states = dict(self._cstate.states)
        if role is CLIENT and type(event) is Request:
            if event.method == b"CONNECT":
                self._cstate.process_client_switch_proposal(_SWITCH_CONNECT)
            if get_comma_header(event.headers, b"upgrade"):
                self._cstate.process_client_switch_proposal(_SWITCH_UPGRADE)
        server_switch_event = None
        if role is SERVER:
            server_switch_event = self._server_switch_event(event)
        self._cstate.process_event(role, type(event), server_switch_event)

        # Then perform the updates triggered by it.

        if type(event) is Request:
            self._request_method = event.method

        if role is self.their_role and type(event) in (
            Request,
            Response,
            InformationalResponse,
        ):
            event = cast(Union[Request, Response, InformationalResponse], event)
            self.their_http_version = event.http_version

        # Keep alive handling
        #
        # RFC 7230 doesn't really say what one should do if Connection: close
        # shows up on a 1xx InformationalResponse. I think the idea is that
        # this is not supposed to happen. In any case, if it does happen, we
        # ignore it.
        if type(event) in (Request, Response) and not _keep_alive(
            cast(Union[Request, Response], event)
        ):
            self._cstate.process_keep_alive_disabled()

        # 100-continue
        if type(event) is Request and has_expect_100_continue(event):
            self.client_is_waiting_for_100_continue = True
        if type(event) in (InformationalResponse, Response):
            self.client_is_waiting_for_100_continue = False
        if role is CLIENT and type(event) in (Data, EndOfMessage):
            self.client_is_waiting_for_100_continue = False

        self._respond_to_state_changes(old_states, event)

    def _get_io_object(
        self,
        role: Type[Sentinel],
        event: Optional[Event],
        io_dict: Union[ReadersType, WritersType],
    ) -> Optional[Callable[..., Any]]:
        # event may be None; it's only used when entering SEND_BODY
        state = self._cstate.states[role]
        if state is SEND_BODY:
            # Special case: the io_dict has a dict of reader/writer factories
            # that depend on the request/response framing.
            framing_type, args = _body_framing(
                cast(bytes, self._request_method), cast(Union[Request, Response], event)
            )
            return io_dict[SEND_BODY][framing_type](*args)  # type: ignore[index]
        else:
            # General case: the io_dict just has the appropriate reader/writer
            # for this state
            return io_dict.get((role, state))  # type: ignore[return-value]

    # This must be called after any action that might have caused
    # self._cstate.states to change.
    def _respond_to_state_changes(
        self,
        old_states: Dict[Type[Sentinel], Type[Sentinel]],
        event: Optional[Event] = None,
    ) -> None:
        # Update reader/writer
        if self.our_state != old_states[self.our_role]:
            self._writer = self._get_io_object(self.our_role, event, WRITERS)
        if self.their_state != old_states[self.their_role]:
            self._reader = self._get_io_object(self.their_role, event, READERS)

    @property
    def trailing_data(self) -> Tuple[bytes, bool]:
        """Data that has been received, but not yet processed, represented as
        a tuple with two elements, where the first is a byte-string containing
        the unprocessed data itself, and the second is a bool that is True if
        the receive connection was closed.

        See :ref:`switching-protocols` for discussion of why you'd want this.
        """
        return (bytes(self._receive_buffer), self._receive_buffer_closed)

    def receive_data(self, data: bytes) -> None:
        """Add data to our internal receive buffer.

        This does not actually do any processing on the data, just stores
        it. To trigger processing, you have to call :meth:`next_event`.

        Args:
            data (:term:`bytes-like object`):
                The new data that was just received.

                Special case: If *data* is an empty byte-string like ``b""``,
                then this indicates that the remote side has closed the
                connection (end of file). Normally this is convenient, because
                standard Python APIs like :meth:`file.read` or
                :meth:`socket.recv` use ``b""`` to indicate end-of-file, while
                other failures to read are indicated using other mechanisms
                like raising :exc:`TimeoutError`. When using such an API you
                can just blindly pass through whatever you get from ``read``
                to :meth:`receive_data`, and everything will work.

                But, if you have an API where reading an empty string is a
                valid non-EOF condition, then you need to be aware of this and
                make sure to check for such strings and avoid passing them to
                :meth:`receive_data`.

        Returns:
            Nothing, but after calling this you should call :meth:`next_event`
            to parse the newly received data.

        Raises:
            RuntimeError:
                Raised if you pass an empty *data*, indicating EOF, and then
                pass a non-empty *data*, indicating more data that somehow
                arrived after the EOF.

                (Calling ``receive_data(b"")`` multiple times is fine,
                and equivalent to calling it once.)

        """
        if data:
            if self._receive_buffer_closed:
                raise RuntimeError("received close, then received more data?")
            self._receive_buffer += data
        else:
            self._receive_buffer_closed = True

    def _extract_next_receive_event(
        self,
    ) -> Union[Event, Type[NEED_DATA], Type[PAUSED]]:
        state = self.their_state
        # We don't pause immediately when they enter DONE, because even in
        # DONE state we can still process a ConnectionClosed() event. But
        # if we have data in our buffer, then we definitely aren't getting
        # a ConnectionClosed() immediately and we need to pause.
        if state is DONE and self._receive_buffer:
            return PAUSED
        if state is MIGHT_SWITCH_PROTOCOL or state is SWITCHED_PROTOCOL:
            return PAUSED
        assert self._reader is not None
        event = self._reader(self._receive_buffer)
        if event is None:
            if not self._receive_buffer and self._receive_buffer_closed:
                # In some unusual cases (basically just HTTP/1.0 bodies), EOF
                # triggers an actual protocol event; in that case, we want to
                # return that event, and then the state will change and we'll
                # get called again to generate the actual ConnectionClosed().
                if hasattr(self._reader, "read_eof"):
                    event = self._reader.read_eof()
                else:
                    event = ConnectionClosed()
        if event is None:
            event = NEED_DATA
        return event  # type: ignore[no-any-return]

    def next_event(self) -> Union[Event, Type[NEED_DATA], Type[PAUSED]]:
        """Parse the next event out of our receive buffer, update our internal
        state, and return it.

        This is a mutating operation -- think of it like calling :func:`next`
        on an iterator.

        Returns:
            : One of three things:

            1) An event object -- see :ref:`events`.

            2) The special constant :data:`NEED_DATA`, which indicates that
               you need to read more data from your socket and pass it to
               :meth:`receive_data` before this method will be able to return
               any more events.

            3) The special constant :data:`PAUSED`, which indicates that we
               are not in a state where we can process incoming data (usually
               because the peer has finished their part of the current
               request/response cycle, and you have not yet called
               :meth:`start_next_cycle`). See :ref:`flow-control` for details.

        Raises:
            RemoteProtocolError:
                The peer has misbehaved. You should close the connection
                (possibly after sending some kind of 4xx response).

        Once this method returns :class:`ConnectionClosed` once, then all
        subsequent calls will also return :class:`ConnectionClosed`.

        If this method raises any exception besides :exc:`RemoteProtocolError`
        then that's a bug -- if it happens please file a bug report!

        If this method raises any exception then it also sets
        :attr:`Connection.their_state` to :data:`ERROR` -- see
        :ref:`error-handling` for discussion.

        """

        if self.their_state is ERROR:
            raise RemoteProtocolError("Can't receive data when peer state is ERROR")
        try:
            event = self._extract_next_receive_event()
            if event not in [NEED_DATA, PAUSED]:
                self._process_event(self.their_role, cast(Event, event))
            if event is NEED_DATA:
                if len(self._receive_buffer) > self._max_incomplete_event_size:
                    # 431 is "Request header fields too large" which is pretty
                    # much the only situation where we can get here
                    raise RemoteProtocolError(
                        "Receive buffer too long", error_status_hint=431
                    )
                if self._receive_buffer_closed:
                    # We're still trying to complete some event, but that's
                    # never going to happen because no more data is coming
                    raise RemoteProtocolError("peer unexpectedly closed connection")
            return event
        except BaseException as exc:
            self._process_error(self.their_role)
            if isinstance(exc, LocalProtocolError):
                exc._reraise_as_remote_protocol_error()
            else:
                raise

    @overload
    def send(self, event: ConnectionClosed) -> None:
        ...

    @overload
    def send(
        self, event: Union[Request, InformationalResponse, Response, Data, EndOfMessage]
    ) -> bytes:
        ...

    @overload
    def send(self, event: Event) -> Optional[bytes]:
        ...

    def send(self, event: Event) -> Optional[bytes]:
        """Convert a high-level event into bytes that can be sent to the peer,
        while updating our internal state machine.

        Args:
            event: The :ref:`event <events>` to send.

        Returns:
            If ``type(event) is ConnectionClosed``, then returns
            ``None``. Otherwise, returns a :term:`bytes-like object`.

        Raises:
            LocalProtocolError:
                Sending this event at this time would violate our
                understanding of the HTTP/1.1 protocol.

        If this method raises any exception then it also sets
        :attr:`Connection.our_state` to :data:`ERROR` -- see
        :ref:`error-handling` for discussion.

        """
        data_list = self.send_with_data_passthrough(event)
        if data_list is None:
            return None
        else:
            return b"".join(data_list)

    def send_with_data_passthrough(self, event: Event) -> Optional[List[bytes]]:
        """Identical to :meth:`send`, except that in situations where
        :meth:`send` returns a single :term:`bytes-like object`, this instead
        returns a list of them -- and when sending a :class:`Data` event, this
        list is guaranteed to contain the exact object you passed in as
        :attr:`Data.data`. See :ref:`sendfile` for discussion.

        """
        if self.our_state is ERROR:
            raise LocalProtocolError("Can't send data when our state is ERROR")
        data_list: List[bytes] = []
        try:
            self._write_event(event, data_list.append)
        except:
            self._process_error(self.our_role)
            raise
        if type(event) is ConnectionClosed:
            return None
        return data_list

    def _write_event(
        self, event: Event, write: Callable[[Any], None]
    ) -> Event:
        # Shared core of send_with_data_passthrough and preflight_send: runs
        # the state machine and the writer for one event, handing every
        # emitted chunk to 'write'. For a Response, returns the
        # header-cleaned version that was actually checked; otherwise the
        # event passed in. Does not check for ERROR state or call
        # _process_error -- the caller is responsible for those.
        if type(event) is Response:
            event = self._clean_up_response_headers_for_sending(event)
        # We want to call _process_event before calling the writer,
        # because if someone tries to do something invalid then this will
        # give a sensible error message, while our writers all just assume
        # they will only receive valid events. But, _process_event might
        # change self._writer. So we have to do a little dance:
        writer = self._writer
        self._process_event(self.our_role, event)
        if type(event) is not ConnectionClosed:
            # In any situation where writer is None, process_event should
            # have raised ProtocolError
            assert writer is not None
            writer(event, write)
        return event

    def send_failed(self) -> None:
        """Notify the state machine that we failed to send the data it gave
        us.

        This causes :attr:`Connection.our_state` to immediately become
        :data:`ERROR` -- see :ref:`error-handling` for discussion.

        """
        self._process_error(self.our_role)

    @overload
    def preflight_send(self, event: Iterable[Event]) -> SendPreflightResult:
        ...

    @overload
    def preflight_send(self, event: Event) -> SendPreflightResult:
        ...

    def preflight_send(
        self, event: Union[Event, Iterable[Event]]
    ) -> SendPreflightResult:
        """Check whether one or more events could be sent, without
        actually sending them.

        This simulates running :meth:`send` on a throwaway copy of the
        connection, so:

        * the real connection's state is left completely untouched -- the
          actual sends performed afterwards will get exactly the same
          legality verdict;
        * no bytes are generated or buffered (the writers' output is
          discarded), and the payload objects in :class:`Data` events are
          only inspected via :func:`len`, so one-shot payloads like
          :ref:`sendfile` placeholders are not consumed.

        Args:
            event: A single :ref:`event <events>` or an iterable of
                events. If a one-shot iterator is passed, it will be
                consumed here -- but the checked events are returned on
                the result's ``events`` attribute, so you can iterate
                that tuple to perform the actual sends.

        Returns:
            A :class:`SendPreflightResult` describing the predicted
            framing, the position of the first failing event (if any),
            and the predicted states. For parts whose legality depends on
            body data that hasn't been provided yet (e.g. a sequence that
            ends mid-body, where it's not yet known whether the
            ``Content-Length`` contract will be satisfied), the verdict
            is reported as undetermined -- ``legal`` is :data:`None` and
            ``undetermined`` is ``True`` -- rather than guessed.

        Raises:
            LocalProtocolError: if the connection is already in
                :data:`ERROR`, in which case no events could possibly be
                sent. The real connection is left in :data:`ERROR`.

        """
        if self.our_state is ERROR:
            raise LocalProtocolError("Can't send data when our state is ERROR")

        if isinstance(event, Event):
            events = (event,)
        else:
            # Materialize here so that (a) we know each event's position,
            # and (b) the caller gets a re-iterable copy back on the
            # result.
            events = tuple(event)

        # All the simulation happens on a copy, so no matter what happens
        # the real connection is untouched.
        sim = deepcopy(self)

        def discard(chunk: Any) -> None:
            pass

        event_results: List[SendPreflightEventResult] = []
        framing: Optional[Framing] = self._active_body_framing(sim)
        failed_at: Optional[int] = None
        error: Optional[LocalProtocolError] = None

        for index, original_event in enumerate(events):
            states_before = dict(sim._cstate.states)
            checked_event = original_event
            event_framing: Optional[Framing] = None
            legal = True
            try:
                checked_event = sim._write_event(original_event, discard)
            except LocalProtocolError as exc:
                # Mirror send(): the failed event puts us into ERROR.
                sim._process_error(sim.our_role)
                legal = False
                failed_at = index
                error = exc

            if legal and sim.our_state is SEND_BODY:
                if states_before[sim.our_role] is not SEND_BODY:
                    framing = self._predict_framing(sim, checked_event)
                    event_framing = framing
            event_results.append(
                SendPreflightEventResult(
                    index=index,
                    event=original_event,
                    legal=legal,
                    framing=event_framing,
                    states_before=states_before,
                    states_after=dict(sim._cstate.states),
                    waiting_for_100_continue_after=(
                        sim.client_is_waiting_for_100_continue
                    ),
                )
            )
            if not legal:
                break

        if failed_at is not None:
            legal_verdict: Optional[bool] = False
        elif sim.our_state is SEND_BODY:
            # The sequence stopped in the middle of a message. Whether the
            # message will eventually be legal depends on the rest of the
            # body (e.g. whether the Content-Length contract is met),
            # which we haven't seen yet.
            legal_verdict = None
        else:
            legal_verdict = True

        return SendPreflightResult(
            events=events,
            event_results=tuple(event_results),
            failed_at=failed_at,
            error=error,
            legal=legal_verdict,
            framing=framing,
            states=dict(sim._cstate.states),
            client_is_waiting_for_100_continue=sim.client_is_waiting_for_100_continue,
        )

    @staticmethod
    def _predict_framing(sim: "Connection", event: Event) -> Framing:
        # Must match the framing that _get_io_object actually picks when
        # entering SEND_BODY.
        method = sim._request_method
        framing_type, args = _body_framing(
            cast(bytes, method), cast(Union[Request, Response], event)
        )
        length: Optional[int]
        if framing_type == "content-length":
            (length,) = cast(Tuple[int], args)
        else:
            length = None
        return Framing(kind=framing_type, length=length)

    @staticmethod
    def _active_body_framing(sim: "Connection") -> Optional[Framing]:
        # Framing for a body that was already open when the preflight
        # started, derived from the live writer. The declared total length
        # isn't recoverable from the writer at this point, so only the
        # mode is reported for content-length framing.
        if sim.our_state is not SEND_BODY or sim._writer is None:
            return None
        writer = sim._writer
        if isinstance(writer, ContentLengthWriter):
            return Framing(kind="content-length")
        if isinstance(writer, ChunkedWriter):
            return Framing(kind="chunked")
        if isinstance(writer, Http10Writer):
            return Framing(kind="http/1.0")
        return None

    # When sending a Response, we take responsibility for a few things:
    #
    # - Sometimes you MUST set Connection: close. We take care of those
    #   times. (You can also set it yourself if you want, and if you do then
    #   we'll respect that and close the connection at the right time. But you
    #   don't have to worry about that unless you want to.)
    #
    # - The user has to set Content-Length if they want it. Otherwise, for
    #   responses that have bodies (e.g. not HEAD), then we will automatically
    #   select the right mechanism for streaming a body of unknown length,
    #   which depends on depending on the peer's HTTP version.
    #
    # This function's *only* responsibility is making sure headers are set up
    # right -- everything downstream just looks at the headers. There are no
    # side channels.
    def _clean_up_response_headers_for_sending(self, response: Response) -> Response:
        assert type(response) is Response

        headers = response.headers
        need_close = False

        # HEAD requests need some special handling: they always act like they
        # have Content-Length: 0, and that's how _body_framing treats
        # them. But their headers are supposed to match what we would send if
        # the request was a GET. (Technically there is one deviation allowed:
        # we're allowed to leave out the framing headers -- see
        # https://tools.ietf.org/html/rfc7231#section-4.3.2 . But it's just as
        # easy to get them right.)
        method_for_choosing_headers = cast(bytes, self._request_method)
        if method_for_choosing_headers == b"HEAD":
            method_for_choosing_headers = b"GET"
        framing_type, _ = _body_framing(method_for_choosing_headers, response)
        if framing_type in ("chunked", "http/1.0"):
            # This response has a body of unknown length.
            # If our peer is HTTP/1.1, we use Transfer-Encoding: chunked
            # If our peer is HTTP/1.0, we use no framing headers, and close the
            # connection afterwards.
            #
            # Make sure to clear Content-Length (in principle user could have
            # set both and then we ignored Content-Length b/c
            # Transfer-Encoding overwrote it -- this would be naughty of them,
            # but the HTTP spec says that if our peer does this then we have
            # to fix it instead of erroring out, so we'll accord the user the
            # same respect).
            headers = set_comma_header(headers, b"content-length", [])
            if self.their_http_version is None or self.their_http_version < b"1.1":
                # Either we never got a valid request and are sending back an
                # error (their_http_version is None), so we assume the worst;
                # or else we did get a valid HTTP/1.0 request, so we know that
                # they don't understand chunked encoding.
                headers = set_comma_header(headers, b"transfer-encoding", [])
                # This is actually redundant ATM, since currently we
                # unconditionally disable keep-alive when talking to HTTP/1.0
                # peers. But let's be defensive just in case we add
                # Connection: keep-alive support later:
                if self._request_method != b"HEAD":
                    need_close = True
            else:
                headers = set_comma_header(headers, b"transfer-encoding", [b"chunked"])

        if not self._cstate.keep_alive or need_close:
            # Make sure Connection: close is set
            connection = set(get_comma_header(headers, b"connection"))
            connection.discard(b"keep-alive")
            connection.add(b"close")
            headers = set_comma_header(headers, b"connection", sorted(connection))

        return Response(
            headers=headers,
            status_code=response.status_code,
            http_version=response.http_version,
            reason=response.reason,
        )
