# This contains the main Connection class. Everything in h11 revolves around
# this.
import base64
from typing import (
    Any,
    Callable,
    cast,
    Dict,
    List,
    Mapping,
    Optional,
    overload,
    Set,
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
from ._readers import (
    ChunkedReader,
    ContentLengthReader,
    Http10Reader,
    READERS,
    ReadersType,
)
from ._receivebuffer import ReceiveBuffer
from ._state import (
    _SWITCH_CONNECT,
    _SWITCH_UPGRADE,
    CLIENT,
    CLOSED,
    ConnectionState,
    DONE,
    ERROR,
    IDLE,
    MIGHT_SWITCH_PROTOCOL,
    MUST_CLOSE,
    SEND_BODY,
    SEND_RESPONSE,
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
__all__ = ["Connection", "NEED_DATA", "PAUSED"]


class NEED_DATA(Sentinel, metaclass=Sentinel):
    pass


class PAUSED(Sentinel, metaclass=Sentinel):
    pass


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
STATE_FORMAT_VERSION = 1

_ROLE_NAMES = {CLIENT: "client", SERVER: "server"}
_ROLES_BY_NAME = {value: key for key, value in _ROLE_NAMES.items()}
_STATE_NAMES = {
    state: state.__name__
    for state in (
        CLIENT,
        SERVER,
        DONE,
        SEND_BODY,
        SEND_RESPONSE,
        MIGHT_SWITCH_PROTOCOL,
        SWITCHED_PROTOCOL,
        ERROR,
        IDLE,
        MUST_CLOSE,
        CLOSED,
    )
}
_STATES_BY_NAME = {
    name: state for state, name in _STATE_NAMES.items() if state not in (CLIENT, SERVER)
}
_SWITCH_NAMES = {_SWITCH_CONNECT: "connect", _SWITCH_UPGRADE: "upgrade"}
_SWITCHES_BY_NAME = {value: key for key, value in _SWITCH_NAMES.items()}

_READER_TYPES = {
    "chunked": ChunkedReader,
    "content-length": ContentLengthReader,
    "http/1.0": Http10Reader,
}
_WRITER_TYPES = {
    "chunked": ChunkedWriter,
    "content-length": ContentLengthWriter,
    "http/1.0": Http10Writer,
}
_COMPATIBLE_STATES = {
    IDLE: (IDLE, SEND_RESPONSE, ERROR),
    SEND_RESPONSE: (),
    SEND_BODY: (
        IDLE,
        SEND_RESPONSE,
        SEND_BODY,
        DONE,
        MUST_CLOSE,
        CLOSED,
        ERROR,
    ),
    DONE: (
        IDLE,
        SEND_RESPONSE,
        SEND_BODY,
        DONE,
        MUST_CLOSE,
        CLOSED,
        ERROR,
    ),
    MUST_CLOSE: (
        IDLE,
        SEND_RESPONSE,
        SEND_BODY,
        DONE,
        MUST_CLOSE,
        CLOSED,
        ERROR,
    ),
    CLOSED: (
        SEND_RESPONSE,
        SEND_BODY,
        DONE,
        MUST_CLOSE,
        CLOSED,
        ERROR,
    ),
    MIGHT_SWITCH_PROTOCOL: (IDLE, SEND_RESPONSE, ERROR),
    SWITCHED_PROTOCOL: (SWITCHED_PROTOCOL,),
    ERROR: (IDLE, SEND_RESPONSE, SEND_BODY, DONE, MUST_CLOSE, CLOSED, ERROR),
}


def _snapshot_error(message: str) -> None:
    raise ValueError(f"invalid connection state snapshot: {message}")


def _require_mapping(value: Any, name: str) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        _snapshot_error(f"{name} must be an object")
    return dict(value)


def _require_exact_keys(value: Mapping[str, Any], keys: Set[str], name: str) -> None:
    actual = set(value)
    missing = keys - actual
    unknown = actual - keys
    if missing or unknown:
        details = []
        if missing:
            details.append(f"missing {sorted(missing)}")
        if unknown:
            details.append(f"unknown {sorted(unknown)}")
        _snapshot_error(f"{name} has invalid keys ({'; '.join(details)})")


def _require_str(value: Any, name: str) -> str:
    if not isinstance(value, str):
        _snapshot_error(f"{name} must be a string")
    return value


def _require_bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        _snapshot_error(f"{name} must be a boolean")
    return value


def _require_int(value: Any, name: str, minimum: Optional[int] = None) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        _snapshot_error(f"{name} must be an integer")
    if minimum is not None and value < minimum:
        _snapshot_error(f"{name} must be >= {minimum}")
    return value


def _encode_bytes(value: Optional[bytes]) -> Optional[str]:
    if value is None:
        return None
    return base64.b64encode(value).decode("ascii")


def _snapshot_bytes(value: object) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    _snapshot_error("expected bytes")
    raise AssertionError("unreachable")


def _decode_bytes(value: Any, name: str, *, required: bool = False) -> Optional[bytes]:
    if value is None:
        if required:
            _snapshot_error(f"{name} is required")
        return None
    text = _require_str(value, name)
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError):
        _snapshot_error(f"{name} must be valid base64")
        raise AssertionError("unreachable")


def _lookup(value: Any, mapping: Mapping[str, Any], name: str) -> Any:
    text = _require_str(value, name)
    try:
        return mapping[text]
    except KeyError:
        _snapshot_error(f"unknown {name} {text!r}")


def _decode_body_snapshot(
    value: Any,
    name: str,
    io_types: Mapping[str, type],
) -> Optional[Tuple[type, Dict[str, Any]]]:
    if value is None:
        return None
    snapshot = _require_mapping(value, name)
    framing = _lookup(snapshot.get("framing"), io_types, f"{name}.framing")
    return framing, snapshot


def _build_body_io(
    value: Any,
    name: str,
    io_types: Mapping[str, type],
    *,
    is_reader: bool,
) -> Any:
    decoded = _decode_body_snapshot(value, name, io_types)
    if decoded is None:
        return None
    io_type, snapshot = decoded

    if io_type is ContentLengthReader or io_type is ContentLengthWriter:
        expected_keys = {"framing", "length", "remaining"} if is_reader else {
            "framing",
            "remaining",
        }
        _require_exact_keys(snapshot, expected_keys, name)
        if is_reader:
            length = _require_int(snapshot["length"], f"{name}.length", 0)
            remaining = _require_int(snapshot["remaining"], f"{name}.remaining", 0)
            if remaining > length:
                _snapshot_error(f"{name}.remaining is greater than {name}.length")
        else:
            remaining = _require_int(snapshot["remaining"], f"{name}.remaining", 0)
        return io_type._from_snapshot(snapshot)

    if io_type is ChunkedReader:
        _require_exact_keys(
            snapshot,
            {"framing", "bytes_in_chunk", "bytes_to_discard", "reading_trailer"},
            name,
        )
        bytes_in_chunk = _require_int(
            snapshot["bytes_in_chunk"], f"{name}.bytes_in_chunk", 0
        )
        bytes_to_discard = _decode_bytes(
            snapshot["bytes_to_discard"], f"{name}.bytes_to_discard", required=True
        )
        reading_trailer = _require_bool(
            snapshot["reading_trailer"], f"{name}.reading_trailer"
        )
        if bytes_to_discard not in (b"", b"\n", b"\r\n"):
            _snapshot_error(f"{name}.bytes_to_discard is invalid")
        if reading_trailer:
            if bytes_in_chunk != 0 or bytes_to_discard:
                _snapshot_error(f"{name} has an invalid trailer state")
        snapshot["bytes_to_discard"] = bytes_to_discard
        return io_type._from_snapshot(snapshot)

    _require_exact_keys(snapshot, {"framing"}, name)
    return io_type._from_snapshot(snapshot)


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

    def export_state(self) -> Dict[str, Any]:
        """Export a versioned, JSON-compatible snapshot of this connection.

        The snapshot contains parser state and buffered bytes, but no sockets
        or user-owned event objects.
        """
        reader_state = (
            cast(Any, self._reader)._snapshot()
            if self.their_state is SEND_BODY
            else None
        )
        if reader_state is not None and reader_state.get("framing") == "chunked":
            reader_state = dict(reader_state)
            reader_state["bytes_to_discard"] = _encode_bytes(
                _snapshot_bytes(reader_state["bytes_to_discard"])
            )
        writer_state = (
            cast(Any, self._writer)._snapshot()
            if self.our_state is SEND_BODY
            else None
        )
        return {
            "version": STATE_FORMAT_VERSION,
            "role": _ROLE_NAMES[self.our_role],
            "max_incomplete_event_size": self._max_incomplete_event_size,
            "states": {
                "client": _STATE_NAMES[self._cstate.states[CLIENT]],
                "server": _STATE_NAMES[self._cstate.states[SERVER]],
            },
            "keep_alive": self._cstate.keep_alive,
            "pending_switch_proposals": [
                _SWITCH_NAMES[proposal]
                for proposal in self._cstate.pending_switch_proposals
            ],
            "their_http_version": _encode_bytes(self.their_http_version),
            "request_method": _encode_bytes(self._request_method),
            "client_is_waiting_for_100_continue": (
                self.client_is_waiting_for_100_continue
            ),
            "receive_buffer": _encode_bytes(bytes(self._receive_buffer)),
            "receive_buffer_closed": self._receive_buffer_closed,
            "reader": reader_state,
            "writer": writer_state,
        }

    @classmethod
    def restore_state(cls, state: Mapping[str, Any]) -> "Connection":
        """Create a connection from a snapshot returned by :meth:`export_state`."""
        snapshot = _require_mapping(state, "state")
        _require_exact_keys(
            snapshot,
            {
                "version",
                "role",
                "max_incomplete_event_size",
                "states",
                "keep_alive",
                "pending_switch_proposals",
                "their_http_version",
                "request_method",
                "client_is_waiting_for_100_continue",
                "receive_buffer",
                "receive_buffer_closed",
                "reader",
                "writer",
            },
            "state",
        )

        version = snapshot["version"]
        if not isinstance(version, int) or isinstance(version, bool):
            _snapshot_error("version must be an integer")
        if version != STATE_FORMAT_VERSION:
            _snapshot_error(
                f"incompatible version {version} (expected {STATE_FORMAT_VERSION})"
            )

        our_role = _lookup(snapshot["role"], _ROLES_BY_NAME, "role")
        their_role = SERVER if our_role is CLIENT else CLIENT
        max_incomplete_event_size = _require_int(
            snapshot["max_incomplete_event_size"],
            "max_incomplete_event_size",
            1,
        )

        raw_states = _require_mapping(snapshot["states"], "states")
        _require_exact_keys(raw_states, {"client", "server"}, "states")
        client_state = _lookup(raw_states["client"], _STATES_BY_NAME, "states.client")
        server_state = _lookup(raw_states["server"], _STATES_BY_NAME, "states.server")
        if client_state is SEND_RESPONSE:
            _snapshot_error("clients cannot be in SEND_RESPONSE state")
        if server_state is MIGHT_SWITCH_PROTOCOL:
            _snapshot_error("servers cannot be in MIGHT_SWITCH_PROTOCOL state")
        if server_state not in _COMPATIBLE_STATES[client_state]:
            _snapshot_error("client and server states are incompatible")

        keep_alive = _require_bool(snapshot["keep_alive"], "keep_alive")
        raw_proposals = snapshot["pending_switch_proposals"]
        if not isinstance(raw_proposals, list):
            _snapshot_error("pending_switch_proposals must be a list")
        pending_switch_proposals = {
            _lookup(proposal, _SWITCHES_BY_NAME, "pending_switch_proposals")
            for proposal in raw_proposals
        }
        if len(pending_switch_proposals) != len(raw_proposals):
            _snapshot_error("pending_switch_proposals contains duplicates")
        if pending_switch_proposals:
            valid_proposal_states = (
                client_state in (SEND_BODY, MIGHT_SWITCH_PROTOCOL)
                and server_state in (IDLE, SEND_RESPONSE, ERROR)
            ) or (
                client_state,
                server_state,
            ) == (
                SWITCHED_PROTOCOL,
                SWITCHED_PROTOCOL,
            ) or (
                client_state is MIGHT_SWITCH_PROTOCOL and server_state is ERROR
            )
            if not valid_proposal_states:
                _snapshot_error("pending switch proposals are invalid for the states")
        elif (client_state, server_state) != (
            SWITCHED_PROTOCOL,
            SWITCHED_PROTOCOL,
        ) and client_state is SWITCHED_PROTOCOL:
            _snapshot_error("switched protocol state requires a switch proposal")

        cstate = ConnectionState()
        cstate.keep_alive = keep_alive
        cstate.pending_switch_proposals = pending_switch_proposals
        cstate.states = {CLIENT: client_state, SERVER: server_state}
        stable_states = dict(cstate.states)
        cstate._fire_state_triggered_transitions()
        if cstate.states != stable_states:
            _snapshot_error("state machine states are incompatible")

        their_http_version = _decode_bytes(
            snapshot["their_http_version"], "their_http_version"
        )
        request_method = _decode_bytes(snapshot["request_method"], "request_method")
        if request_method is not None and not request_method:
            _snapshot_error("request_method cannot be empty")

        if (
            client_state is SEND_BODY
            or server_state in (SEND_RESPONSE, SEND_BODY)
        ) and request_method is None:
            _snapshot_error("request_method is required for the current state")

        client_is_waiting = _require_bool(
            snapshot["client_is_waiting_for_100_continue"],
            "client_is_waiting_for_100_continue",
        )
        if client_is_waiting and client_state not in (
            SEND_BODY,
            DONE,
            MUST_CLOSE,
            MIGHT_SWITCH_PROTOCOL,
            ERROR,
        ):
            _snapshot_error(
                "client_is_waiting_for_100_continue is invalid for the current state"
            )

        receive_buffer = ReceiveBuffer()
        buffered_data = _decode_bytes(
            snapshot["receive_buffer"], "receive_buffer", required=True
        )
        assert buffered_data is not None
        receive_buffer += buffered_data
        receive_buffer_closed = _require_bool(
            snapshot["receive_buffer_closed"], "receive_buffer_closed"
        )

        reader = _build_body_io(
            snapshot["reader"],
            "reader",
            _READER_TYPES,
            is_reader=True,
        )
        writer = _build_body_io(
            snapshot["writer"],
            "writer",
            _WRITER_TYPES,
            is_reader=False,
        )
        if cstate.states[their_role] is SEND_BODY:
            if reader is None:
                _snapshot_error("reader is required in SEND_BODY state")
        elif reader is not None:
            _snapshot_error("reader must be omitted outside SEND_BODY state")
        if cstate.states[our_role] is SEND_BODY:
            if writer is None:
                _snapshot_error("writer is required in SEND_BODY state")
        elif writer is not None:
            _snapshot_error("writer must be omitted outside SEND_BODY state")

        if reader is None:
            reader = READERS.get((their_role, cstate.states[their_role]))
        if writer is None:
            writer = WRITERS.get((our_role, cstate.states[our_role]))

        connection = cls.__new__(cls)
        connection._max_incomplete_event_size = max_incomplete_event_size
        connection.our_role = our_role
        connection.their_role = their_role
        connection._cstate = cstate
        connection._writer = writer
        connection._reader = reader
        connection._receive_buffer = receive_buffer
        connection._receive_buffer_closed = receive_buffer_closed
        connection.their_http_version = their_http_version
        connection._request_method = request_method
        connection.client_is_waiting_for_100_continue = client_is_waiting
        return connection

    @classmethod
    def from_state(cls, state: Mapping[str, Any]) -> "Connection":
        """Restore a connection from a snapshot returned by :meth:`export_state`."""
        return cls.restore_state(state)

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
        try:
            if type(event) is Response:
                event = self._clean_up_response_headers_for_sending(event)
            # We want to call _process_event before calling the writer,
            # because if someone tries to do something invalid then this will
            # give a sensible error message, while our writers all just assume
            # they will only receive valid events. But, _process_event might
            # change self._writer. So we have to do a little dance:
            writer = self._writer
            self._process_event(self.our_role, event)
            if type(event) is ConnectionClosed:
                return None
            else:
                # In any situation where writer is None, process_event should
                # have raised ProtocolError
                assert writer is not None
                data_list: List[bytes] = []
                writer(event, data_list.append)
                return data_list
        except:
            self._process_error(self.our_role)
            raise

    def send_failed(self) -> None:
        """Notify the state machine that we failed to send the data it gave
        us.

        This causes :attr:`Connection.our_state` to immediately become
        :data:`ERROR` -- see :ref:`error-handling` for discussion.

        """
        self._process_error(self.our_role)

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
