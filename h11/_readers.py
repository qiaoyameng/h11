# Code to read HTTP data
#
# Strategy: each reader is a callable which takes a ReceiveBuffer object, and
# either:
# 1) consumes some of it and returns an Event
# 2) raises a LocalProtocolError (for consistency -- e.g. we call validate()
#    and it might raise a LocalProtocolError, so simpler just to always use
#    this)
# 3) returns None, meaning "I need more data"
#
# If they have a .read_eof attribute, then this will be called if an EOF is
# received -- but this is optional. Either way, the actual ConnectionClosed
# event will be generated afterwards.
#
# READERS is a dict describing how to pick a reader. It maps states to either:
# - a reader
# - or, for body readers, a dict of per-framing reader factories

import re
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    NoReturn,
    Optional,
    Tuple,
    Type,
    Union,
)

from ._abnf import chunk_header, header_field, request_line, status_line
from ._events import Data, EndOfMessage, InformationalResponse, Request, Response
from ._headers import Headers, normalize_and_validate
from ._receivebuffer import LocatedBytearray, ReceiveBuffer
from ._state import (
    CLIENT,
    CLOSED,
    DONE,
    IDLE,
    MUST_CLOSE,
    SEND_BODY,
    SEND_RESPONSE,
    SERVER,
)
from ._util import (
    ErrorLocation,
    LocalProtocolError,
    RemoteProtocolError,
    Sentinel,
    validate,
)

__all__ = ["READERS"]

header_field_re = re.compile(header_field.encode("ascii"))
obs_fold_re = re.compile(rb"[ \t]+")


def _obsolete_line_fold(
    lines: Iterable[LocatedBytearray], message_start: int = 0
) -> Iterable[Tuple[LocatedBytearray, List[Tuple[int, int]]]]:
    it = iter(lines)
    last: Optional[LocatedBytearray] = None
    last_offsets: List[Tuple[int, int]] = []
    for line in it:
        match = obs_fold_re.match(line)
        if match:
            if last is None:
                connection_offset = getattr(line, "connection_offset", 0)
                raise LocalProtocolError(
                    "continuation line at start of headers",
                    error_location=ErrorLocation(
                        connection_offset=connection_offset,
                        message_offset=connection_offset - message_start,
                        fragment_type="header_fold",
                    ),
                )
            assert last is not None
            last_offsets.append((line.connection_offset, len(line)))
            last += b" "
            last += line[match.end() :]
        else:
            if last is not None:
                yield last, last_offsets
            last = line
            last_offsets = [(line.connection_offset, len(line))]
    if last is not None:
        yield last, last_offsets


def _decode_header_lines(
    lines: Iterable[LocatedBytearray], message_start: int
) -> Headers:
    folded_lines = list(_obsolete_line_fold(lines, message_start))
    decoded_headers = []
    for line_number, (line, line_offsets) in enumerate(folded_lines):
        try:
            matches = validate(
                header_field_re,
                line,
                "illegal header line: {!r}",
                bytes(line),
            )
        except LocalProtocolError as exc:
            if exc.error_location is None:
                connection_offset = line_offsets[-1][0]
                exc.error_location = ErrorLocation(
                    connection_offset=connection_offset,
                    message_offset=connection_offset - message_start,
                    fragment_type="header",
                )
            raise
        decoded_headers.append((matches["field_name"], matches["field_value"]))
    try:
        normalized = normalize_and_validate(decoded_headers, _parsed=True)
    except LocalProtocolError as exc:
        if exc.error_location is None:
            content_length_lines = [
                line_number
                for line_number, (name, _) in enumerate(decoded_headers)
                if name.lower() == b"content-length"
            ]
            if content_length_lines:
                line_number = content_length_lines[-1]
            else:
                line_number = len(folded_lines) - 1
            connection_offset = folded_lines[line_number][0].connection_offset
            fragment_type = (
                "content_length"
                if "Content-Length" in str(exc)
                else "header"
            )
            exc.error_location = ErrorLocation(
                connection_offset=connection_offset,
                message_offset=connection_offset - message_start,
                fragment_type=fragment_type,
            )
        raise
    return normalized


request_line_re = re.compile(request_line.encode("ascii"))


def maybe_read_from_IDLE_client(buf: ReceiveBuffer) -> Optional[Request]:
    lines = buf.maybe_extract_lines()
    if lines is None:
        if buf.is_next_line_obviously_invalid_request_line():
            raise LocalProtocolError(
                "illegal request line",
                error_location=buf.error_location("request_line", buf.start_offset),
            )
        return None
    if not lines:
        raise LocalProtocolError(
            "no request line received",
            error_location=buf.error_location("request_line"),
        )
    message_start = buf.message_start_offset
    try:
        matches = validate(
            request_line_re,
            lines[0],
            "illegal request line: {!r}",
            bytes(lines[0]),
        )
    except LocalProtocolError as exc:
        if exc.error_location is None:
            exc.error_location = ErrorLocation(
                connection_offset=lines[0].connection_offset,
                message_offset=lines[0].connection_offset - message_start,
                fragment_type="request_line",
            )
        raise
    headers = _decode_header_lines(lines[1:], message_start)
    try:
        return Request(headers=headers, _parsed=True, **matches)
    except LocalProtocolError as exc:
        if exc.error_location is None:
            exc.error_location = ErrorLocation(
                connection_offset=lines[-1].connection_offset,
                message_offset=lines[-1].connection_offset - message_start,
                fragment_type="header",
            )
        raise


status_line_re = re.compile(status_line.encode("ascii"))


def maybe_read_from_SEND_RESPONSE_server(
    buf: ReceiveBuffer,
) -> Union[InformationalResponse, Response, None]:
    lines = buf.maybe_extract_lines()
    if lines is None:
        if buf.is_next_line_obviously_invalid_request_line():
            raise LocalProtocolError(
                "illegal status line",
                error_location=buf.error_location("status_line", buf.start_offset),
            )
        return None
    if not lines:
        raise LocalProtocolError(
            "no response line received",
            error_location=buf.error_location("status_line"),
        )
    message_start = buf.message_start_offset
    try:
        matches = validate(
            status_line_re,
            lines[0],
            "illegal status line: {!r}",
            bytes(lines[0]),
        )
    except LocalProtocolError as exc:
        if exc.error_location is None:
            exc.error_location = ErrorLocation(
                connection_offset=lines[0].connection_offset,
                message_offset=lines[0].connection_offset - message_start,
                fragment_type="status_line",
            )
        raise
    headers = _decode_header_lines(lines[1:], message_start)
    http_version = (
        b"1.1" if matches["http_version"] is None else matches["http_version"]
    )
    reason = b"" if matches["reason"] is None else matches["reason"]
    status_code = int(matches["status_code"])
    class_: Union[Type[InformationalResponse], Type[Response]] = (
        InformationalResponse if status_code < 200 else Response
    )
    try:
        return class_(
            headers=headers,
            _parsed=True,
            status_code=status_code,
            reason=reason,
            http_version=http_version,
        )
    except LocalProtocolError as exc:
        if exc.error_location is None:
            exc.error_location = ErrorLocation(
                connection_offset=lines[-1].connection_offset,
                message_offset=lines[-1].connection_offset - message_start,
                fragment_type="header",
            )
        raise


class ContentLengthReader:
    def __init__(self, length: int) -> None:
        self._length = length
        self._remaining = length

    def __call__(self, buf: ReceiveBuffer) -> Union[Data, EndOfMessage, None]:
        if self._remaining == 0:
            return EndOfMessage()
        data = buf.maybe_extract_at_most(self._remaining)
        if data is None:
            return None
        self._remaining -= len(data)
        return Data(data=data)

    def read_eof(self, buf: Optional[ReceiveBuffer] = None) -> NoReturn:
        error_location = (
            buf.error_location("body", buf.end_offset) if buf is not None else None
        )
        raise RemoteProtocolError(
            "peer closed connection without sending complete message body "
            "(received {} bytes, expected {})".format(
                self._length - self._remaining, self._length
            ),
            error_location=error_location,
        )


chunk_header_re = re.compile(chunk_header.encode("ascii"))


class ChunkedReader:
    def __init__(self) -> None:
        self._bytes_in_chunk = 0
        # After reading a chunk, we have to throw away the trailing \r\n.
        # This tracks the bytes that we need to match and throw away.
        self._bytes_to_discard = b""
        self._reading_trailer = False

    def __call__(self, buf: ReceiveBuffer) -> Union[Data, EndOfMessage, None]:
        if self._reading_trailer:
            lines = buf.maybe_extract_lines()
            if lines is None:
                return None
            return EndOfMessage(
                headers=_decode_header_lines(lines, buf.message_start_offset)
            )
        if self._bytes_to_discard:
            data = buf.maybe_extract_at_most(len(self._bytes_to_discard))
            if data is None:
                return None
            if data != self._bytes_to_discard[: len(data)]:
                raise LocalProtocolError(
                    "malformed chunk footer: {!r} (expected {!r})".format(
                        bytes(data), self._bytes_to_discard
                    ),
                    error_location=buf.error_location(
                        "chunk_terminator", data.connection_offset
                    ),
                )
            self._bytes_to_discard = self._bytes_to_discard[len(data) :]
            if self._bytes_to_discard:
                return None
            # else, fall through and read some more
        assert self._bytes_to_discard == b""
        if self._bytes_in_chunk == 0:
            # We need to refill our chunk count
            chunk_header = buf.maybe_extract_next_line()
            if chunk_header is None:
                return None
            try:
                matches = validate(
                    chunk_header_re,
                    chunk_header,
                    "illegal chunk header: {!r}",
                    bytes(chunk_header),
                )
            except LocalProtocolError as exc:
                if exc.error_location is None:
                    exc.error_location = buf.error_location(
                        "chunk_size", chunk_header.connection_offset
                    )
                raise
            # XX FIXME: we discard chunk extensions. Does anyone care?
            self._bytes_in_chunk = int(matches["chunk_size"], base=16)
            if self._bytes_in_chunk == 0:
                self._reading_trailer = True
                return self(buf)
            chunk_start = True
        else:
            chunk_start = False
        assert self._bytes_in_chunk > 0
        data = buf.maybe_extract_at_most(self._bytes_in_chunk)
        if data is None:
            return None
        self._bytes_in_chunk -= len(data)
        if self._bytes_in_chunk == 0:
            self._bytes_to_discard = b"\r\n"
            chunk_end = True
        else:
            chunk_end = False
        return Data(data=data, chunk_start=chunk_start, chunk_end=chunk_end)

    def read_eof(self, buf: Optional[ReceiveBuffer] = None) -> NoReturn:
        error_location = (
            buf.error_location("body", buf.end_offset) if buf is not None else None
        )
        raise RemoteProtocolError(
            "peer closed connection without sending complete message body "
            "(incomplete chunked read)",
            error_location=error_location,
        )


class Http10Reader:
    def __call__(self, buf: ReceiveBuffer) -> Optional[Data]:
        data = buf.maybe_extract_at_most(999999999)
        if data is None:
            return None
        return Data(data=data)

    def read_eof(self, buf: Optional[ReceiveBuffer] = None) -> EndOfMessage:
        return EndOfMessage()


def expect_nothing(buf: ReceiveBuffer) -> None:
    if buf:
        raise LocalProtocolError("Got data when expecting EOF")
    return None


ReadersType = Dict[
    Union[Type[Sentinel], Tuple[Type[Sentinel], Type[Sentinel]]],
    Union[Callable[..., Any], Dict[str, Callable[..., Any]]],
]

READERS: ReadersType = {
    (CLIENT, IDLE): maybe_read_from_IDLE_client,
    (SERVER, IDLE): maybe_read_from_SEND_RESPONSE_server,
    (SERVER, SEND_RESPONSE): maybe_read_from_SEND_RESPONSE_server,
    (CLIENT, DONE): expect_nothing,
    (CLIENT, MUST_CLOSE): expect_nothing,
    (CLIENT, CLOSED): expect_nothing,
    (SERVER, DONE): expect_nothing,
    (SERVER, MUST_CLOSE): expect_nothing,
    (SERVER, CLOSED): expect_nothing,
    SEND_BODY: {
        "chunked": ChunkedReader,
        "content-length": ContentLengthReader,
        "http/1.0": Http10Reader,
    },
}
