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
from ._receivebuffer import ReceiveBuffer
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


def _obsolete_line_fold(lines: Iterable[bytes]) -> Iterable[bytes]:
    it = iter(lines)
    last: Optional[bytes] = None
    for line in it:
        match = obs_fold_re.match(line)
        if match:
            if last is None:
                raise LocalProtocolError("continuation line at start of headers")
            if not isinstance(last, bytearray):
                # Cast to a mutable type, avoiding copy on append to ensure O(n) time
                last = bytearray(last)
            last += b" "
            last += line[match.end() :]
        else:
            if last is not None:
                yield last
            last = line
    if last is not None:
        yield last


def _decode_header_lines(
    lines: Iterable[bytes],
) -> Iterable[Tuple[bytes, bytes]]:
    for line in _obsolete_line_fold(lines):
        matches = validate(header_field_re, line, "illegal header line: {!r}", line)
        yield (matches["field_name"], matches["field_value"])


def _absolute_error_location(
    buf: ReceiveBuffer, fragment_category: str, start: int, end: int
) -> ErrorLocation:
    return buf.make_error_location(
        fragment_category,
        start - buf.consumed_offset,
        end - buf.consumed_offset,
    )


def _set_error_location(exc: LocalProtocolError, location: ErrorLocation) -> None:
    exc.error_location = location


def _decode_header_lines_with_offsets(
    buf: ReceiveBuffer,
    lines: List[Tuple[bytearray, int]],
    fragment_category: str = "header",
) -> List[Tuple[Tuple[bytes, bytes], int, int]]:
    decoded: List[Tuple[Tuple[bytes, bytes], int, int]] = []
    logical_line: Optional[bytearray] = None
    logical_start = 0
    logical_end = 0

    def flush() -> None:
        nonlocal logical_line, logical_start, logical_end
        if logical_line is None:
            return
        try:
            matches = validate(header_field_re, logical_line, "illegal header line")
        except LocalProtocolError as exc:
            _set_error_location(
                exc,
                _absolute_error_location(
                    buf, fragment_category, logical_start, logical_end
                ),
            )
            raise
        decoded.append(
            (
                (matches["field_name"], matches["field_value"]),
                logical_start,
                logical_end,
            )
        )
        logical_line = None

    for line, start in lines:
        end = start + len(line)
        match = obs_fold_re.match(line)
        if match:
            if logical_line is None:
                exc = LocalProtocolError("continuation line at start of headers")
                _set_error_location(
                    exc, _absolute_error_location(buf, fragment_category, start, end)
                )
                raise exc
            logical_line += b" "
            logical_line += line[match.end() :]
            logical_end = end
        else:
            flush()
            logical_line = bytearray(line)
            logical_start = start
            logical_end = end
    flush()
    return decoded


def _annotate_message_header_error(
    exc: LocalProtocolError,
    buf: ReceiveBuffer,
    headers: List[Tuple[Tuple[bytes, bytes], int, int]],
    block_start: int,
    block_end: int,
) -> None:
    message = str(exc)
    if message in (
        "conflicting Content-Length headers",
        "bad Content-Length",
    ):
        for (name, _), start, end in reversed(headers):
            if name.lower() == b"content-length":
                _set_error_location(
                    exc, _absolute_error_location(buf, "content-length", start, end)
                )
                return
    if message == "Found multiple Host: headers":
        for (name, _), start, end in reversed(headers):
            if name.lower() == b"host":
                _set_error_location(
                    exc, _absolute_error_location(buf, "header", start, end)
                )
                return
    _set_error_location(
        exc, _absolute_error_location(buf, "header-block", block_start, block_end)
    )


request_line_re = re.compile(request_line.encode("ascii"))


def maybe_read_from_IDLE_client(buf: ReceiveBuffer) -> Optional[Request]:
    buf.begin_message()
    extracted = buf.maybe_extract_lines_with_offsets()
    if extracted is None:
        if buf.is_next_line_obviously_invalid_request_line():
            exc = LocalProtocolError("illegal request line")
            _set_error_location(
                exc, buf.make_error_location("request-line", 0, len(buf))
            )
            raise exc
        return None
    lines, block_start, block_end = extracted
    if not lines:
        exc = LocalProtocolError("no request line received")
        _set_error_location(
            exc,
            _absolute_error_location(buf, "request-line", block_start, block_end),
        )
        raise exc

    request_line, request_line_start = lines[0]
    request_line_end = request_line_start + len(request_line)
    header_block_start = request_line_end
    try:
        matches = validate(
            request_line_re,
            request_line,
            "illegal request line",
        )
    except LocalProtocolError as exc:
        _set_error_location(
            exc,
            _absolute_error_location(
                buf, "request-line", request_line_start, request_line_end
            ),
        )
        raise
    decoded_headers = _decode_header_lines_with_offsets(buf, lines[1:])
    headers = [header for header, _, _ in decoded_headers]
    try:
        return Request(headers=headers, _parsed=True, **matches)
    except LocalProtocolError as exc:
        _annotate_message_header_error(
            exc, buf, decoded_headers, header_block_start, block_end
        )
        raise


status_line_re = re.compile(status_line.encode("ascii"))


def maybe_read_from_SEND_RESPONSE_server(
    buf: ReceiveBuffer,
) -> Union[InformationalResponse, Response, None]:
    buf.begin_message()
    extracted = buf.maybe_extract_lines_with_offsets()
    if extracted is None:
        if buf.is_next_line_obviously_invalid_request_line():
            exc = LocalProtocolError("illegal request line")
            _set_error_location(
                exc, buf.make_error_location("status-line", 0, len(buf))
            )
            raise exc
        return None
    lines, block_start, block_end = extracted
    if not lines:
        exc = LocalProtocolError("no response line received")
        _set_error_location(
            exc,
            _absolute_error_location(buf, "status-line", block_start, block_end),
        )
        raise exc

    status_line, status_line_start = lines[0]
    status_line_end = status_line_start + len(status_line)
    header_block_start = status_line_end
    try:
        matches = validate(
            status_line_re, status_line, "illegal status line"
        )
    except LocalProtocolError as exc:
        _set_error_location(
            exc,
            _absolute_error_location(
                buf, "status-line", status_line_start, status_line_end
            ),
        )
        raise
    http_version = (
        b"1.1" if matches["http_version"] is None else matches["http_version"]
    )
    reason = b"" if matches["reason"] is None else matches["reason"]
    status_code = int(matches["status_code"])
    class_: Union[Type[InformationalResponse], Type[Response]] = (
        InformationalResponse if status_code < 200 else Response
    )
    decoded_headers = _decode_header_lines_with_offsets(buf, lines[1:])
    headers = [header for header, _, _ in decoded_headers]
    try:
        return class_(
            headers=headers,
            _parsed=True,
            status_code=status_code,
            reason=reason,
            http_version=http_version,
        )
    except LocalProtocolError as exc:
        _annotate_message_header_error(
            exc, buf, decoded_headers, header_block_start, block_end
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

    def read_eof(self, buf: ReceiveBuffer) -> NoReturn:
        exc = RemoteProtocolError(
            "peer closed connection without sending complete message body "
            "(received {} bytes, expected {})".format(
                self._length - self._remaining, self._length
            )
        )
        _set_error_location(exc, buf.make_error_location("content-length-body"))
        raise exc


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
            extracted = buf.maybe_extract_lines_with_offsets()
            if extracted is None:
                return None
            lines, _, _ = extracted
            decoded_headers = _decode_header_lines_with_offsets(
                buf, lines, "chunk-trailer"
            )
            return EndOfMessage(
                headers=[header for header, _, _ in decoded_headers]
            )
        if self._bytes_to_discard:
            data = buf.maybe_extract_at_most(len(self._bytes_to_discard))
            if data is None:
                return None
            if data != self._bytes_to_discard[: len(data)]:
                start = buf.consumed_offset - len(data)
                exc = LocalProtocolError("malformed chunk footer")
                _set_error_location(
                    exc,
                    _absolute_error_location(
                        buf, "chunk-terminator", start, buf.consumed_offset
                    ),
                )
                raise exc
            self._bytes_to_discard = self._bytes_to_discard[len(data) :]
            if self._bytes_to_discard:
                return None
            # else, fall through and read some more
        assert self._bytes_to_discard == b""
        if self._bytes_in_chunk == 0:
            # We need to refill our chunk count
            chunk_header_data = buf.maybe_extract_next_line_with_offset()
            if chunk_header_data is None:
                return None
            chunk_header, chunk_header_start = chunk_header_data
            chunk_header_end = chunk_header_start + len(chunk_header) - 2
            try:
                matches = validate(
                    chunk_header_re,
                    chunk_header,
                    "illegal chunk header",
                )
            except LocalProtocolError as exc:
                _set_error_location(
                    exc,
                    _absolute_error_location(
                        buf, "chunk-size", chunk_header_start, chunk_header_end
                    ),
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

    def read_eof(self, buf: ReceiveBuffer) -> NoReturn:
        exc = RemoteProtocolError(
            "peer closed connection without sending complete message body "
            "(incomplete chunked read)"
        )
        _set_error_location(exc, buf.make_error_location("chunked-body"))
        raise exc


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
        exc = LocalProtocolError("Got data when expecting EOF")
        _set_error_location(exc, buf.make_error_location("unexpected-data"))
        raise exc
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
