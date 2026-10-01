# Code to read HTTP data
#
# Strategy: each writer takes an event + a write-some-bytes function, which is
# calls.
#
# WRITERS is a dict describing how to pick a reader. It maps states to either:
# - a writer
# - or, for body writers, a dict of framin-dependent writer factories

from typing import Any, Callable, Dict, List, Optional, Tuple, Type, Union

from ._chunkextensions import ChunkExtensions, encode_chunk_extensions
from ._events import Data, EndOfMessage, Event, InformationalResponse, Request, Response
from ._headers import Headers
from ._state import CLIENT, IDLE, SEND_BODY, SEND_RESPONSE, SERVER
from ._util import LocalProtocolError, Sentinel

__all__ = ["WRITERS"]

Writer = Callable[[bytes], Any]


def write_headers(headers: Headers, write: Writer) -> None:
    # "Since the Host field-value is critical information for handling a
    # request, a user agent SHOULD generate Host as the first header field
    # following the request-line." - RFC 7230
    raw_items = headers._full_items
    for raw_name, name, value in raw_items:
        if name == b"host":
            write(b"%s: %s\r\n" % (raw_name, value))
    for raw_name, name, value in raw_items:
        if name != b"host":
            write(b"%s: %s\r\n" % (raw_name, value))
    write(b"\r\n")


def write_request(request: Request, write: Writer) -> None:
    if request.http_version != b"1.1":
        raise LocalProtocolError("I only send HTTP/1.1")
    write(b"%s %s HTTP/1.1\r\n" % (request.method, request.target))
    write_headers(request.headers, write)


# Shared between InformationalResponse and Response
def write_any_response(
    response: Union[InformationalResponse, Response], write: Writer
) -> None:
    if response.http_version != b"1.1":
        raise LocalProtocolError("I only send HTTP/1.1")
    status_bytes = str(response.status_code).encode("ascii")
    # We don't bother sending ascii status messages like "OK"; they're
    # optional and ignored by the protocol. (But the space after the numeric
    # status code is mandatory.)
    #
    # XX FIXME: could at least make an effort to pull out the status message
    # from stdlib's http.HTTPStatus table. Or maybe just steal their enums
    # (either by import or copy/paste). We already accept them as status codes
    # since they're of type IntEnum < int.
    write(b"HTTP/1.1 %s %s\r\n" % (status_bytes, response.reason))
    write_headers(response.headers, write)


class BodyWriter:
    def __call__(self, event: Event, write: Writer) -> None:
        if type(event) is Data:
            self.send_data(
                event.data,
                write,
                event.chunk_extensions,
                event.chunk_start,
                event.chunk_end,
            )
        elif type(event) is EndOfMessage:
            self.send_eom(event.headers, write, event.chunk_extensions)
        else:  # pragma: no cover
            assert False

    def send_data(
        self,
        data: bytes,
        write: Writer,
        chunk_extensions: Optional[ChunkExtensions] = None,
        chunk_start: bool = False,
        chunk_end: bool = False,
    ) -> None:
        pass

    def send_eom(
        self,
        headers: Headers,
        write: Writer,
        chunk_extensions: Optional[ChunkExtensions] = None,
    ) -> None:
        pass


#
# These are all careful not to do anything to 'data' except call len(data) and
# write(data). This allows us to transparently pass-through funny objects,
# like placeholder objects referring to files on disk that will be sent via
# sendfile(2).
#
class ContentLengthWriter(BodyWriter):
    def __init__(self, length: int) -> None:
        self._length = length

    def send_data(
        self,
        data: bytes,
        write: Writer,
        chunk_extensions: Optional[ChunkExtensions] = None,
        chunk_start: bool = False,
        chunk_end: bool = False,
    ) -> None:
        if chunk_extensions is not None:
            raise LocalProtocolError(
                "chunk extensions require chunked transfer encoding"
            )
        self._length -= len(data)
        if self._length < 0:
            raise LocalProtocolError("Too much data for declared Content-Length")
        write(data)

    def send_eom(
        self,
        headers: Headers,
        write: Writer,
        chunk_extensions: Optional[ChunkExtensions] = None,
    ) -> None:
        if chunk_extensions is not None:
            raise LocalProtocolError(
                "chunk extensions require chunked transfer encoding"
            )
        if self._length != 0:
            raise LocalProtocolError("Too little data for declared Content-Length")
        if headers:
            raise LocalProtocolError("Content-Length and trailers don't mix")


class ChunkedWriter(BodyWriter):
    def __init__(self, preserve_chunk_extensions: bool = False) -> None:
        self._preserve_chunk_extensions = preserve_chunk_extensions
        self._in_chunk = False
        self._chunk_extensions: Optional[ChunkExtensions] = None
        self._data_parts: List[Any] = []

    def send_data(
        self,
        data: bytes,
        write: Writer,
        chunk_extensions: Optional[ChunkExtensions] = None,
        chunk_start: bool = False,
        chunk_end: bool = False,
    ) -> None:
        if not self._preserve_chunk_extensions:
            if chunk_extensions is not None:
                raise LocalProtocolError(
                    "cannot send chunk extensions when their preservation is "
                    "disabled"
                )
            self._write_immediate_chunk(data, write)
            return

        if self._in_chunk:
            if chunk_start:
                raise LocalProtocolError("received data for a new chunk mid-chunk")
            if (
                chunk_extensions is not None
                and chunk_extensions != self._chunk_extensions
            ):
                raise LocalProtocolError("chunk extension metadata changed mid-chunk")
        elif not chunk_start:
            if chunk_end:
                raise LocalProtocolError(
                    "chunk end received without a matching chunk start"
                )
            self._write_single_chunk(data, chunk_extensions, write)
            return
        else:
            self._chunk_extensions = chunk_extensions

        self._data_parts.append(data)
        self._in_chunk = not chunk_end
        if chunk_end:
            self._write_buffered_chunk(write)

    def _write_single_chunk(
        self,
        data: bytes,
        chunk_extensions: Optional[ChunkExtensions],
        write: Writer,
    ) -> None:
        extensions = encode_chunk_extensions(chunk_extensions)
        if not data:
            if extensions:
                raise LocalProtocolError(
                    "chunk extensions must be attached to a non-empty chunk"
                )
            return
        write(b"%x" % len(data))
        write(extensions)
        write(b"\r\n")
        write(data)
        write(b"\r\n")

    def _write_immediate_chunk(self, data: bytes, write: Writer) -> None:
        # if we encoded 0-length data in the naive way, it would look like an
        # end-of-message.
        if not data:
            return
        write(b"%x\r\n" % len(data))
        write(data)
        write(b"\r\n")

    def _write_buffered_chunk(self, write: Writer) -> None:
        extensions = encode_chunk_extensions(self._chunk_extensions)
        total_length = sum(len(part) for part in self._data_parts)
        if total_length:
            write(b"%x" % total_length)
            write(extensions)
            write(b"\r\n")
            for part in self._data_parts:
                write(part)
            write(b"\r\n")
        elif extensions:
            raise LocalProtocolError(
                "chunk extensions must be attached to a non-empty chunk"
            )
        self._in_chunk = False
        self._chunk_extensions = None
        self._data_parts = []

    def send_eom(
        self,
        headers: Headers,
        write: Writer,
        chunk_extensions: Optional[ChunkExtensions] = None,
    ) -> None:
        if self._preserve_chunk_extensions:
            if self._in_chunk:
                raise LocalProtocolError("EndOfMessage received before a chunk ended")
            extensions = encode_chunk_extensions(chunk_extensions)
        else:
            if chunk_extensions is not None:
                raise LocalProtocolError(
                    "cannot send chunk extensions when their preservation is "
                    "disabled"
                )
            extensions = b""
        write(b"0")
        write(extensions)
        write(b"\r\n")
        write_headers(headers, write)


class Http10Writer(BodyWriter):
    def send_data(
        self,
        data: bytes,
        write: Writer,
        chunk_extensions: Optional[ChunkExtensions] = None,
        chunk_start: bool = False,
        chunk_end: bool = False,
    ) -> None:
        if chunk_extensions is not None:
            raise LocalProtocolError(
                "chunk extensions require chunked transfer encoding"
            )
        write(data)

    def send_eom(
        self,
        headers: Headers,
        write: Writer,
        chunk_extensions: Optional[ChunkExtensions] = None,
    ) -> None:
        if chunk_extensions is not None:
            raise LocalProtocolError(
                "chunk extensions require chunked transfer encoding"
            )
        if headers:
            raise LocalProtocolError("can't send trailers to HTTP/1.0 client")
        # no need to close the socket ourselves, that will be taken care of by
        # Connection: close machinery


WritersType = Dict[
    Union[Tuple[Type[Sentinel], Type[Sentinel]], Type[Sentinel]],
    Union[
        Dict[str, Type[BodyWriter]],
        Callable[[Union[InformationalResponse, Response], Writer], None],
        Callable[[Request, Writer], None],
    ],
]

WRITERS: WritersType = {
    (CLIENT, IDLE): write_request,
    (SERVER, IDLE): write_any_response,
    (SERVER, SEND_RESPONSE): write_any_response,
    SEND_BODY: {
        "chunked": ChunkedWriter,
        "content-length": ContentLengthWriter,
        "http/1.0": Http10Writer,
    },
}
