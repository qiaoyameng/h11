# Code to read HTTP data
#
# Strategy: each writer takes an event + a write-some-bytes function, which is
# calls.
#
# WRITERS is a dict describing how to pick a reader. It maps states to either:
# - a writer
# - or, for body writers, a dict of framin-dependent writer factories

import re
from typing import Any, Callable, Dict, Iterable, List, Tuple, Type, Union

from ._abnf import token
from ._events import Data, EndOfMessage, Event, InformationalResponse, Request, Response
from ._headers import Headers
from ._state import CLIENT, IDLE, SEND_BODY, SEND_RESPONSE, SERVER
from ._util import LocalProtocolError, Sentinel, validate

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
            self.send_data(event.data, write)
        elif type(event) is EndOfMessage:
            self.send_eom(event.headers, write)
        else:  # pragma: no cover
            assert False

    def send_data(self, data: bytes, write: Writer) -> None:
        pass

    def send_eom(self, headers: Headers, write: Writer) -> None:
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

    def send_data(self, data: bytes, write: Writer) -> None:
        self._length -= len(data)
        if self._length < 0:
            raise LocalProtocolError("Too much data for declared Content-Length")
        write(data)

    def send_eom(self, headers: Headers, write: Writer) -> None:
        if self._length != 0:
            raise LocalProtocolError("Too little data for declared Content-Length")
        if headers:
            raise LocalProtocolError("Content-Length and trailers don't mix")


class ChunkedWriter(BodyWriter):
    def __init__(self, preserve_chunk_extensions: bool = False) -> None:
        self._preserve_chunk_extensions = preserve_chunk_extensions

    def __call__(self, event: Event, write: Writer) -> None:
        if type(event) is Data:
            self.send_data(event.data, write, event.chunk_extensions)
        elif type(event) is EndOfMessage:
            self.send_eom(event.headers, write, event.chunk_extensions)
        else:  # pragma: no cover
            assert False

    def _encode_extensions(
        self, chunk_extensions: Tuple[Tuple[bytes, bytes], ...]
    ) -> bytes:
        if not chunk_extensions:
            return b""
        if not self._preserve_chunk_extensions:
            raise LocalProtocolError(
                "chunk_extensions can only be sent on connections created "
                "with preserve_chunk_extensions=True"
            )
        return _encode_chunk_extensions(chunk_extensions)

    def send_data(
        self,
        data: bytes,
        write: Writer,
        chunk_extensions: Tuple[Tuple[bytes, bytes], ...] = (),
    ) -> None:
        # if we encoded 0-length data in the naive way, it would look like an
        # end-of-message.
        if not data:
            if chunk_extensions:
                raise LocalProtocolError(
                    "can't attach chunk_extensions to an empty Data event"
                )
            return
        write(b"%x%s\r\n" % (len(data), self._encode_extensions(chunk_extensions)))
        write(data)
        write(b"\r\n")

    def send_eom(
        self,
        headers: Headers,
        write: Writer,
        chunk_extensions: Tuple[Tuple[bytes, bytes], ...] = (),
    ) -> None:
        write(b"0%s\r\n" % self._encode_extensions(chunk_extensions))
        write_headers(headers, write)


chunk_ext_name_re = re.compile(token.encode("ascii"))
# Everything legal inside a quoted-string (before escaping):
# HTAB / SP / VCHAR / obs-text. In particular this excludes CR and LF, so
# validating against it prevents header-injection through extension values.
chunk_ext_value_re = re.compile(rb"[\t\x20-\x7e\x80-\xff]*")


def _encode_chunk_extensions(
    chunk_extensions: Iterable[Tuple[bytes, bytes]],
) -> bytes:
    encoded = b""
    for name, value in chunk_extensions:
        validate(chunk_ext_name_re, name, "illegal chunk extension name: {!r}", name)
        validate(
            chunk_ext_value_re,
            value,
            "illegal character in chunk extension value: {!r}",
            value,
        )
        if not value:
            encoded += b";" + name
        elif chunk_ext_name_re.fullmatch(value):
            encoded += b";" + name + b"=" + value
        else:
            escaped = value.replace(b"\\", b"\\\\").replace(b'"', b'\\"')
            encoded += b";" + name + b'="' + escaped + b'"'
    return encoded


class Http10Writer(BodyWriter):
    def send_data(self, data: bytes, write: Writer) -> None:
        write(data)

    def send_eom(self, headers: Headers, write: Writer) -> None:
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
