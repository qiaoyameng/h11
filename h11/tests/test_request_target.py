import pytest

from .._connection import Connection
from .._events import Request
from .._state import CLIENT, SERVER
from .._util import LocalProtocolError, RemoteProtocolError
from .helpers import receive_and_get


def make_request_line(method, target, host=b"example.com", version=b"1.1"):
    return (
        method + b" " + target + b" HTTP/" + version + b"\r\n"
        b"Host: " + host + b"\r\n\r\n"
    )


# -- Request constructor --------------------------------------------------

def test_request_strict_constructor_validates():
    Request(
        method="GET",
        target="/",
        headers=[("Host", "example.com")],
        strict_request_target=True,
    )
    Request(
        method="OPTIONS",
        target="*",
        headers=[("Host", "example.com")],
        strict_request_target=True,
    )
    Request(
        method="CONNECT",
        target="example.com:443",
        headers=[("Host", "example.com:443")],
        strict_request_target=True,
    )
    with pytest.raises(LocalProtocolError):
        Request(
            method="GET",
            target="relative",
            headers=[("Host", "example.com")],
            strict_request_target=True,
        )
    with pytest.raises(LocalProtocolError):
        Request(
            method="CONNECT",
            target="example.com",
            headers=[("Host", "example.com")],
            strict_request_target=True,
        )


def test_request_non_strict_default_keeps_compat():
    # Default: no structural validation, anything with legal bytes is OK.
    req = Request(
        method="GET", target="weird-but-legal", headers=[("Host", "a")]
    )
    assert req.target == b"weird-but-legal"


def test_request_target_bytes_never_modified():
    target = "http://example.com"
    req = Request(
        method="GET",
        target=target,
        headers=[("Host", "example.com")],
        strict_request_target=True,
    )
    # Absolute URI with an empty path must be preserved verbatim.
    assert req.target == b"http://example.com"


# -- client-side Connection validation ------------------------------------

def test_client_strict_send_valid():
    client = Connection(CLIENT, strict_request_target=True)
    client.send(
        Request(
            method="GET",
            target="/",
            headers=[("Host", "example.com")],
        )
    )


def test_client_strict_send_rejects_bad_target():
    client = Connection(CLIENT, strict_request_target=True)
    with pytest.raises(LocalProtocolError):
        client.send(
            Request(
                method="GET",
                target="relative-path",
                headers=[("Host", "example.com")],
            )
        )
    from .._state import ERROR

    assert client.our_state is ERROR


def test_client_non_strict_send_keeps_compat():
    client = Connection(CLIENT)
    client.send(
        Request(
            method="GET",
            target="relative-path",
            headers=[("Host", "example.com")],
        )
    )


# -- server-side Connection validation ------------------------------------

def test_server_strict_receives_valid_forms():
    for method, target, host in [
        (b"GET", b"/", b"example.com"),
        (b"GET", b"/a/b?x=1", b"example.com"),
        (b"OPTIONS", b"*", b"example.com"),
        (b"CONNECT", b"example.com:443", b"example.com:443"),
        (b"GET", b"http://example.com/", b"example.com"),
        (b"GET", b"http://[2001:db8::1]:8080/path", b"[2001:db8::1]:8080"),
    ]:
        server = Connection(SERVER, strict_request_target=True)
        events = receive_and_get(
            server, make_request_line(method, target, host=host)
        )
        assert any(type(e) is Request for e in events)
        # The target bytes are delivered untouched.
        req = [e for e in events if type(e) is Request][0]
        assert req.target == target


def test_server_strict_absolute_uri_must_match_host():
    server = Connection(SERVER, strict_request_target=True)
    with pytest.raises(RemoteProtocolError):
        receive_and_get(
            server,
            make_request_line(
                b"GET", b"http://example.com/", host=b"evil.example"
            ),
        )


def test_server_strict_rejects_bad_targets():
    bad = [
        (b"GET", b"relative", b"example.com"),
        (b"GET", b"/bad%2", b"example.com"),
        (b"GET", b"/x\x01", b"example.com"),
        (b"GET", b"*", b"example.com"),
        (b"CONNECT", b"example.com", b"example.com"),
        (b"CONNECT", b"example.com:99999", b"example.com:99999"),
        (b"GET", b"http://user@example.com/", b"user@example.com"),
        (b"GET", b"http://[::1/", b"[::1"),
    ]
    for method, target, host in bad:
        server = Connection(SERVER, strict_request_target=True)
        with pytest.raises(RemoteProtocolError):
            receive_and_get(server, make_request_line(method, target, host=host))


def test_connect_target_is_not_compared_to_host():
    # RFC 7230 5.4: for CONNECT, the authority-form target is the
    # authority; the Host header plays no role.
    from h11._uri import validate_request_target

    validate_request_target(
        method=b"CONNECT",
        target=b"example.com:443",
        host_header=b"something-different:443",
    )


def test_server_non_strict_default_keeps_compat():
    server = Connection(SERVER)
    # Absolute URI that disagrees with Host: accepted by default.
    events = receive_and_get(
        server,
        make_request_line(b"GET", b"http://example.com/", host=b"other.example"),
    )
    req = [e for e in events if type(e) is Request][0]
    assert req.target == b"http://example.com/"
