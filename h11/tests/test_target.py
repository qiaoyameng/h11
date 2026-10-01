import pytest

from .._connection import Connection
from .._events import Request
from .._state import CLIENT, ERROR, SERVER
from .._target import validate_request_target
from .._util import LocalProtocolError, RemoteProtocolError


def make_request(method, target, host=b"example.com", http_version=b"1.1"):
    headers = [(b"host", host)] if host is not None else []
    return Request(
        method=method,
        target=target,
        headers=headers,
        http_version=http_version,
    )


VALID_TARGETS = [
    # origin-form
    (b"GET", b"/", b"example.com"),
    (b"GET", b"/index.html", b"example.com"),
    (b"GET", b"//double-slash", b"example.com"),
    (b"POST", b"/a/b/c;x=1?query=1&other=%ff", b"example.com"),
    (b"GET", b"/%7Euser/path%20with%20spaces", b"example.com"),
    (b"GET", b"/?@:%21!", b"example.com"),
    (b"OPTIONS", b"/", b"example.com"),
    # origin-form without a Host (HTTP/1.0 only)
    (b"GET", b"/", None, b"1.0"),
    # absolute-form; an empty path is allowed
    (b"GET", b"http://example.com", b"example.com"),
    (b"GET", b"http://example.com/", b"example.com"),
    (b"GET", b"http://example.com/a?b=c", b"example.com"),
    # scheme / host case-insensitivity, trailing-dot equivalence
    (b"GET", b"HTTP://EXAMPLE.COM/", b"example.com"),
    (b"GET", b"http://example.com./", b"example.com"),
    # percent-encoded unreserved characters in the host
    (b"GET", b"http://%65xample.com/", b"example.com"),
    # ports
    (b"GET", b"http://example.com:8080/", b"example.com:8080"),
    (b"GET", b"http://example.com:0/", b"example.com:0"),
    (b"GET", b"http://example.com:65535/x", b"example.com:65535"),
    # IPv4
    (b"GET", b"http://127.0.0.1/", b"127.0.0.1"),
    # IPv6, with and without port, case normalization, zone id
    (b"GET", b"http://[2001:db8::1]/", b"[2001:db8::1]"),
    (b"GET", b"http://[2001:DB8::1]/", b"[2001:db8::1]"),
    (b"GET", b"http://[::1]:8080/", b"[::1]:8080"),
    (b"GET", b"http://[fe80::1%25eth0]/", b"[fe80::1%25eth0]"),
    # asterisk-form
    (b"OPTIONS", b"*", b"example.com"),
    # authority-form
    (b"CONNECT", b"example.com:443", b"example.com:443"),
    (b"CONNECT", b"[::1]:443", b"[::1]:443"),
    (b"CONNECT", b"127.0.0.1:443", b"127.0.0.1:443"),
]


@pytest.mark.parametrize("case", VALID_TARGETS)
def test_valid_targets(case):
    validate_request_target(make_request(*case))


INVALID_TARGETS = [
    # empty / non-VCHAR / control characters
    (b"GET", b"", b"example.com"),
    (b"GET", b"/\x00", b"example.com"),
    (b"GET", b"/\x01", b"example.com"),
    (b"GET", b"/\x7f", b"example.com"),
    (b"GET", b"/\xee", b"example.com"),
    (b"GET", b"/ path", b"example.com"),
    # malformed percent escapes
    (b"GET", b"/%", b"example.com"),
    (b"GET", b"/%2", b"example.com"),
    (b"GET", b"/%zz", b"example.com"),
    # fragments are never part of a request target
    (b"GET", b"/a#frag", b"example.com"),
    (b"GET", b"/x?a=b#f", b"example.com"),
    (b"GET", b"http://example.com/#frag", b"example.com"),
    # origin-form must be an absolute path
    (b"GET", b"relative/path", b"example.com"),
    (b"GET", b"?query", b"example.com"),
    # '[' and ']' aren't pchar
    (b"GET", b"/foo[bar]", b"example.com"),
    # method / form mismatches
    (b"GET", b"*", b"example.com"),
    (b"POST", b"*", b"example.com"),
    (b"HEAD", b"*", b"example.com"),
    # CONNECT must use authority-form with a port
    (b"CONNECT", b"example.com", b"example.com"),
    (b"CONNECT", b"/", b"example.com"),
    (b"CONNECT", b"http://example.com:443/", b"example.com:443"),
    (b"CONNECT", b"*", b"example.com"),
    # absolute-form must carry an authority
    (b"GET", b"http:", b"example.com"),
    (b"GET", b"http:/x", b"example.com"),
    (b"GET", b"http:///x", b"x"),
    (b"GET", b"1http://x/", b"x"),
    # userinfo forbidden
    (b"GET", b"http://user@example.com/", b"example.com"),
    (b"GET", b"http://user:pass@example.com/", b"example.com"),
    (b"CONNECT", b"user@example.com:443", b"user@example.com:443"),
    # bad ports
    (b"GET", b"http://example.com:99999/", b"example.com:99999"),
    (b"GET", b"http://example.com:abc/", b"example.com:abc"),
    (b"GET", b"http://example.com:/", b"example.com"),
    (b"CONNECT", b"example.com:99999", b"example.com:99999"),
    (b"CONNECT", b"example.com:abc", b"example.com:abc"),
    # bad IPv6
    (b"GET", b"http://[::1/", b"[::1"),
    (b"GET", b"http://[zz::1]/", b"[zz::1]"),
    (b"GET", b"http://[::1]extra/", b"x"),
    # bad IPv4 dotted-numeric
    (b"GET", b"http://999.1.1.1/", b"999.1.1.1"),
    (b"GET", b"http://1.2.3/", b"1.2.3"),
    (b"GET", b"http://1.2.3.4.5/", b"1.2.3.4.5"),
    # Host mismatches
    (b"GET", b"http://a.com/", b"b.com"),
    (b"GET", b"http://example.com:80/", b"example.com:81"),
    (b"GET", b"http://[::1]/", b"[::2]"),
    (b"CONNECT", b"example.com:443", b"example.com:444"),
    # malformed Host headers are rejected for every target form
    (b"GET", b"/", b"user@example.com"),
    (b"GET", b"/", b"example.com:abc"),
    (b"GET", b"/", b"example.com:99999"),
    (b"GET", b"/", b"/"),
    (b"GET", b"http://example.com/", b""),
]


@pytest.mark.parametrize(
    "method,target,host",
    INVALID_TARGETS,
)
def test_invalid_targets(method, target, host):
    with pytest.raises(LocalProtocolError):
        validate_request_target(make_request(method, target, host))


def test_target_bytes_are_not_modified():
    request = make_request(
        b"GET", b"http://EXAMPLE.com/A%2fB?x=1", host=b"EXAMPLE.com"
    )
    validate_request_target(request)
    assert request.target == b"http://EXAMPLE.com/A%2fB?x=1"


def test_client_connection_enforces_strict_target():
    client = Connection(our_role=CLIENT, strict_request_target=True)
    data = client.send(make_request(b"GET", b"/", host=b"example.com"))
    assert b"GET / HTTP/1.1\r\n" in data

    client = Connection(our_role=CLIENT, strict_request_target=True)
    with pytest.raises(LocalProtocolError):
        client.send(make_request(b"GET", b"*", host=b"example.com"))
    # A local failure puts the connection into ERROR
    assert client.our_state is ERROR


def test_client_connection_strict_host_mismatch():
    client = Connection(our_role=CLIENT, strict_request_target=True)
    with pytest.raises(LocalProtocolError):
        client.send(
            make_request(b"GET", b"http://example.com/", host=b"other.example.com")
        )


def test_server_connection_enforces_strict_target():
    server = Connection(our_role=SERVER, strict_request_target=True)
    server.receive_data(b"GET /valid HTTP/1.1\r\nHost: example.com\r\n\r\n")
    event = server.next_event()
    assert type(event) is Request
    assert event.target == b"/valid"

    # A peer violation becomes a RemoteProtocolError, not a local one.
    for wire in [
        b"GET * HTTP/1.1\r\nHost: example.com\r\n\r\n",
        b"POST /a%zz HTTP/1.1\r\nHost: example.com\r\n\r\n",
        b"CONNECT example.com HTTP/1.1\r\nHost: example.com\r\n\r\n",
        b"GET http://a.com/ HTTP/1.1\r\nHost: b.com\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: a@b\r\n\r\n",
    ]:
        server = Connection(our_role=SERVER, strict_request_target=True)
        server.receive_data(wire)
        with pytest.raises(RemoteProtocolError):
            server.next_event()


def test_lenient_mode_keeps_compat_behavior():
    # Default construction performs no form/method/Host consistency checks.
    server = Connection(our_role=SERVER)
    server.receive_data(b"GET * HTTP/1.1\r\nHost: example.com\r\n\r\n")
    event = server.next_event()
    assert type(event) is Request
    assert event.target == b"*"

    server = Connection(our_role=SERVER)
    server.receive_data(b"GET http://a.com/ HTTP/1.1\r\nHost: b.com\r\n\r\n")
    event = server.next_event()
    assert event.target == b"http://a.com/"

    client = Connection(our_role=CLIENT)
    data = client.send(make_request(b"GET", b"*", host=b"example.com"))
    assert b"GET * HTTP/1.1\r\n" in data


def test_strict_flag_is_stored():
    assert Connection(our_role=SERVER)._strict_request_target is False
    assert (
        Connection(our_role=SERVER, strict_request_target=False)
        ._strict_request_target
        is False
    )
    assert (
        Connection(our_role=SERVER, strict_request_target=True)
        ._strict_request_target
        is True
    )
