import pytest

from .._uri import validate_request_target
from .._util import LocalProtocolError


def check_valid(method, target, host=None):
    # The validator must never modify the target bytes.
    original = bytes(target)
    validate_request_target(method=method, target=target, host_header=host)
    assert target == original


def check_invalid(method, target, host=None):
    with pytest.raises(LocalProtocolError):
        validate_request_target(
            method=method, target=target, host_header=host
        )


# -- origin-form ----------------------------------------------------------

@pytest.mark.parametrize(
    "target",
    [
        b"/",
        b"/index.html",
        b"/path/to/resource",
        b"/",
        b"//",
        b"/a//b",
        b"/a/b?q=1&r=2",
        b"/%7euser",
        b"/%00",
        b"/weird%2Dbut%2Dok",
        b"/path;parameters",
        b"/path:colon",
        b"/path@at",
        b"/?q=%2Fslash",
    ],
)
def test_valid_origin_form(target):
    check_valid(b"GET", target)
    check_valid(b"POST", target)
    check_valid(b"OPTIONS", target)


@pytest.mark.parametrize(
    "target",
    [
        b"",
        b"relative/path",
        b"/bad escape/%2",
        b"/bad%/x",
        b"/%zz",
        b"/contains space",
        b"/control\x01",
        b"/del\x7f",
        b'/double"quote',
        b"/back\\slash",
        b"/pipe|",
        b"/bracket[",
        b"/frag#ment",
        b"*",
    ],
)
def test_invalid_origin_form(target):
    if target == b"*":
        # "*" is valid for OPTIONS, invalid for other methods
        check_invalid(b"GET", target)
        check_valid(b"OPTIONS", target)
    else:
        check_invalid(b"GET", target)


def test_empty_target_rejected():
    check_invalid(b"GET", b"")


# -- asterisk-form --------------------------------------------------------

def test_asterisk_form():
    check_valid(b"OPTIONS", b"*")
    for method in [b"GET", b"HEAD", b"POST", b"PUT", b"DELETE", b"CONNECT"]:
        check_invalid(method, b"*")


# -- authority-form (CONNECT) --------------------------------------------

@pytest.mark.parametrize(
    "target",
    [
        b"example.com:443",
        b"host:80",
        b"localhost:1",
        b"host:65535",
        b"host:0",
        b"192.0.2.1:443",
        b"[::1]:443",
        b"[2001:db8::1]:8080",
        b"[0:0:0:0:0:0:0:1]:443",
        b"host-name.example:443",
        b"host%2dname:443",
    ],
)
def test_valid_authority_form(target):
    check_valid(b"CONNECT", target)


@pytest.mark.parametrize(
    "target",
    [
        b"example.com",
        b"host:",
        b"host:abc",
        b"host:65536",
        b"host:99999",
        b"host:-1",
        b"host:443/",
        b"user@host:443",
        b"[::1]",
        b"[::1]:",
        b"[fe80::1%25eth0]:443",
        b"[fe80::1%eth0]:443",
        b"[::1]:99999",
        b"[not-an-ip]:443",
        b"[v1.fe80]:443",
        b"::1:443",
        b"/path",
        b"192.0.2.999:443",
        b"",
    ],
)
def test_invalid_authority_form(target):
    check_invalid(b"CONNECT", target)


def test_connect_rejects_non_authority_forms():
    check_invalid(b"CONNECT", b"http://example.com:443/")
    check_invalid(b"CONNECT", b"/path")
    check_invalid(b"CONNECT", b"*")


# -- absolute-form --------------------------------------------------------

@pytest.mark.parametrize(
    "target,host",
    [
        (b"http://example.com/", b"example.com"),
        (b"http://example.com:8080/", b"example.com:8080"),
        (b"https://example.com/", b"example.com"),
        (b"http://EXAMPLE.com/", b"example.com"),
        (b"http://example.com/", b"EXAMPLE.COM"),
        (b"http://example.com", b"example.com"),
        (b"http://example.com?", b"example.com"),
        (b"http://example.com?q=1", b"example.com"),
        (b"http://example.com/path", b"example.com"),
        (b"http://example.com/a/b?q=1", b"example.com"),
        (b"http://192.0.2.1/", b"192.0.2.1"),
        (b"http://[::1]/", b"[::1]"),
        (b"http://[::1]:8080/", b"[::1]:8080"),
        (b"http://[2001:db8::1]/x", b"[2001:db8::1]"),
        (b"HTTP://example.com/", b"example.com"),
        (b"Http://example.com/", b"example.com"),
    ],
)
def test_valid_absolute_form(target, host):
    check_valid(b"GET", target, host)
    check_valid(b"OPTIONS", target, host)
    # With no Host header the comparison is skipped.
    check_valid(b"GET", target, None)


@pytest.mark.parametrize(
    "target,host",
    [
        (b"http://example.com/", b"other.example"),
        (b"http://example.com:8080/", b"example.com"),
        (b"http://example.com/", b"example.com:8080"),
        (b"http://example.com:80/", b"example.com:8080"),
        (b"http://192.0.2.1/", b"192.0.2.2"),
        (b"http://[::1]/", b"[::2]"),
        (b"http://[::1]:8080/", b"[::1]:80"),
        (b"http://example.com/", b"evil@example.com"),
        (b"http://example.com/", b"example.com#frag"),
    ],
)
def test_absolute_form_host_mismatch(target, host):
    check_invalid(b"GET", target, host)


@pytest.mark.parametrize(
    "target",
    [
        b"ftp://example.com/",
        b"file:///etc/passwd",
        b"://example.com/",
        b"http://",
        b"https://",
        b"http://user:pass@example.com/",
        b"http://user@example.com/",
        b"http://example.com:99999/",
        b"http://example.com:/",
        b"http://[::1/",
        b"http://::1/",
        b"http://[zzz]/",
        b"http://192.0.2.999/",
        b"http://example.com/#fragment",
        b"http://example.com/path#frag",
        b"http://example.com/space here",
        b"http://example.com/bad%2",
        b"not-a-uri",
        b"",
    ],
)
def test_invalid_absolute_form(target):
    check_invalid(b"GET", target, b"example.com")
