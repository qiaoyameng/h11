# Strict request-target validation.
#
# By default h11 only checks that a request target consists of visible
# ASCII characters, because that is all the HTTP/1.1 wire grammar
# guarantees. When strict request-target checking is enabled, we also
# verify the target's *form*: that it is consistent with the request
# method, that any percent-escapes and URI authorities are well-formed,
# and that the authority of an absolute-form URI agrees with the Host
# header. This is primarily useful for proxies, where intermediaries
# disagreeing about the interpretation of a request target is a common
# source of request-smuggling vulnerabilities.
#
# Reference: RFC 7230 section 5.3 and RFC 3986.
#
# These functions never modify or normalize their inputs: a target is
# either accepted exactly as received or rejected.

import ipaddress
import re
from typing import List, Optional, Tuple

from ._util import LocalProtocolError

__all__ = ["get_host_header", "validate_request_target"]


# Fragments of the RFC 3986 ABNF, written as pieces of byte-string
# regular expressions.
_unreserved = rb"A-Za-z0-9\-._~"
_sub_delims = rb"!$&'()*+,;="
_pct_encoded = rb"(?:%[0-9A-Fa-f]{2})"
# pchar = unreserved / pct-encoded / sub-delims / ":" / "@"
_pchar = rb"(?:[" + _unreserved + _sub_delims + rb":@]|" + _pct_encoded + rb")"
_segment = _pchar + rb"*"
# query = *( pchar / "/" / "?" )
_query = rb"(?:[" + _unreserved + _sub_delims + rb":@/?]|" + _pct_encoded + rb")*"
# reg-name = *( unreserved / pct-encoded / sub-delims )
_reg_name = rb"(?:[" + _unreserved + _sub_delims + rb"]|" + _pct_encoded + rb")*"
_scheme = rb"[A-Za-z][A-Za-z0-9+\-.]*"
_decimal_octet = rb"[0-9]+"

# origin-form = absolute-path [ "?" query ]
# absolute-path = 1*( "/" segment )
_origin_form_re = re.compile(
    rb"^(?:/" + _segment + rb")+(?:\?" + _query + rb")?$"
)
# The part of an absolute URI after the authority: an optional
# path-abempty followed by an optional query.
# path-abempty = *( "/" segment )
_path_abempty_query_re = re.compile(
    rb"^(?:/" + _segment + rb")*(?:\?" + _query + rb")?$"
)
_reg_name_re = re.compile(rb"^" + _reg_name + rb"$")
_scheme_re = re.compile(rb"^" + _scheme + rb"$")
_port_digits_re = re.compile(rb"^[0-9]+$")
_dotted_decimal_re = re.compile(rb"^(?:[0-9]+\.){3}[0-9]+$")


def get_host_header(headers: List[Tuple[bytes, bytes]]) -> Optional[bytes]:
    """Return the (last) Host header value, or None if there is none.

    h11 already rejects requests with more than one Host header, so at
    most one can be present here.
    """
    host: Optional[bytes] = None
    for name, value in headers:
        if name == b"host":
            host = value
    return host


def validate_request_target(
    *, method: bytes, target: bytes, host_header: Optional[bytes]
) -> None:
    """Validate an HTTP request target against RFC 7230 section 5.3.

    The four request-target forms are:

    * origin-form: ``/path?query``, used by ordinary requests
    * absolute-form: ``http://host/path?query``
    * authority-form: ``host:port``, only valid for CONNECT
    * asterisk-form: ``*``, only valid for OPTIONS

    Raises LocalProtocolError if the target is malformed or does not
    match the method. The target is never modified.
    """
    if not target:
        raise LocalProtocolError("request target must not be empty")

    # asterisk-form = "*"
    if target == b"*":
        if method != b"OPTIONS":
            raise LocalProtocolError(
                "'*' request target is only valid with the OPTIONS method"
            )
        return

    # authority-form is only legal for CONNECT.
    if method == b"CONNECT":
        _, port = _split_authority(target)
        if port is None:
            raise LocalProtocolError("CONNECT request target must include a port")
        return

    # origin-form
    if target.startswith(b"/"):
        if _origin_form_re.fullmatch(target) is None:
            raise LocalProtocolError(
                f"invalid origin-form request target: {target!r}"
            )
        return

    # Anything else must be absolute-form.
    uri_host, uri_port = _parse_absolute_uri(target)
    if host_header is not None:
        _check_host_matches(uri_host, uri_port, host_header)


def _parse_absolute_uri(target: bytes) -> Tuple[bytes, Optional[int]]:
    # RFC 7230 only defines absolute-form in terms of an absolute-URI;
    # in HTTP practice only http and https are used, so we reject other
    # schemes rather than forwarding, e.g., "file:" URIs.
    if b"#" in target:
        raise LocalProtocolError("request targets must not contain a URI fragment")
    marker = target.find(b"://")
    if marker == -1:
        raise LocalProtocolError(
            f"request target is not a valid origin-form, absolute-form, "
            f"authority-form, or asterisk-form target: {target!r}"
        )
    scheme = target[:marker]
    if _scheme_re.fullmatch(scheme) is None or scheme.lower() not in (
        b"http",
        b"https",
    ):
        raise LocalProtocolError(
            f"unsupported URI scheme {scheme!r} in request target "
            f"(only http and https are allowed)"
        )
    rest = target[marker + 3 :]
    # The authority runs up to the first "/" or "?" (an empty
    # path-abempty is allowed, in which case the recipient treats the
    # path as "/").
    delimiter = re.search(rb"[/?]", rest)
    if delimiter is None:
        authority = rest
        path_and_query = b""
    else:
        authority = rest[: delimiter.start()]
        path_and_query = rest[delimiter.start() :]
    host, port = _split_authority(authority)
    if _path_abempty_query_re.fullmatch(path_and_query) is None:
        raise LocalProtocolError(
            f"invalid path in absolute-form request target: {target!r}"
        )
    return host, port


def _split_authority(authority: bytes) -> Tuple[bytes, Optional[int]]:
    """Split "host" or "host:port" into its parts and validate them."""
    if not authority:
        raise LocalProtocolError("request target contains an empty authority")

    # RFC 7230: "A sender MUST NOT generate the userinfo subcomponent".
    if b"@" in authority:
        raise LocalProtocolError(
            "userinfo (user:password@) is not allowed in request targets"
        )

    if authority.startswith(b"["):
        closing_bracket = authority.find(b"]")
        if closing_bracket == -1:
            raise LocalProtocolError(
                f"unterminated IPv6 address literal in authority {authority!r}"
            )
        host = authority[1:closing_bracket]
        _validate_ip_literal(host)
        port = _parse_port_tail(authority[closing_bracket + 1 :], authority)
        return host, port

    if b"[" in authority or b"]" in authority:
        raise LocalProtocolError(
            f"'[' and ']' are only valid around an IPv6 address literal "
            f"in authority {authority!r}"
        )

    host, separator, port_bytes = authority.rpartition(b":")
    if not separator:
        host = authority
        port: Optional[int] = None
    else:
        # A bare (unbracketed) host containing another colon would be an
        # unbracketed IPv6 literal or an ambiguous authority.
        if b":" in host:
            raise LocalProtocolError(
                f"IPv6 address literals must be enclosed in '[' and ']' "
                f"in authority {authority!r}"
            )
        port = _parse_port(port_bytes, authority)
    _validate_host(host)
    return host, port


def _parse_port_tail(tail: bytes, authority: bytes) -> Optional[int]:
    # After an IPv6 literal, the only legal suffix is "" or ":port".
    if tail == b"":
        return None
    if not tail.startswith(b":"):
        raise LocalProtocolError(f"invalid authority {authority!r}")
    return _parse_port(tail[1:], authority)


def _parse_port(port_bytes: bytes, authority: bytes) -> int:
    if _port_digits_re.fullmatch(port_bytes) is None:
        raise LocalProtocolError(
            f"invalid or missing port in authority {authority!r}"
        )
    port = int(port_bytes)
    if port > 65535:
        raise LocalProtocolError(
            f"port {port} in authority {authority!r} is out of range 0-65535"
        )
    return port


def _validate_ip_literal(host: bytes) -> None:
    # The surrounding brackets have already been stripped.
    if host[:1] in (b"v", b"V"):
        raise LocalProtocolError(
            f"IPvFuture address literals are not supported: {host!r}"
        )
    # RFC 7230's IP-literal production only allows a bare IPv6address;
    # scoped/zone identifiers (e.g. fe80::1%eth0) are deliberately
    # rejected to avoid interpretation disagreements at a proxy.
    if b"%" in host:
        raise LocalProtocolError(
            f"zone identifiers are not allowed in IPv6 address literals: "
            f"{host!r}"
        )
    try:
        ipaddress.IPv6Address(host.decode("ascii"))
    except ValueError:
        raise LocalProtocolError(f"invalid IPv6 address literal: {host!r}") from None


def _validate_host(host: bytes) -> None:
    if not host:
        raise LocalProtocolError("request target contains an empty host")
    if _reg_name_re.fullmatch(host) is None:
        raise LocalProtocolError(f"invalid host in request target: {host!r}")
    # A syntactically valid reg-name that looks like a dotted-decimal
    # IPv4 address has to actually be one (e.g. "999.0.0.1" is not).
    if _dotted_decimal_re.fullmatch(host) is not None:
        try:
            ipaddress.IPv4Address(host.decode("ascii"))
        except ValueError:
            raise LocalProtocolError(
                f"invalid IPv4 address in request target: {host!r}"
            ) from None


def _normalize_host(host: bytes) -> Tuple[str, bytes]:
    # Returns a ("ip", packed-bytes) or ("name", lowercase-name) pair for
    # comparison. Inputs have already passed _split_authority, so the
    # only remaining ambiguity is registered-name vs IP address.
    try:
        return ("ip", ipaddress.ip_address(host.decode("ascii")).packed)
    except ValueError:
        return ("name", host.lower())


def _check_host_matches(
    uri_host: bytes, uri_port: Optional[int], host_header: bytes
) -> None:
    try:
        header_host, header_port = _split_authority(host_header)
    except LocalProtocolError:
        raise LocalProtocolError(
            f"absolute-form request target with invalid Host header: "
            f"{host_header!r}"
        ) from None
    if _normalize_host(uri_host) != _normalize_host(header_host):
        raise LocalProtocolError(
            f"absolute-form request target host {uri_host!r} does not match "
            f"Host header {host_header!r}"
        )
    # Ports are compared literally (no default-port normalization): an
    # explicit port in the URI must be echoed explicitly in Host.
    if uri_port != header_port:
        raise LocalProtocolError(
            f"absolute-form request target port {uri_port!r} does not match "
            f"Host header {host_header!r}"
        )
