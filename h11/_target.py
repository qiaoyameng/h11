# Strict validation of request-targets.
#
# In its default, backwards-compatible mode h11 only checks that a
# request-target is non-empty and contains visible (VCHAR) characters;
# it passes it straight through to the caller.  That's fine for most
# applications, but for things like proxies it's useful to enforce the
# grammar of RFC 7230 section 5.3, which defines four possible forms:
#
#   origin-form    = absolute-path [ "?" query ]
#   absolute-form  = absolute-URI
#   authority-form = authority
#   asterisk-form  = "*"
#
# The rules about which method is allowed to use which form come from
# RFC 7230 sections 5.3.3 (authority-form is for CONNECT only) and
# 5.3.4 (asterisk-form is for OPTIONS only).
#
# The URI grammar used here is from RFC 3986.

import ipaddress
import re
from typing import TYPE_CHECKING, Iterable, Optional, Tuple

if TYPE_CHECKING:
    from ._events import Request

from ._util import LocalProtocolError

__all__ = ["validate_request_target"]

# RFC 3986 section 2.3
unreserved_chars = rb"A-Za-z0-9\-._~"
# RFC 3986 section 2.2 (subset that makes sense in a URI; ":" / "@" / "/"
# are given their structural meaning elsewhere)
sub_delims_chars = rb"!$&'()*+,;="
# A percent-encoded octet, or any single pchar character apart from
# percent itself (which is only valid as the start of a percent-escape).
_pchar = rb"(?:%[0-9A-Fa-f]{2}|[" + unreserved_chars + sub_delims_chars + rb":@])"
_segment = rb"(?:" + _pchar + rb")*"

# absolute-path = 1*( "/" segment )
_origin_form_re = re.compile(
    rb"(?:/" + _segment + rb")+(?:\?(?:" + _pchar + rb"|/|\?)*)?"
)

# scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
_scheme_re = re.compile(rb"([A-Za-z][A-Za-z0-9+\-.]*):(.*)")

# After the authority, RFC 3986 allows path-abempty = *( "/" segment ),
# optionally followed by "?" query.
_path_abempty_re = re.compile(
    rb"(?:/" + _segment + rb")*(?:\?(?:" + _pchar + rb"|/|\?)*)?"
)

# reg-name = *( unreserved / pct-encoded / sub-delims )
_reg_name_re = re.compile(
    rb"(?:%[0-9A-Fa-f]{2}|[" + unreserved_chars + sub_delims_chars + rb"])*"
)

_dec_octet = rb"(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
_ipv4_re = re.compile(rb"(?:" + _dec_octet + rb"\.){3}" + _dec_octet)
# A dotted host whose segments are all digits can only possibly be an
# IPv4 address; treat malformed ones as such rather than as reg-names.
_dotted_numeric_re = re.compile(rb"[0-9]+(?:\.[0-9]+)+")

# Everything that may legitimately appear in a request-target is VCHAR
# (no whitespace, no control characters, and -- since we match the
# patterns with fullmatch -- nothing non-ASCII either).
_vchar_re = re.compile(rb"[\x21-\x7e]+")


def _pct_decode_reg_name(host: bytes) -> bytes:
    # Percent escapes in a reg-name represent raw octets; the only way
    # they can end up valid is by decoding to an unreserved character.
    out = bytearray()
    i = 0
    while i < len(host):
        ch = host[i]
        if ch == 0x25:  # "%"
            out.append(int(host[i + 1 : i + 3], 16))
            i += 3
        else:
            out.append(ch)
            i += 1
    return bytes(out)


def _validate_reg_name(host: bytes) -> bytes:
    if not _reg_name_re.fullmatch(host):
        raise LocalProtocolError("illegal character in host")
    decoded = _pct_decode_reg_name(host)
    if not re.fullmatch(b"[" + unreserved_chars + b"]*", decoded):
        raise LocalProtocolError(
            "percent-escape in host does not decode to an unreserved character"
        )
    # Host names are case-insensitive, and percent-encoded unreserved
    # characters are equivalent to the characters themselves
    # (RFC 3986 section 6.2.2.2).  We only use this normalized form for
    # comparison against the Host header -- the original target bytes
    # are never touched.
    canonical = decoded.lower()
    # A trailing "." marks a fully-qualified domain name and names the
    # same host as without it (RFC 3986 section 3.2.2).
    if canonical.endswith(b"."):
        canonical = canonical[:-1]
    return canonical


def _validate_ipv6(host: bytes) -> bytes:
    # IPv6 addresses may carry a zone identifier (RFC 6874), encoded as
    # "%25" followed by the zone id.
    try:
        return str(ipaddress.IPv6Address(host.decode("ascii"))).encode("ascii")
    except ValueError:
        pass
    if b"%25" in host:
        decoded = host.replace(b"%25", b"%", 1)
        try:
            return str(ipaddress.IPv6Address(decoded.decode("ascii"))).encode("ascii")
        except ValueError:
            pass
    raise LocalProtocolError("illegal IPv6 address")


# Returns (canonical_host, port), suitable for case-insensitive
# comparison against the Host header.  userinfo is always rejected.
def _parse_authority(
    authority: bytes, *, require_port: bool
) -> Tuple[bytes, Optional[int]]:
    if b"@" in authority:
        raise LocalProtocolError("userinfo is not allowed in request target")

    host: bytes
    port_bytes: Optional[bytes]
    if authority[:1] == b"[":
        end = authority.find(b"]")
        if end == -1:
            raise LocalProtocolError("unterminated IPv6 address")
        host = authority[1:end]
        rest = authority[end + 1 :]
        if rest == b"":
            port_bytes = None
        elif rest[:1] == b":":
            port_bytes = rest[1:]
        else:
            raise LocalProtocolError("illegal character after IPv6 address")
        canonical_host = b"[" + _validate_ipv6(host) + b"]"
    else:
        if b"[" in authority or b"]" in authority:
            raise LocalProtocolError("illegal character in authority")
        if authority.count(b":") > 1:
            raise LocalProtocolError("illegal port in authority")
        host, sep, port_bytes_ = authority.rpartition(b":")
        if sep and host != b"":
            port_bytes = port_bytes_
        else:
            host = authority
            port_bytes = None
        if not host:
            raise LocalProtocolError("empty host in request target")
        if _dotted_numeric_re.fullmatch(host) and not _ipv4_re.fullmatch(host):
            raise LocalProtocolError("illegal IPv4 address")
        if _ipv4_re.fullmatch(host):
            try:
                canonical_host = str(
                    ipaddress.IPv4Address(host.decode("ascii"))
                ).encode("ascii")
            except ValueError:
                raise LocalProtocolError("illegal IPv4 address")
        else:
            canonical_host = _validate_reg_name(host)

    if port_bytes is None:
        if require_port:
            raise LocalProtocolError("CONNECT target must include a port")
        port = None
    else:
        if not re.fullmatch(rb"[0-9]+", port_bytes):
            raise LocalProtocolError("illegal port in request target")
        port = int(port_bytes)
        if port > 65535:
            raise LocalProtocolError("port out of range in request target")

    return canonical_host, port


def _get_host_header(headers: Iterable[Tuple[bytes, bytes]]) -> Optional[bytes]:
    # Headers is a list of (name, value) byte pairs with lowercased
    # names; the Request constructor already rejects duplicate Host
    # headers.
    host_value = None
    for name, value in headers:
        if name == b"host":
            host_value = value
    return host_value


def _validate_host_header(
    host_value: bytes,
) -> Tuple[bytes, Optional[int]]:
    if not _vchar_re.fullmatch(host_value):
        raise LocalProtocolError("illegal Host header")
    if host_value[:1] == b"[":
        end = host_value.find(b"]")
        if end == -1:
            raise LocalProtocolError("illegal Host header")
        host = host_value[1:end]
        rest = host_value[end + 1 :]
        canonical_host = b"[" + _validate_ipv6(host) + b"]"
        if rest == b"":
            port = None
        elif rest[:1] == b":":
            port = _parse_port(rest[1:])
        else:
            raise LocalProtocolError("illegal Host header")
    else:
        if b"@" in host_value:
            raise LocalProtocolError("userinfo is not allowed in Host header")
        if b"[" in host_value or b"]" in host_value:
            raise LocalProtocolError("illegal Host header")
        if host_value.count(b":") > 1:
            raise LocalProtocolError("illegal Host header")
        host, sep, port_bytes = host_value.rpartition(b":")
        if sep and host != b"":
            if _dotted_numeric_re.fullmatch(host) and not _ipv4_re.fullmatch(host):
                raise LocalProtocolError("illegal Host header")
            if _ipv4_re.fullmatch(host):
                try:
                    canonical_host = str(
                        ipaddress.IPv4Address(host.decode("ascii"))
                    ).encode("ascii")
                except ValueError:
                    raise LocalProtocolError("illegal Host header")
            else:
                canonical_host = _validate_reg_name(host)
            port = _parse_port(port_bytes)
        else:
            if _dotted_numeric_re.fullmatch(host_value) and not _ipv4_re.fullmatch(
                host_value
            ):
                raise LocalProtocolError("illegal Host header")
            if _ipv4_re.fullmatch(host_value):
                try:
                    canonical_host = str(
                        ipaddress.IPv4Address(host_value.decode("ascii"))
                    ).encode("ascii")
                except ValueError:
                    raise LocalProtocolError("illegal Host header")
            else:
                canonical_host = _validate_reg_name(host_value)
            port = None
    if not canonical_host or canonical_host == b".":
        raise LocalProtocolError("empty host in Host header")
    return canonical_host, port


def _parse_port(port_bytes: bytes) -> int:
    if not re.fullmatch(rb"[0-9]+", port_bytes):
        raise LocalProtocolError("illegal port in Host header")
    port = int(port_bytes)
    if port > 65535:
        raise LocalProtocolError("port out of range in Host header")
    return port


def _check_host_header(
    headers: Iterable[Tuple[bytes, bytes]],
    target_authority: Optional[Tuple[bytes, Optional[int]]] = None,
) -> None:
    host_value = _get_host_header(headers)
    if host_value is None:
        # RFC 7230 5.4: HTTP/1.1 requests without a Host header are
        # already rejected by the Request constructor.
        return
    # An invalid Host field-value must be rejected regardless of the
    # request-target form (RFC 7230 section 5.4).
    header_authority = _validate_host_header(host_value)
    # For absolute-form / authority-form, the Host header must also
    # identify the same host (and port) as the target.
    if target_authority is not None and header_authority != target_authority:
        raise LocalProtocolError(
            "Host header does not match the authority of the request target"
        )


def validate_request_target(
    request: "Request",
) -> None:
    """Strictly validate a :class:`Request`'s request-target.

    This enforces the four request-target forms from RFC 7230 section
    5.3, checks that the form matches the method, and (for
    authority-form and absolute-form) checks consistency with the
    ``Host`` header.  The request's ``target`` bytes are never modified.

    Raises :class:`LocalProtocolError` if the request is invalid.
    """
    method: bytes = request.method
    target: bytes = request.target

    if not target:
        raise LocalProtocolError("empty request target")
    if not _vchar_re.fullmatch(target):
        raise LocalProtocolError("illegal characters in request target")

    if target == b"*":
        # asterisk-form: OPTIONS only (RFC 7230 5.3.4)
        if method != b"OPTIONS":
            raise LocalProtocolError(
                "asterisk-form request target is only valid with OPTIONS"
            )
        return

    if method == b"CONNECT":
        # authority-form (RFC 7230 5.3.3): just host:port, and unlike
        # the authority component of an absolute URI the port is
        # required.
        authority = _parse_authority(target, require_port=True)
        _check_host_header(request.headers, authority)
        return

    scheme_match = _scheme_re.fullmatch(target)
    if scheme_match is not None:
        # absolute-form
        remainder = scheme_match.group(2)
        if not remainder.startswith(b"//"):
            raise LocalProtocolError(
                "absolute-form request target must have an authority component"
            )
        authority_and_path = remainder[2:]
        # authority = [ userinfo "@" ] host [ ":" port ]
        slash = authority_and_path.find(b"/")
        question = authority_and_path.find(b"?")
        cut = len(authority_and_path)
        if slash != -1:
            cut = slash
        if question != -1 and question < cut:
            cut = question
        authority_bytes = authority_and_path[:cut]
        path_and_query = authority_and_path[cut:]
        authority = _parse_authority(authority_bytes, require_port=False)
        if not _path_abempty_re.fullmatch(path_and_query):
            raise LocalProtocolError("illegal path in request target")
        _check_host_header(request.headers, authority)
        return

    # origin-form
    if not target.startswith(b"/"):
        raise LocalProtocolError(
            "request target must be an origin-form path starting with '/', "
            "an absolute URI, an authority (CONNECT only), or '*' (OPTIONS only)"
        )
    if not _origin_form_re.fullmatch(target):
        raise LocalProtocolError("illegal characters in request target path")
    _check_host_header(request.headers)
