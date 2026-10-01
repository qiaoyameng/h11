# We use native strings for all the re patterns, to take advantage of string
# formatting, and then convert to bytestrings when compiling the final re
# objects.

# https://svn.tools.ietf.org/svn/wg/httpbis/specs/rfc7230.html#whitespace
#  OWS            = *( SP / HTAB )
#                 ; optional whitespace
OWS = r"[ \t]*"

# https://svn.tools.ietf.org/svn/wg/httpbis/specs/rfc7230.html#rule.token.separators
#   token          = 1*tchar
#
#   tchar          = "!" / "#" / "$" / "%" / "&" / "'" / "*"
#                  / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
#                  / DIGIT / ALPHA
#                  ; any VCHAR, except delimiters
token = r"[-!#$%&'*+.^_`|~0-9a-zA-Z]+"

# https://svn.tools.ietf.org/svn/wg/httpbis/specs/rfc7230.html#header.fields
#  field-name     = token
field_name = token

# The standard says:
#
#  field-value    = *( field-content / obs-fold )
#  field-content  = field-vchar [ 1*( SP / HTAB ) field-vchar ]
#  field-vchar    = VCHAR / obs-text
#  obs-fold       = CRLF 1*( SP / HTAB )
#                 ; obsolete line folding
#                 ; see Section 3.2.4
#
# https://tools.ietf.org/html/rfc5234#appendix-B.1
#
#   VCHAR          =  %x21-7E
#                  ; visible (printing) characters
#
# https://svn.tools.ietf.org/svn/wg/httpbis/specs/rfc7230.html#rule.quoted-string
#   obs-text       = %x80-FF
#
# However, the standard definition of field-content is WRONG! It disallows
# fields containing a single visible character surrounded by whitespace,
# e.g. "foo a bar".
#
# See: https://www.rfc-editor.org/errata_search.php?rfc=7230&eid=4189
#
# So our definition of field_content attempts to fix it up...
#
# Also, we allow lots of control characters, because apparently people assume
# that they're legal in practice (e.g., google analytics makes cookies with
# \x01 in them!):
#   https://github.com/python-hyper/h11/issues/57
# We still don't allow NUL or whitespace, because those are often treated as
# meta-characters and letting them through can lead to nasty issues like SSRF.
vchar = r"[\x21-\x7e]"
vchar_or_obs_text = r"[^\x00\s]"
field_vchar = vchar_or_obs_text
field_content = r"{field_vchar}+(?:[ \t]+{field_vchar}+)*".format(**globals())

# We handle obs-fold at a different level, and our fixed-up field_content
# already grows to swallow the whole value, so ? instead of *
field_value = r"({field_content})?".format(**globals())

#  header-field   = field-name ":" OWS field-value OWS
header_field = (
    r"(?P<field_name>{field_name})"
    r":"
    r"{OWS}"
    r"(?P<field_value>{field_value})"
    r"{OWS}".format(**globals())
)

# https://svn.tools.ietf.org/svn/wg/httpbis/specs/rfc7230.html#request.line
#
#   request-line   = method SP request-target SP HTTP-version CRLF
#   method         = token
#   HTTP-version   = HTTP-name "/" DIGIT "." DIGIT
#   HTTP-name      = %x48.54.54.50 ; "HTTP", case-sensitive
#
# request-target is complicated (see RFC 7230 sec 5.3) -- could be path, full
# URL, host+port (for connect), or even "*", but in any case we are guaranteed
# that it contists of the visible printing characters.
method = token
request_target = r"{vchar}+".format(**globals())
http_version = r"HTTP/(?P<http_version>[0-9]\.[0-9])"
request_line = (
    r"(?P<method>{method})"
    r" "
    r"(?P<target>{request_target})"
    r" "
    r"{http_version}".format(**globals())
)

# https://svn.tools.ietf.org/svn/wg/httpbis/specs/rfc7230.html#status.line
#
#   status-line = HTTP-version SP status-code SP reason-phrase CRLF
#   status-code    = 3DIGIT
#   reason-phrase  = *( HTAB / SP / VCHAR / obs-text )
status_code = r"[0-9]{3}"
reason_phrase = r"([ \t]|{vchar_or_obs_text})*".format(**globals())
status_line = (
    r"{http_version}"
    r" "
    r"(?P<status_code>{status_code})"
    # However, there are apparently a few too many servers out there that just
    # leave out the reason phrase:
    #   https://github.com/scrapy/scrapy/issues/345#issuecomment-281756036
    #   https://github.com/seanmonstar/httparse/issues/29
    # so make it optional. ?: is a non-capturing group.
    r"(?: (?P<reason>{reason_phrase}))?".format(**globals())
)

HEXDIG = r"[0-9A-Fa-f]"
# Actually
#
#      chunk-size     = 1*HEXDIG
#
# but we impose an upper-limit to avoid ridiculosity. len(str(2**64)) == 20
chunk_size = r"({HEXDIG}){{1,20}}".format(**globals())

# https://www.rfc-editor.org/rfc/rfc7230#section-3.2.6
#
#   quoted-string  = DQUOTE *( qdtext / quoted-pair ) DQUOTE
#   qdtext         = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text
#   quoted-pair    = "\" ( HTAB / SP / VCHAR / obs-text )
qdtext = r"[\t\x20\x21\x23-\x5b\x5d-\x7e\x80-\xff]"
quoted_pair = r"\\[\t\x20-\x7e\x80-\xff]"
quoted_string = r'"(?:{qdtext}|{quoted_pair})*"'.format(**globals())

# https://www.rfc-editor.org/rfc/rfc7230#section-4.1.1
#
#   chunk-ext      = *( ";" chunk-ext-name [ "=" chunk-ext-val ] )
#   chunk-ext-name = token
#   chunk-ext-val  = token / quoted-string
#
# chunk_ext_part matches a single ";" name [= value] element, and is used to
# actually parse the extensions when preserve_chunk_extensions is enabled.
chunk_ext_name = token
chunk_ext_val = r"(?:{token}|{quoted_string})".format(**globals())
chunk_ext_part = (
    r";(?P<ext_name>{chunk_ext_name})"
    r"(?:=(?P<ext_val>{chunk_ext_val}))?"
).format(**globals())
# When not parsing chunk extensions, we accept (and discard) anything after
# the chunk-size, like we always have.
chunk_ext = r";.*"
chunk_header = (
    r"(?P<chunk_size>{chunk_size})"
    r"(?P<chunk_ext>{chunk_ext})?"
    r"{OWS}\r\n".format(
        **globals()
    )  # Even though the specification does not allow for extra whitespaces,
    # we are lenient with trailing whitespaces because some servers on the wild use it.
)
