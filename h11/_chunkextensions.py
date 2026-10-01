import re
from typing import List, Optional, Tuple

from ._abnf import token
from ._util import LocalProtocolError, bytesify

ChunkExtension = Tuple[bytes, Optional[bytes]]
ChunkExtensions = List[ChunkExtension]

_token_re = re.compile(token.encode("ascii"))


def normalize_chunk_extensions(
    extensions: object,
    *,
    _parsed: bool = False,
) -> Optional[ChunkExtensions]:
    if extensions is None:
        return None
    if not isinstance(extensions, list):
        raise TypeError("chunk extensions must be a list of (name, value) pairs")

    normalized: ChunkExtensions = []
    for extension in extensions:
        if not isinstance(extension, tuple) or len(extension) != 2:
            raise TypeError("chunk extensions must be (name, value) pairs")
        name, value = extension
        if not _parsed:
            name = bytesify(name)
            if value is not None:
                value = bytesify(value)
        if not isinstance(name, bytes) or (
            value is not None and not isinstance(value, bytes)
        ):
            raise TypeError("chunk extension names and values must be bytes")
        if not _token_re.fullmatch(name):
            raise LocalProtocolError(f"invalid chunk extension name {name!r}")
        normalized.append((name, value))
    return normalized


def _skip_whitespace(data: bytes, position: int) -> int:
    while position < len(data) and data[position] in (0x09, 0x20):
        position += 1
    return position


def parse_chunk_extensions(raw: bytes) -> ChunkExtensions:
    extensions: ChunkExtensions = []
    position = 0

    while True:
        position = _skip_whitespace(raw, position)
        if position == len(raw):
            break
        if raw[position] != 0x3B:
            raise LocalProtocolError("malformed chunk extensions")
        position += 1
        position = _skip_whitespace(raw, position)

        name_match = _token_re.match(raw, position)
        if name_match is None:
            raise LocalProtocolError("malformed chunk extension name")
        name = name_match.group(0)
        position = name_match.end()
        value: Optional[bytes] = None

        if position < len(raw) and raw[position] == 0x3D:
            position += 1
            if position >= len(raw):
                raise LocalProtocolError("missing chunk extension value")
            if raw[position] == 0x22:
                position += 1
                quoted_value = bytearray()
                while True:
                    if position >= len(raw):
                        raise LocalProtocolError("unterminated chunk extension value")
                    char = raw[position]
                    if char == 0x22:
                        position += 1
                        break
                    if char == 0x5C:
                        position += 1
                        if position >= len(raw):
                            raise LocalProtocolError(
                                "unterminated chunk extension escape"
                            )
                        char = raw[position]
                        if not _valid_quoted_character(char):
                            raise LocalProtocolError("invalid chunk extension escape")
                    elif char == 0x0D or char == 0x0A or char == 0x7F:
                        raise LocalProtocolError("invalid chunk extension character")
                    elif char < 0x20 and char != 0x09:
                        raise LocalProtocolError("invalid chunk extension character")
                    quoted_value.append(char)
                    position += 1
                value = bytes(quoted_value)
            else:
                value_match = _token_re.match(raw, position)
                if value_match is None or value_match.start() != position:
                    raise LocalProtocolError("malformed chunk extension value")
                value = value_match.group(0)
                position = value_match.end()

        extensions.append((name, value))

    return extensions


def _valid_quoted_character(char: int) -> bool:
    return (
        char == 0x09
        or char == 0x20
        or 0x21 <= char <= 0x7E
        or 0x80 <= char <= 0xFF
    )


def encode_chunk_extensions(extensions: Optional[ChunkExtensions]) -> bytes:
    if extensions is None:
        return b""

    encoded = bytearray()
    for name, value in extensions:
        if not _token_re.fullmatch(name):
            raise LocalProtocolError(f"invalid chunk extension name {name!r}")
        encoded.extend(b";")
        encoded.extend(name)
        if value is None:
            continue

        encoded.extend(b"=")
        if _token_re.fullmatch(value):
            encoded.extend(value)
            continue

        encoded.append(0x22)
        for char in value:
            if not _valid_quoted_character(char):
                raise LocalProtocolError(
                    f"invalid chunk extension character in {name!r}"
                )
            if char == 0x22 or char == 0x5C:
                encoded.append(0x5C)
            encoded.append(char)
        encoded.append(0x22)

    return bytes(encoded)
