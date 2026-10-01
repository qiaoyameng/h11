import re
import sys
from typing import List, Optional, Union

from ._util import ErrorLocation

__all__ = ["ReceiveBuffer", "LocatedBytearray"]


class LocatedBytearray(bytearray):
    def __init__(self, data: bytes, connection_offset: int) -> None:
        super().__init__(data)
        self.connection_offset = connection_offset


# Operations we want to support:
# - find next \r\n or \r\n\r\n (\n or \n\n are also acceptable),
#   or wait until there is one
# - read at-most-N bytes
# Goals:
# - on average, do this fast
# - worst case, do this in O(n) where n is the number of bytes processed
# Plan:
# - store bytearray, offset, how far we've searched for a separator token
# - use the how-far-we've-searched data to avoid rescanning
# - while doing a stream of uninterrupted processing, advance offset instead
#   of constantly copying
# WARNING:
# - I haven't benchmarked or profiled any of this yet.
#
# Note that starting in Python 3.4, deleting the initial n bytes from a
# bytearray is amortized O(n), thanks to some excellent work by Antoine
# Martin:
#
#     https://bugs.python.org/issue19087
#
# This means that if we only supported 3.4+, we could get rid of the code here
# involving self._start and self.compress, because it's doing exactly the same
# thing that bytearray now does internally.
#
# BUT unfortunately, we still support 2.7, and reading short segments out of a
# long buffer MUST be O(bytes read) to avoid DoS issues, so we can't actually
# delete this code. Yet:
#
#     https://pythonclock.org/
#
# (Two things to double-check first though: make sure PyPy also has the
# optimization, and benchmark to make sure it's a win, since we do have a
# slightly clever thing where we delay calling compress() until we've
# processed a whole event, which could in theory be slightly more efficient
# than the internal bytearray support.)
blank_line_regex = re.compile(b"\n\r?\n", re.MULTILINE)


class ReceiveBuffer:
    def __init__(self) -> None:
        self._data = bytearray()
        self._next_line_search = 0
        self._multiple_lines_search = 0
        self._consumed = 0
        self._message_start = 0
        self._last_extract_start = 0
        self._last_extract_end = 0

    def __iadd__(self, byteslike: Union[bytes, bytearray]) -> "ReceiveBuffer":
        self._data += byteslike
        return self

    def __bool__(self) -> bool:
        return bool(len(self))

    def __len__(self) -> int:
        return len(self._data)

    @property
    def start_offset(self) -> int:
        return self._consumed

    @property
    def end_offset(self) -> int:
        return self._consumed + len(self._data)

    def begin_message(self) -> None:
        self._message_start = self._consumed

    @property
    def message_start_offset(self) -> int:
        return self._message_start

    def error_location(
        self,
        fragment_type: str,
        connection_offset: Optional[int] = None,
    ) -> ErrorLocation:
        if connection_offset is None:
            connection_offset = self._last_extract_start
        return ErrorLocation(
            connection_offset=connection_offset,
            message_offset=connection_offset - self._message_start,
            fragment_type=fragment_type,
        )

    # for @property unprocessed_data
    def __bytes__(self) -> bytes:
        return bytes(self._data)

    def _extract(self, count: int) -> bytearray:
        # extracting an initial slice of the data buffer and return it
        self._last_extract_start = self._consumed
        out = LocatedBytearray(self._data[:count], self._consumed)
        del self._data[:count]
        self._consumed += len(out)
        self._last_extract_end = self._consumed

        self._next_line_search = 0
        self._multiple_lines_search = 0

        return out

    def maybe_extract_at_most(self, count: int) -> Optional[bytearray]:
        """
        Extract a fixed number of bytes from the buffer.
        """
        out = self._data[:count]
        if not out:
            return None

        return self._extract(count)

    def maybe_extract_next_line(self) -> Optional[bytearray]:
        """
        Extract the first line, if it is completed in the buffer.
        """
        # Only search in buffer space that we've not already looked at.
        search_start_index = max(0, self._next_line_search - 1)
        partial_idx = self._data.find(b"\r\n", search_start_index)

        if partial_idx == -1:
            self._next_line_search = len(self._data)
            return None

        # + 2 is to compensate len(b"\r\n")
        idx = partial_idx + 2

        return self._extract(idx)

    def maybe_extract_lines(self) -> Optional[List[LocatedBytearray]]:
        """
        Extract everything up to the first blank line, and return a list of lines.
        """
        # Handle the case where we have an immediate empty line.
        if self._data[:1] == b"\n":
            self._extract(1)
            return []

        if self._data[:2] == b"\r\n":
            self._extract(2)
            return []

        # Only search in buffer space that we've not already looked at.
        match = blank_line_regex.search(self._data, self._multiple_lines_search)
        if match is None:
            self._multiple_lines_search = max(0, len(self._data) - 2)
            return None

        # Truncate the buffer and return it.
        idx = match.span(0)[-1]
        out = self._extract(idx)
        lines = []
        line_offset = out.connection_offset
        for raw_line in out.split(b"\n"):
            line = LocatedBytearray(raw_line, line_offset)
            line_offset += len(raw_line) + 1
            if line.endswith(b"\r"):
                del line[-1]
            lines.append(line)

        assert lines[-2] == lines[-1] == b""

        del lines[-2:]

        return lines

    # In theory we should wait until `\r\n` before starting to validate
    # incoming data. However it's interesting to detect (very) invalid data
    # early given they might not even contain `\r\n` at all (hence only
    # timeout will get rid of them).
    # This is not a 100% effective detection but more of a cheap sanity check
    # allowing for early abort in some useful cases.
    # This is especially interesting when peer is messing up with HTTPS and
    # sent us a TLS stream where we were expecting plain HTTP given all
    # versions of TLS so far start handshake with a 0x16 message type code.
    def is_next_line_obviously_invalid_request_line(self) -> bool:
        try:
            # HTTP header line must not contain non-printable characters
            # and should not start with a space
            return self._data[0] < 0x21
        except IndexError:
            return False
