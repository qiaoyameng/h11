import re
from typing import Tuple

import pytest

from .._receivebuffer import ReceiveBuffer


def test_receivebuffer() -> None:
    b = ReceiveBuffer()
    assert not b
    assert len(b) == 0
    assert bytes(b) == b""

    b += b"123"
    assert b
    assert len(b) == 3
    assert bytes(b) == b"123"

    assert bytes(b) == b"123"

    assert b.maybe_extract_at_most(2) == b"12"
    assert b
    assert len(b) == 1
    assert bytes(b) == b"3"

    assert bytes(b) == b"3"

    assert b.maybe_extract_at_most(10) == b"3"
    assert bytes(b) == b""

    assert b.maybe_extract_at_most(10) is None
    assert not b

    ################################################################
    # maybe_extract_until_next
    ################################################################

    b += b"123\n456\r\n789\r\n"

    assert b.maybe_extract_next_line() == b"123\n456\r\n"
    assert bytes(b) == b"789\r\n"

    assert b.maybe_extract_next_line() == b"789\r\n"
    assert bytes(b) == b""

    b += b"12\r"
    assert b.maybe_extract_next_line() is None
    assert bytes(b) == b"12\r"

    b += b"345\n\r"
    assert b.maybe_extract_next_line() is None
    assert bytes(b) == b"12\r345\n\r"

    # here we stopped at the middle of b"\r\n" delimiter

    b += b"\n6789aaa123\r\n"
    assert b.maybe_extract_next_line() == b"12\r345\n\r\n"
    assert b.maybe_extract_next_line() == b"6789aaa123\r\n"
    assert b.maybe_extract_next_line() is None
    assert bytes(b) == b""

    ################################################################
    # maybe_extract_lines
    ################################################################

    b += b"123\r\na: b\r\nfoo:bar\r\n\r\ntrailing"
    lines = b.maybe_extract_lines()
    assert lines == [b"123", b"a: b", b"foo:bar"]
    assert bytes(b) == b"trailing"

    assert b.maybe_extract_lines() is None

    b += b"\r\n\r"
    assert b.maybe_extract_lines() is None

    assert b.maybe_extract_at_most(100) == b"trailing\r\n\r"
    assert not b

    # Empty body case (as happens at the end of chunked encoding if there are
    # no trailing headers, e.g.)
    b += b"\r\ntrailing"
    assert b.maybe_extract_lines() == []
    assert bytes(b) == b"trailing"


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(
            (
                b"HTTP/1.1 200 OK\r\n",
                b"Content-type: text/plain\r\n",
                b"Connection: close\r\n",
                b"\r\n",
                b"Some body",
            ),
            id="with_crlf_delimiter",
        ),
        pytest.param(
            (
                b"HTTP/1.1 200 OK\n",
                b"Content-type: text/plain\n",
                b"Connection: close\n",
                b"\n",
                b"Some body",
            ),
            id="with_lf_only_delimiter",
        ),
        pytest.param(
            (
                b"HTTP/1.1 200 OK\n",
                b"Content-type: text/plain\r\n",
                b"Connection: close\n",
                b"\n",
                b"Some body",
            ),
            id="with_mixed_crlf_and_lf",
        ),
    ],
)
def test_receivebuffer_for_invalid_delimiter(data: Tuple[bytes]) -> None:
    b = ReceiveBuffer()

    for line in data:
        b += line

    lines = b.maybe_extract_lines()

    assert lines == [
        b"HTTP/1.1 200 OK",
        b"Content-type: text/plain",
        b"Connection: close",
    ]
    assert bytes(b) == b"Some body"


def test_extracted_line_offsets_survive_compaction() -> None:
    b = ReceiveBuffer()
    b += b"first\r\nsecond\r\n"

    assert b.maybe_extract_next_line_with_offset() == (b"first\r\n", 0)
    assert b.consumed_offset == 7
    assert b.maybe_extract_next_line_with_offset() == (b"second\r\n", 7)
    assert b.consumed_offset == 15
    assert not b


def test_header_line_offsets_for_lf_and_crlf() -> None:
    for separator in (b"\r\n", b"\n"):
        b = ReceiveBuffer()
        b += (
            b"GET / HTTP/1.1"
            + separator
            + b"Host: example.com"
            + separator
            + separator
        )

        lines, start, end = b.maybe_extract_lines_with_offsets()
        total_length = len(
            b"GET / HTTP/1.1"
            + separator
            + b"Host: example.com"
            + separator
            + separator
        )

        assert start == 0
        assert end == total_length
        assert lines == [
            (bytearray(b"GET / HTTP/1.1"), 0),
            (
                bytearray(b"Host: example.com"),
                len(b"GET / HTTP/1.1" + separator),
            ),
        ]
