import json
from typing import Any, Dict, List

import pytest

from .._connection import Connection, NEED_DATA, PAUSED, SNAPSHOT_FORMAT_VERSION
from .._events import (
    Data,
    EndOfMessage,
    Event,
    InformationalResponse,
    Request,
    Response,
)
from .._state import CLIENT, DONE, IDLE, SEND_BODY, SERVER
from .helpers import get_all_events, receive_and_get


def json_roundtrip(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    # Snapshots must contain only plain JSON-safe data -- no sockets, event
    # objects, or other live references.
    return json.loads(json.dumps(snapshot))


def restore(conn: Connection) -> Connection:
    return Connection.from_snapshot(json_roundtrip(conn.snapshot()))


def feed(conn: Connection, chunks: List[bytes]) -> List[Event]:
    events = []
    for chunk in chunks:
        events += receive_and_get(conn, chunk)
    return events


def test_snapshot_is_json_safe_and_versioned() -> None:
    conn = Connection(SERVER)
    conn.receive_data(b"GET / HTTP/1.1\r\nHost: example.com\r\n")
    snapshot = conn.snapshot()
    assert snapshot["version"] == SNAPSHOT_FORMAT_VERSION
    # Must round-trip through JSON unchanged
    assert json_roundtrip(snapshot) == snapshot


def test_snapshot_fresh_connection() -> None:
    for role in (CLIENT, SERVER):
        conn = restore(Connection(role))
        assert conn.our_role is role
        assert conn.states == Connection(role).states
        assert conn.trailing_data == (b"", False)


def test_snapshot_mid_request_headers() -> None:
    # Snapshot with half a request (request line + partial headers) sitting
    # unconsumed in the receive buffer.
    first = b"GET /foo HTTP/1.1\r\nHost: example.com\r\nX-Long-Header: aaa"
    rest = [
        b"aaa\r\nContent-Length: 5\r\n\r\nhel",
        b"lo",
    ]
    reference = Connection(SERVER)
    reference.receive_data(first)
    assert reference.next_event() is NEED_DATA

    conn = restore(reference)
    assert conn.trailing_data == (first, False)
    assert conn.our_role is SERVER

    assert feed(conn, rest) == feed(reference, rest)
    assert conn.states == reference.states


def test_snapshot_mid_chunked_body() -> None:
    headers = (
        b"POST / HTTP/1.1\r\nHost: example.com\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n"
    )
    # Stop in the middle of a chunk header: "1" of "1f\r\n"
    first = headers + b"1"
    rest = [b"f\r\n0123456789", b"abcdef\r\n0\r\n\r\n"]

    reference = Connection(SERVER)
    events = receive_and_get(reference, headers + b"1")
    assert type(events[0]) is Request
    assert reference.their_state is SEND_BODY

    conn = restore(reference)
    assert feed(conn, rest) == feed(reference, rest)
    assert conn.states == reference.states


def test_snapshot_mid_chunk_data_and_footer() -> None:
    headers = (
        b"POST / HTTP/1.1\r\nHost: example.com\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n"
    )
    # Mid-chunk-data: chunk of 10 bytes, only 4 delivered
    for first, rest in [
        (b"5\r\nhe", [b"llo\r\n0\r\n\r\n"]),
        # Mid-chunk-footer: the \r\n after a chunk, partially delivered
        (b"5\r\nhello\r", [b"\n0\r\n\r\n"]),
        # Mid-trailer
        (b"0\r\nX-Trail", [b"er: y\r\n\r\n"]),
    ]:
        reference = Connection(SERVER)
        receive_and_get(reference, headers)
        receive_and_get(reference, first)
        conn = restore(reference)
        assert feed(conn, rest) == feed(reference, rest)
        assert conn.states == reference.states


def test_snapshot_mid_content_length_body() -> None:
    headers = (
        b"POST / HTTP/1.1\r\nHost: example.com\r\n"
        b"Content-Length: 10\r\n\r\n"
    )
    reference = Connection(SERVER)
    receive_and_get(reference, headers)
    receive_and_get(reference, b"abc")
    conn = restore(reference)
    assert feed(conn, [b"defg", b"hij"]) == feed(reference, [b"defg", b"hij"])
    assert conn.states == reference.states


def test_snapshot_100_continue() -> None:
    # Server-side: client sent a request with Expect: 100-continue; snapshot
    # while the client is still waiting, then make sure the restored
    # connection still knows about it and completes the exchange.
    reference = Connection(SERVER)
    events = receive_and_get(
        reference,
        b"POST / HTTP/1.1\r\nHost: example.com\r\n"
        b"Expect: 100-continue\r\nContent-Length: 3\r\n\r\n",
    )
    assert type(events[0]) is Request
    assert reference.client_is_waiting_for_100_continue
    assert reference.they_are_waiting_for_100_continue

    conn = restore(reference)
    assert conn.client_is_waiting_for_100_continue
    assert conn.they_are_waiting_for_100_continue

    for c in (conn, reference):
        data = c.send(InformationalResponse(status_code=100, headers=[]))
        assert data is not None
        assert not c.client_is_waiting_for_100_continue
        data = c.send(Response(status_code=200, headers=[("Content-Length", "0")]))
        assert data is not None

    # The request body the client sends after the 100 must parse identically.
    assert feed(conn, [b"abc"]) == feed(reference, [b"abc"])
    assert conn.states == reference.states


def test_snapshot_waiting_for_next_cycle() -> None:
    # Full request/response cycle done, both sides DONE, keep-alive still
    # enabled: snapshot, restore, start_next_cycle, run another cycle.
    server = Connection(SERVER)
    receive_and_get(server, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    server.send(Response(status_code=200, headers=[("Content-Length", "0")]))
    server.send(EndOfMessage())
    assert server.states == {CLIENT: DONE, SERVER: DONE}

    conn = restore(server)
    assert conn.states == {CLIENT: DONE, SERVER: DONE}

    for c in (conn, server):
        c.start_next_cycle()
        assert c.states == {CLIENT: IDLE, SERVER: IDLE}

    # Second request on the same (restored) connection parses identically.
    next_request = b"GET /two HTTP/1.1\r\nHost: example.com\r\n\r\n"
    assert feed(conn, [next_request]) == feed(server, [next_request])
    assert conn.states == server.states


def test_snapshot_client_send_side() -> None:
    # Client in the middle of sending a content-length body: the restored
    # connection must enforce the remaining byte count identically.
    reference = Connection(CLIENT)
    reference.send(
        Request(
            method="POST",
            target="/",
            headers=[("Host", "example.com"), ("Content-Length", "10")],
        )
    )
    reference.send(Data(data=b"abcd"))
    conn = restore(reference)
    assert conn.send(Data(data=b"ef")) == reference.send(Data(data=b"ef"))
    assert conn.send(Data(data=b"ghij")) == reference.send(Data(data=b"ghij"))
    assert conn.send(EndOfMessage()) == reference.send(EndOfMessage())
    assert conn.states == reference.states


def test_snapshot_preserves_max_incomplete_event_size() -> None:
    conn = restore(Connection(SERVER, max_incomplete_event_size=42))
    assert conn._max_incomplete_event_size == 42


def test_snapshot_after_eof() -> None:
    # HTTP/1.0-style response body framed by EOF: snapshot after the close
    # notification but before the buffered data is consumed.
    reference = Connection(CLIENT)
    receive_and_get(
        reference,
        b"HTTP/1.0 200 OK\r\n\r\nhello",
    )
    reference.receive_data(b"")
    conn = restore(reference)
    assert conn.trailing_data == reference.trailing_data
    assert get_all_events(conn) == get_all_events(reference)
    assert conn.states == reference.states


def make_valid_snapshot() -> Dict[str, Any]:
    conn = Connection(SERVER)
    conn.receive_data(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    conn.next_event()
    return json_roundtrip(conn.snapshot())


def test_from_snapshot_rejects_non_dict() -> None:
    with pytest.raises(ValueError, match="must be a dict"):
        Connection.from_snapshot("not a dict")  # type: ignore[arg-type]


def test_from_snapshot_rejects_bad_version() -> None:
    snapshot = make_valid_snapshot()
    for bad_version in (0, 2, -1, "1", None):
        snapshot["version"] = bad_version
        with pytest.raises(ValueError, match="incompatible snapshot version"):
            Connection.from_snapshot(snapshot)


def test_from_snapshot_rejects_unknown_role() -> None:
    snapshot = make_valid_snapshot()
    snapshot["role"] = "MIDDLEMAN"
    with pytest.raises(ValueError, match="unknown role"):
        Connection.from_snapshot(snapshot)


def test_from_snapshot_rejects_unknown_state() -> None:
    snapshot = make_valid_snapshot()
    snapshot["states"]["CLIENT"] = "HALF_OPEN"
    with pytest.raises(ValueError, match="unknown state"):
        Connection.from_snapshot(snapshot)
    snapshot = make_valid_snapshot()
    snapshot["states"] = {"CLIENT": "IDLE"}
    with pytest.raises(ValueError, match="CLIENT and SERVER"):
        Connection.from_snapshot(snapshot)


def test_from_snapshot_rejects_unknown_switch_proposal() -> None:
    snapshot = make_valid_snapshot()
    snapshot["pending_switch_proposals"] = ["_SWITCH_TO_PLAID"]
    with pytest.raises(ValueError, match="unknown pending switch proposal"):
        Connection.from_snapshot(snapshot)


def test_from_snapshot_rejects_invalid_lengths() -> None:
    conn = Connection(SERVER)
    receive_and_get(
        conn,
        b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 10\r\n\r\nabc",
    )
    snapshot = json_roundtrip(conn.snapshot())
    assert snapshot["reader"]["framing"] == "content-length"

    # remaining > length
    bad = json_roundtrip(snapshot)
    bad["reader"]["state"]["remaining"] = 11
    with pytest.raises(ValueError, match="exceeds"):
        Connection.from_snapshot(bad)

    # negative remaining
    bad = json_roundtrip(snapshot)
    bad["reader"]["state"]["remaining"] = -1
    with pytest.raises(ValueError, match=">="):
        Connection.from_snapshot(bad)

    # non-integer length
    bad = json_roundtrip(snapshot)
    bad["reader"]["state"]["length"] = "10"
    with pytest.raises(ValueError, match="must be an int"):
        Connection.from_snapshot(bad)

    # bool is not an int
    bad = json_roundtrip(snapshot)
    bad["reader"]["state"]["remaining"] = True
    with pytest.raises(ValueError, match="must be an int"):
        Connection.from_snapshot(bad)

    # negative writer remaining
    bad = json_roundtrip(snapshot)
    bad["writer"] = {"framing": "content-length", "state": {"remaining": -5}}
    bad["states"]["SERVER"] = "SEND_BODY"
    with pytest.raises(ValueError, match=">="):
        Connection.from_snapshot(bad)


def test_from_snapshot_rejects_bad_chunk_state() -> None:
    conn = Connection(SERVER)
    receive_and_get(
        conn,
        b"POST / HTTP/1.1\r\nHost: example.com\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n5\r\nhe",
    )
    snapshot = json_roundtrip(conn.snapshot())
    assert snapshot["reader"]["framing"] == "chunked"

    # bytes_to_discard that isn't a prefix of \r\n
    bad = json_roundtrip(snapshot)
    bad["reader"]["state"]["bytes_to_discard"] = "eHk="  # b"xy"
    with pytest.raises(ValueError, match="bytes_to_discard"):
        Connection.from_snapshot(bad)

    # corrupt base64
    bad = json_roundtrip(snapshot)
    bad["reader"]["state"]["bytes_to_discard"] = "!!!not-base64!!!"
    with pytest.raises(ValueError, match="base64"):
        Connection.from_snapshot(bad)

    # negative bytes_in_chunk
    bad = json_roundtrip(snapshot)
    bad["reader"]["state"]["bytes_in_chunk"] = -3
    with pytest.raises(ValueError, match=">="):
        Connection.from_snapshot(bad)


def test_from_snapshot_rejects_unknown_framing() -> None:
    conn = Connection(SERVER)
    receive_and_get(
        conn,
        b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\n",
    )
    snapshot = json_roundtrip(conn.snapshot())
    snapshot["reader"]["framing"] = "gzip"
    with pytest.raises(ValueError, match="unknown reader framing"):
        Connection.from_snapshot(snapshot)
    snapshot = json_roundtrip(conn.snapshot())
    snapshot["writer"] = {"framing": "gzip", "state": {}}
    snapshot["states"]["SERVER"] = "SEND_BODY"
    with pytest.raises(ValueError, match="unknown writer framing"):
        Connection.from_snapshot(snapshot)


def test_from_snapshot_rejects_inconsistent_io_entries() -> None:
    # reader entry present although their_state is not SEND_BODY
    snapshot = json_roundtrip(Connection(SERVER).snapshot())
    snapshot["reader"] = {"framing": "chunked", "state": {}}
    with pytest.raises(ValueError, match="not SEND_BODY"):
        Connection.from_snapshot(snapshot)

    # their_state is SEND_BODY but the reader entry is missing
    conn = Connection(SERVER)
    receive_and_get(
        conn,
        b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\n",
    )
    snapshot = json_roundtrip(conn.snapshot())
    snapshot["reader"] = None
    with pytest.raises(ValueError, match="no reader entry"):
        Connection.from_snapshot(snapshot)


def test_from_snapshot_rejects_bad_scalar_fields() -> None:
    snapshot = make_valid_snapshot()
    snapshot["receive_buffer"] = 12345
    with pytest.raises(ValueError, match="base64"):
        Connection.from_snapshot(snapshot)

    snapshot = make_valid_snapshot()
    snapshot["client_is_waiting_for_100_continue"] = "yes"
    with pytest.raises(ValueError, match="must be a bool"):
        Connection.from_snapshot(snapshot)

    snapshot = make_valid_snapshot()
    snapshot["max_incomplete_event_size"] = 0
    with pytest.raises(ValueError, match=">="):
        Connection.from_snapshot(snapshot)
