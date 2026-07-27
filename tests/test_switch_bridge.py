"""Unit tests for SwitchBridge — no broker required.

The bridge's paho client is a MagicMock so we can invoke the on_message
callback directly with synthetic payloads."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest

from choochoo.switch_protocol import SwitchState, switch_cmd_topic
from choochoo.web import SwitchBridge


def _bridge() -> SwitchBridge:
    b = SwitchBridge("localhost", 1883, "sw1")
    b._client = MagicMock()
    return b


def _msg(payload: bytes):
    m = MagicMock()
    m.payload = payload
    return m


def test_on_message_valid_state_caches_and_fans_out():
    b = _bridge()
    loop = asyncio.new_event_loop()
    try:
        b._loop = loop
        q = b.subscribe()  # empty queue, no cached state yet

        state_json = SwitchState(
            switch_id="sw1", position="forward", connected=True
        ).model_dump_json().encode()
        b._on_message(None, None, _msg(state_json))

        assert b.state is not None
        assert b.state.position == "forward"
        # call_soon_threadsafe schedules the enqueue; run one iteration.
        loop.call_soon(loop.stop)
        loop.run_forever()
        got = q.get_nowait()
        assert got.position == "forward"
    finally:
        loop.close()


def test_on_message_bad_json_is_dropped(caplog):
    b = _bridge()
    caplog.set_level("WARNING")
    b._on_message(None, None, _msg(b"not json"))
    assert b.state is None
    assert any("bad switch state payload" in r.getMessage() for r in caplog.records)


def test_publish_writes_to_cmd_throw_topic():
    b = _bridge()
    b.publish("throw", {"action": "throw", "direction": "forward"})
    topic, payload = b._client.publish.call_args.args
    assert topic == switch_cmd_topic("sw1", "throw")
    assert '"direction": "forward"' in payload


def test_subscribe_delivers_cached_state_immediately():
    b = _bridge()
    b.state = SwitchState(switch_id="sw1", position="reverse", connected=True)
    q = b.subscribe()
    got = q.get_nowait()
    assert got.position == "reverse"


def test_full_queue_drops_oldest_state():
    b = _bridge()
    loop = asyncio.new_event_loop()
    try:
        b._loop = loop
        q: asyncio.Queue[SwitchState] = asyncio.Queue(maxsize=2)
        # Fill it to capacity.
        q.put_nowait(SwitchState(switch_id="sw1", position="forward"))
        q.put_nowait(SwitchState(switch_id="sw1", position="reverse"))
        SwitchBridge._enqueue(q, SwitchState(switch_id="sw1", position="unknown"))
        # Oldest ("forward") should be gone; "reverse" is now first.
        assert q.get_nowait().position == "reverse"
        assert q.get_nowait().position == "unknown"
    finally:
        loop.close()


# Coverage note: _on_connect is thin (subscribe + log) and exercised by the
# integration test via TestClient in tests/test_web_switch.py.
_ = pytest  # keep the import for future async fixtures
