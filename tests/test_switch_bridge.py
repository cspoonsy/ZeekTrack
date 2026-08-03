"""Unit tests for SwitchBridge — no broker required.

The bridge's paho client is a MagicMock so we can invoke the on_message
callback directly with synthetic payloads on both the state and the
discovery topics."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest

from choochoo.switch_protocol import (
    SwitchDiscovery,
    SwitchState,
    switch_cmd_topic,
    switch_discovery_topic,
    switch_state_topic,
)
from choochoo.web import SwitchBridge


def _bridge() -> SwitchBridge:
    b = SwitchBridge("localhost", 1883, "sw1")
    b._client = MagicMock()
    return b


def _state_msg(payload: bytes):
    m = MagicMock()
    m.topic = switch_state_topic("sw1")
    m.payload = payload
    return m


def _discovery_msg(payload: bytes):
    m = MagicMock()
    m.topic = switch_discovery_topic("sw1")
    m.payload = payload
    return m


def _drain(loop: asyncio.AbstractEventLoop) -> None:
    loop.call_soon(loop.stop)
    loop.run_forever()


def test_on_state_message_caches_and_fans_out():
    b = _bridge()
    loop = asyncio.new_event_loop()
    try:
        b._loop = loop
        q = b.subscribe()

        state_json = SwitchState(
            switch_id="sw1", position="forward", connected=True
        ).model_dump_json().encode()
        b._on_message(None, None, _state_msg(state_json))

        assert b.state is not None
        assert b.state.position == "forward"
        _drain(loop)
        view = q.get_nowait()
        assert view["position"] == "forward"
        assert view["online"] is None  # discovery not seen yet
    finally:
        loop.close()


def test_on_discovery_message_updates_online_and_fans_out():
    b = _bridge()
    loop = asyncio.new_event_loop()
    try:
        b._loop = loop
        q = b.subscribe()

        disc_json = SwitchDiscovery(
            switch_id="sw1",
            cmd_topic="choochoo/switch/sw1/cmd/+",
            state_topic="choochoo/switch/sw1/state",
            online=True,
        ).model_dump_json().encode()
        b._on_message(None, None, _discovery_msg(disc_json))

        assert b._online is True
        _drain(loop)
        view = q.get_nowait()
        assert view["online"] is True
    finally:
        loop.close()


def test_lwt_offline_beats_stale_state_connected():
    """The exact bug: retained state says connected=true, LWT says offline.
    view() must trust the LWT signal (view.online = False)."""
    b = _bridge()
    b.state = SwitchState(switch_id="sw1", position="forward", connected=True)
    b._online = False  # discovery LWT fired
    view = b.view()
    assert view["connected"] is True   # stale — preserved as-is
    assert view["online"] is False     # authoritative liveness


def test_view_before_any_messages_is_bare():
    b = _bridge()
    assert b.view() == {"switch_id": "sw1", "online": None}


def test_on_bad_state_payload_is_dropped(caplog):
    b = _bridge()
    caplog.set_level("WARNING")
    b._on_message(None, None, _state_msg(b"not json"))
    assert b.state is None
    assert any("bad switch state payload" in r.getMessage() for r in caplog.records)


def test_on_bad_discovery_payload_is_dropped(caplog):
    b = _bridge()
    caplog.set_level("WARNING")
    b._on_message(None, None, _discovery_msg(b"not json"))
    assert b._online is None
    assert any("bad switch discovery payload" in r.getMessage() for r in caplog.records)


def test_publish_writes_to_cmd_throw_topic():
    b = _bridge()
    b.publish("throw", {"action": "throw", "direction": "forward"})
    topic, payload = b._client.publish.call_args.args
    assert topic == switch_cmd_topic("sw1", "throw")
    assert '"direction": "forward"' in payload


def test_subscribe_delivers_cached_view_immediately():
    b = _bridge()
    b.state = SwitchState(switch_id="sw1", position="reverse", connected=True)
    b._online = True
    q = b.subscribe()
    view = q.get_nowait()
    assert view["position"] == "reverse"
    assert view["online"] is True


def test_on_connect_subscribes_to_state_and_discovery():
    b = _bridge()
    fake_client = MagicMock()
    b._on_connect(fake_client, None, None, "Success", None)
    subscribed = [c.args[0] for c in fake_client.subscribe.call_args_list]
    assert switch_state_topic("sw1") in subscribed
    assert switch_discovery_topic("sw1") in subscribed


def test_full_queue_drops_oldest():
    q: asyncio.Queue[dict] = asyncio.Queue(maxsize=2)
    q.put_nowait({"seq": 1})
    q.put_nowait({"seq": 2})
    SwitchBridge._enqueue(q, {"seq": 3})
    assert q.get_nowait()["seq"] == 2
    assert q.get_nowait()["seq"] == 3


_ = pytest  # kept for future async fixtures
