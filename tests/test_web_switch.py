"""Web endpoint tests for the switch panel — bridges are mocked so no
broker is needed."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from choochoo.switch_protocol import SwitchState, switch_cmd_topic
from choochoo.web import create_app


@pytest.fixture
def client():
    app = create_app()
    # Prevent both bridges' paho clients from touching the network.
    app.state.bridge._client = MagicMock()
    app.state.switch_bridge._client = MagicMock()
    with TestClient(app) as c:
        yield c, app.state.switch_bridge


def test_switch_state_endpoint_without_cache_returns_bare(client):
    c, _ = client
    r = c.get("/api/switch/state")
    assert r.status_code == 200
    assert r.json() == {"switch_id": "sw1"}


def test_switch_state_endpoint_returns_cached_state(client):
    c, bridge = client
    bridge.state = SwitchState(
        switch_id="sw1", position="forward", connected=True
    )
    r = c.get("/api/switch/state")
    assert r.status_code == 200
    body = r.json()
    assert body["position"] == "forward"
    assert body["connected"] is True


def test_switch_throw_publishes(client):
    c, bridge = client
    r = c.post("/api/switch/throw", json={"action": "throw", "direction": "forward"})
    assert r.status_code == 200
    assert r.json() == {"ok": True}
    topic, payload = bridge._client.publish.call_args.args
    assert topic == switch_cmd_topic("sw1", "throw")
    assert '"direction": "forward"' in payload


def test_switch_throw_rejects_bad_direction(client):
    c, bridge = client
    r = c.post("/api/switch/throw", json={"action": "throw", "direction": "sideways"})
    assert r.status_code == 422
    bridge._client.publish.assert_not_called()
