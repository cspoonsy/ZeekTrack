"""Web API tests. The bridge's MQTT client is replaced with a mock so the
tests don't need a broker running."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from choochoo.web import create_app


@pytest.fixture
def client():
    app = create_app()
    app.state.bridge._client = MagicMock()
    # The switch bridge is always created; mock its client too so no broker
    # is needed for train-only tests.
    app.state.switch_bridge._client = MagicMock()
    with TestClient(app) as c:
        yield c, app.state.bridge


def test_motor_endpoint_publishes(client):
    c, bridge = client
    r = c.post("/api/motor", json={"direction": "forward", "power": 40})
    assert r.status_code == 200
    topic, payload = bridge._client.publish.call_args.args
    assert topic.endswith("/cmd/motor")
    assert '"direction": "forward"' in payload
    assert '"power": 40' in payload


def test_motor_endpoint_rejects_bad_power(client):
    c, _ = client
    r = c.post("/api/motor", json={"direction": "forward", "power": 999})
    assert r.status_code == 422


def test_stop_endpoint_publishes(client):
    c, bridge = client
    r = c.post("/api/stop")
    assert r.status_code == 200
    topic, _ = bridge._client.publish.call_args.args
    assert topic.endswith("/cmd/stop")


def test_index_serves_html(client):
    c, _ = client
    r = c.get("/")
    assert r.status_code == 200
    assert "ChooChoo" in r.text
    # Switch panel is always shipped regardless of train protocol.
    assert 'id="switch-position-pill"' in r.text
    assert "/static/switch.js" in r.text
