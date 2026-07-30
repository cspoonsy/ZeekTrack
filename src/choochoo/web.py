"""FastAPI web UI.

The web app is intentionally just another MQTT client: it publishes command
messages to the broker and subscribes to the retained state topic. It never
talks to the train directly. That means a browser user and a mosquitto_pub
attacker look identical on the wire — exactly what we want for the exercise.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager, suppress
from pathlib import Path

import paho.mqtt.client as mqtt
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError

from choochoo import mqtt_auth
from choochoo.protocol import (
    MAX_POWER,
    Direction,
    LightCommand,
    MotorCommand,
    StopCommand,
    TrainState,
    cmd_topic,
    state_topic,
)
from choochoo.switch_protocol import (
    SwitchDiscovery,
    SwitchState,
    ThrowCommand,
    switch_cmd_topic,
    switch_discovery_topic,
    switch_state_topic,
)

log = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).parent / "static"


class MqttBridge:
    """Keeps a paho client connected and fans the retained state topic out
    to any number of attached WebSocket subscribers."""

    def __init__(self, host: str, port: int, train_id: str) -> None:
        self.host = host
        self.port = port
        self.train_id = train_id
        self.state: TrainState | None = None
        self._subscribers: set[asyncio.Queue[TrainState]] = set()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=f"choochoo-web-{train_id}",
        )
        mqtt_auth.configure(self._client)
        self._client.on_connect = self._on_connect
        self._client.on_message = self._on_message

    def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._client.connect_async(self.host, self.port, keepalive=30)
        self._client.loop_start()

    def stop(self) -> None:
        self._client.loop_stop()
        self._client.disconnect()

    def publish(self, action: str, payload: dict) -> bool:
        if not self._client.is_connected():
            return False
        self._client.publish(cmd_topic(self.train_id, action), json.dumps(payload))
        return True

    def subscribe(self) -> asyncio.Queue[TrainState]:
        q: asyncio.Queue[TrainState] = asyncio.Queue(maxsize=16)
        self._subscribers.add(q)
        if self.state is not None:
            q.put_nowait(self.state)
        return q

    def unsubscribe(self, q: asyncio.Queue[TrainState]) -> None:
        self._subscribers.discard(q)

    def _on_connect(self, client, _userdata, _flags, reason_code, _props) -> None:
        topic = state_topic(self.train_id)
        log.info("web mqtt connected rc=%s, subscribing to %s", reason_code, topic)
        client.subscribe(topic)

    def _on_message(self, _client, _userdata, msg: mqtt.MQTTMessage) -> None:
        try:
            state = TrainState.model_validate_json(msg.payload)
        except ValidationError as e:
            log.warning("bad state payload: %s", e)
            return
        self.state = state
        if self._loop is None:
            return
        for q in list(self._subscribers):
            self._loop.call_soon_threadsafe(self._enqueue, q, state)

    @staticmethod
    def _enqueue(q: asyncio.Queue[TrainState], state: TrainState) -> None:
        if q.full():
            # Drop the oldest — we only care about current state.
            with suppress(asyncio.QueueEmpty):
                q.get_nowait()
        q.put_nowait(state)


class SwitchBridge:
    """MQTT bridge for the track switch. Structurally mirrors MqttBridge but
    scoped to switch topics. Independent paho client so a switch-broker
    glitch does not stall the train UI.

    Subscribes to BOTH the retained `state` topic (controller-published
    telemetry) AND the retained `discovery` topic (which the controller
    marks online=true on connect and its LWT flips to online=false when
    the controller drops). The websocket view combines the two so the UI
    can reflect controller liveness — `SwitchState.connected` is a
    payload field the controller writes about its own BLE link and stays
    stale in retention when the controller dies uncleanly."""

    def __init__(self, host: str, port: int, switch_id: str, client_suffix: str = "") -> None:
        self.host = host
        self.port = port
        self.switch_id = switch_id
        self.state: SwitchState | None = None
        self._online: bool | None = None
        self._subscribers: set[asyncio.Queue[dict]] = set()
        self._loop: asyncio.AbstractEventLoop | None = None
        suffix = f"-{client_suffix}" if client_suffix else ""
        self._client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=f"choochoo-web-switch-{switch_id}{suffix}",
        )
        mqtt_auth.configure(self._client)
        self._client.on_connect = self._on_connect
        self._client.on_message = self._on_message

    def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._client.connect_async(self.host, self.port, keepalive=30)
        self._client.loop_start()

    def stop(self) -> None:
        self._client.loop_stop()
        self._client.disconnect()

    def publish(self, action: str, payload: dict) -> bool:
        if not self._client.is_connected():
            return False
        self._client.publish(switch_cmd_topic(self.switch_id, action), json.dumps(payload))
        return True

    def view(self) -> dict:
        """Combined view for REST/WebSocket consumers.

        - `online`: True iff the controller's retained discovery beacon
          says online=true. False after LWT fires (controller dead).
          None until the first discovery message arrives.
        - Remaining fields come from the latest `state` topic message.
          Falls back to a bare `{"switch_id": ...}` if we haven't seen one."""
        base: dict = (
            self.state.model_dump()
            if self.state is not None
            else {"switch_id": self.switch_id}
        )
        base["online"] = self._online
        return base

    def subscribe(self) -> asyncio.Queue[dict]:
        q: asyncio.Queue[dict] = asyncio.Queue(maxsize=16)
        self._subscribers.add(q)
        if self.state is not None or self._online is not None:
            q.put_nowait(self.view())
        return q

    def unsubscribe(self, q: asyncio.Queue[dict]) -> None:
        self._subscribers.discard(q)

    def _on_connect(self, client, _userdata, _flags, reason_code, _props) -> None:
        state = switch_state_topic(self.switch_id)
        discovery = switch_discovery_topic(self.switch_id)
        log.info(
            "web switch mqtt connected rc=%s, subscribing to %s and %s",
            reason_code, state, discovery,
        )
        client.subscribe(state)
        client.subscribe(discovery)

    def _on_message(self, _client, _userdata, msg: mqtt.MQTTMessage) -> None:
        state_t = switch_state_topic(self.switch_id)
        discovery_t = switch_discovery_topic(self.switch_id)
        if msg.topic == state_t:
            try:
                self.state = SwitchState.model_validate_json(msg.payload)
            except ValidationError as e:
                log.warning("bad switch state payload: %s", e)
                return
        elif msg.topic == discovery_t:
            try:
                self._online = SwitchDiscovery.model_validate_json(msg.payload).online
            except ValidationError as e:
                log.warning("bad switch discovery payload: %s", e)
                return
        else:
            return
        if self._loop is None:
            return
        view = self.view()
        for q in list(self._subscribers):
            self._loop.call_soon_threadsafe(self._enqueue, q, view)

    @staticmethod
    def _enqueue(q: asyncio.Queue[dict], view: dict) -> None:
        if q.full():
            with suppress(asyncio.QueueEmpty):
                q.get_nowait()
        q.put_nowait(view)


def create_app() -> FastAPI:
    protocol = os.environ.get("CHOOCHOO_PROTOCOL", "mqtt").lower()
    host = os.environ.get("CHOOCHOO_BROKER", "localhost")
    train_id = os.environ.get("CHOOCHOO_TRAIN_ID", "t1")
    switch_id = os.environ.get("CHOOCHOO_SWITCH_ID", "sw1")
    mqtt_port = int(os.environ.get("CHOOCHOO_BROKER_PORT", "1883"))

    if protocol == "modbus":
        from choochoo.modbus_bridge import ModbusBridge
        modbus_port = int(os.environ.get("CHOOCHOO_MODBUS_PORT", "5020"))
        bridge: MqttBridge | ModbusBridge = ModbusBridge(host, modbus_port, train_id)
    else:
        bridge = MqttBridge(host, mqtt_port, train_id)

    # Switch is MQTT-only and always present regardless of the train protocol.
    # It can point at a different broker than the train (relevant when the
    # train is Modbus and CHOOCHOO_BROKER is the outstation host).
    switch_host = os.environ.get("CHOOCHOO_SWITCH_BROKER", host)
    switch_port = int(os.environ.get("CHOOCHOO_SWITCH_BROKER_PORT", mqtt_port))
    switch_bridge = SwitchBridge(switch_host, switch_port, switch_id, client_suffix=protocol)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        bridge.start()
        switch_bridge.start()
        try:
            yield
        finally:
            switch_bridge.stop()
            bridge.stop()

    app = FastAPI(lifespan=lifespan, title="ChooChoo")
    # Wide-open CORS — any origin can drive the train. Real attack value:
    # an attacker who can lure a legit user's browser to any other site
    # (or who controls a printer / dev tool with an exposed page on the LAN)
    # can issue motor commands directly. CSRF without same-origin protection.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.state.bridge = bridge
    app.state.train_id = train_id
    app.state.switch_bridge = switch_bridge
    app.state.switch_id = switch_id

    @app.get("/", response_class=HTMLResponse)
    async def index() -> HTMLResponse:
        html = (STATIC_DIR / "index.html").read_text()
        html = html.replace("{{MAX_POWER}}", str(MAX_POWER))
        html = html.replace("{{PROTOCOL}}", protocol)
        return HTMLResponse(html)

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.post("/api/motor")
    async def post_motor(cmd: MotorCommand) -> dict:
        if not bridge.publish("motor", cmd.model_dump()):
            raise HTTPException(503, "bridge not connected")
        return {"ok": True}

    @app.post("/api/stop")
    async def post_stop() -> dict:
        if not bridge.publish("stop", StopCommand().model_dump()):
            raise HTTPException(503, "bridge not connected")
        return {"ok": True}

    @app.post("/api/light")
    async def post_light(cmd: LightCommand) -> dict:
        if not bridge.publish("light", cmd.model_dump()):
            raise HTTPException(503, "bridge not connected")
        return {"ok": True}

    @app.get("/api/state")
    async def get_state() -> dict:
        return bridge.state.model_dump() if bridge.state else {"train_id": train_id}

    @app.websocket("/ws/state")
    async def ws_state(ws: WebSocket) -> None:
        await ws.accept()
        q = bridge.subscribe()
        try:
            while True:
                try:
                    state = await asyncio.wait_for(q.get(), timeout=15.0)
                    await ws.send_text(state.model_dump_json())
                except asyncio.TimeoutError:
                    # No state update in 15s — send cached state to keep the
                    # connection alive and the UI current.
                    if bridge.state is not None:
                        await ws.send_text(bridge.state.model_dump_json())
                    else:
                        await ws.send_text("{}")
        except WebSocketDisconnect:
            pass
        finally:
            bridge.unsubscribe(q)

    @app.get("/api/switch/state")
    async def get_switch_state() -> dict:
        return switch_bridge.view()

    @app.post("/api/switch/throw")
    async def post_switch_throw(cmd: ThrowCommand) -> dict:
        if not switch_bridge.publish("throw", cmd.model_dump()):
            raise HTTPException(503, "bridge not connected")
        return {"ok": True}

    @app.websocket("/ws/switch/state")
    async def ws_switch_state(ws: WebSocket) -> None:
        await ws.accept()
        q = switch_bridge.subscribe()
        try:
            while True:
                try:
                    view = await asyncio.wait_for(q.get(), timeout=15.0)
                except asyncio.TimeoutError:
                    view = switch_bridge.view()
                await ws.send_json(view)
        except WebSocketDisconnect:
            pass
        finally:
            switch_bridge.unsubscribe(q)

    # Referenced so lint doesn't flag these as unused endpoints.
    _ = (
        post_motor, post_stop, post_light, get_state, ws_state, index,
        get_switch_state, post_switch_throw, ws_switch_state,
    )

    return app


app = create_app()


# Re-exported so tests can reach it without env vars.
__all__ = ["app", "create_app", "MqttBridge", "SwitchBridge", "Direction"]
