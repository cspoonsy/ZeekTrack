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
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
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

    def publish(self, action: str, payload: dict) -> None:
        self._client.publish(cmd_topic(self.train_id, action), json.dumps(payload))

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


def create_app() -> FastAPI:
    protocol = os.environ.get("CHOOCHOO_PROTOCOL", "mqtt").lower()
    host = os.environ.get("CHOOCHOO_BROKER", "localhost")
    train_id = os.environ.get("CHOOCHOO_TRAIN_ID", "t1")

    if protocol == "modbus":
        from choochoo.modbus_bridge import ModbusBridge
        port = int(os.environ.get("CHOOCHOO_MODBUS_PORT", "5020"))
        bridge: MqttBridge | ModbusBridge = ModbusBridge(host, port, train_id)
    else:
        port = int(os.environ.get("CHOOCHOO_BROKER_PORT", "1883"))
        bridge = MqttBridge(host, port, train_id)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        bridge.start()
        try:
            yield
        finally:
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

    @app.get("/", response_class=HTMLResponse)
    async def index() -> HTMLResponse:
        html = (STATIC_DIR / "index.html").read_text()
        html = html.replace("{{MAX_POWER}}", str(MAX_POWER))
        html = html.replace("{{PROTOCOL}}", protocol)
        return HTMLResponse(html)

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.post("/api/motor")
    async def post_motor(cmd: MotorCommand) -> dict:
        bridge.publish("motor", cmd.model_dump())
        return {"ok": True}

    @app.post("/api/stop")
    async def post_stop() -> dict:
        bridge.publish("stop", StopCommand().model_dump())
        return {"ok": True}

    @app.post("/api/light")
    async def post_light(cmd: LightCommand) -> dict:
        bridge.publish("light", cmd.model_dump())
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
                state = await q.get()
                await ws.send_text(state.model_dump_json())
        except WebSocketDisconnect:
            pass
        finally:
            bridge.unsubscribe(q)

    # Referenced so lint doesn't flag these as unused endpoints.
    _ = (post_motor, post_stop, post_light, get_state, ws_state, index)

    return app


app = create_app()


# Re-exported so tests can reach it without env vars.
__all__ = ["app", "create_app", "MqttBridge", "Direction"]
