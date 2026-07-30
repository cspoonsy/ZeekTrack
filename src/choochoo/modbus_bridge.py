"""Modbus master used by the web UI in enterprise mode.

Polls the outstation at a fixed cadence and exposes the same
TrainState shape that the MQTT bridge does, so the FastAPI layer
above doesn't have to care which protocol is in play.

Connection is async (pymodbus AsyncModbusTcpClient) but the public
API is sync — internal asyncio loop runs on a daemon thread.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any

from pymodbus.client import AsyncModbusTcpClient

from choochoo.modbus_map import (
    CO_ESTOP,
    DI_CONNECTED,
    DI_COUNT,
    DI_DIRECTION,
    HR_LIGHT,
    HR_POWER,
    IR_COUNT,
    IR_CURRENT_POWER,
    IR_MAX_POWER,
    UNIT_ID,
    encode_signed_power,
)
from choochoo.protocol import Direction, TrainState

log = logging.getLogger(__name__)

POLL_INTERVAL_S = 0.25


class ModbusBridge:
    """Mirrors `MqttBridge`'s public surface so `web.py` can swap between them."""

    def __init__(self, host: str, port: int, train_id: str) -> None:
        self.host = host
        self.port = port
        self.train_id = train_id
        self.state: TrainState | None = None

        self._subscribers: set[asyncio.Queue[TrainState]] = set()
        self._loop: asyncio.AbstractEventLoop | None = None  # FastAPI's loop
        self._cmd_counter = 0

        self._worker_loop: asyncio.AbstractEventLoop | None = None
        self._worker_thread: threading.Thread | None = None
        self._client: AsyncModbusTcpClient | None = None
        self._stop_event: asyncio.Event | None = None

    # --- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._worker_thread = threading.Thread(
            target=self._run_worker, daemon=True, name="modbus-bridge",
        )
        self._worker_thread.start()

    def stop(self) -> None:
        if self._worker_loop is not None and self._stop_event is not None:
            self._worker_loop.call_soon_threadsafe(self._stop_event.set)
        if self._worker_thread is not None:
            self._worker_thread.join(timeout=2.0)

    def _run_worker(self) -> None:
        self._worker_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._worker_loop)
        self._stop_event = asyncio.Event()
        try:
            self._worker_loop.run_until_complete(self._main_with_retry())
        finally:
            self._worker_loop.close()

    async def _main_with_retry(self) -> None:
        delay = 1.0
        while not self._stop_event.is_set():
            try:
                await self._main()
                break
            except Exception:
                log.warning("modbus bridge connect failed, retrying in %.1fs", delay)
                await asyncio.sleep(delay)
                delay = min(delay * 2, 30.0)

    async def _main(self) -> None:
        self._client = AsyncModbusTcpClient(self.host, port=self.port)
        await self._client.connect()
        log.info("modbus bridge connected to %s:%d", self.host, self.port)
        try:
            while not self._stop_event.is_set():
                try:
                    await self._poll_once()
                except Exception:  # noqa: BLE001 — bridge stays up across blips
                    log.exception("poll failed")
                await asyncio.sleep(POLL_INTERVAL_S)
        finally:
            self._client.close()

    async def _poll_once(self) -> None:
        ir = await self._client.read_input_registers(0, count=IR_COUNT, slave=UNIT_ID)
        di = await self._client.read_discrete_inputs(0, count=DI_COUNT, slave=UNIT_ID)
        if ir.isError() or di.isError():
            return
        power = int(ir.registers[IR_CURRENT_POWER])
        max_power = int(ir.registers[IR_MAX_POWER])
        connected = bool(di.bits[DI_CONNECTED])
        direction = Direction.FORWARD if di.bits[DI_DIRECTION] else Direction.REVERSE

        new_state = TrainState(
            train_id=self.train_id,
            direction=direction,
            power=power,
            connected=connected,
        )
        # Stash max_power so the FastAPI handler can include it if needed.
        new_state_dict = new_state.model_dump()
        new_state_dict["max_power"] = max_power

        self.state = new_state
        self._fan_out(new_state)

    # --- writes ------------------------------------------------------------

    def publish(self, action: str, payload: dict[str, Any]) -> None:
        """Translate the web UI's "publish a command" call into Modbus writes."""
        if self._worker_loop is None or self._client is None:
            log.warning("modbus bridge not yet started; dropping %s", action)
            return
        coro = self._publish_async(action, payload)
        asyncio.run_coroutine_threadsafe(coro, self._worker_loop)

    async def _publish_async(self, action: str, payload: dict[str, Any]) -> None:
        self._cmd_counter = (self._cmd_counter + 1) & 0xFFFF
        try:
            if action == "motor":
                direction = payload.get("direction", "forward")
                magnitude = int(payload.get("power", 0))
                signed = magnitude if direction == "forward" else -magnitude
                await self._client.write_registers(
                    HR_POWER,
                    [encode_signed_power(signed), 0, self._cmd_counter],
                    slave=UNIT_ID,
                )
            elif action == "stop":
                await self._client.write_coil(CO_ESTOP, True, slave=UNIT_ID)
            elif action == "light":
                brightness = int(payload.get("brightness", 0))
                await self._client.write_register(HR_LIGHT, brightness, slave=UNIT_ID)
            else:
                log.warning("unknown action: %s", action)
        except Exception:  # noqa: BLE001
            log.exception("modbus write failed")

    # --- state fan-out (mirrors MqttBridge) --------------------------------

    def subscribe(self) -> asyncio.Queue[TrainState]:
        q: asyncio.Queue[TrainState] = asyncio.Queue(maxsize=16)
        self._subscribers.add(q)
        if self.state is not None:
            q.put_nowait(self.state)
        return q

    def unsubscribe(self, q: asyncio.Queue[TrainState]) -> None:
        self._subscribers.discard(q)

    def _fan_out(self, state: TrainState) -> None:
        if self._loop is None:
            return
        for q in list(self._subscribers):
            self._loop.call_soon_threadsafe(self._enqueue, q, state)

    @staticmethod
    def _enqueue(q: asyncio.Queue[TrainState], state: TrainState) -> None:
        from contextlib import suppress

        if q.full():
            with suppress(asyncio.QueueEmpty):
                q.get_nowait()
        q.put_nowait(state)
