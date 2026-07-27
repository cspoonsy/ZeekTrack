"""Modbus/TCP controller: the enterprise-mode equivalent of controller.py.

Runs a Modbus TCP server. Writes to specific holding registers / coils get
translated into TrainClient calls; train state is mirrored back into input
registers and discrete inputs that any Modbus master can poll.

No auth, no TLS, plaintext on TCP/5020 — same deliberate baseline posture as
the MQTT mode. Standard Modbus uses 502 but that's privileged on Linux; we
use 5020 by default, configurable via CHOOCHOO_MODBUS_PORT.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from collections.abc import Callable
from dataclasses import dataclass

import paho.mqtt.client as mqtt
from pydantic import ValidationError
from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusServerContext,
    ModbusSlaveContext,
)
from pymodbus.server import StartAsyncTcpServer

from choochoo import mqtt_auth
from choochoo.modbus_map import (
    CO_COUNT,
    CO_ESTOP,
    CO_SWITCH_TO_CURVE,
    CO_SWITCH_TO_STRAIGHT,
    DI_CONNECTED,
    DI_COUNT,
    DI_DIRECTION,
    DI_SWITCH_ONLINE,
    DI_SWITCH_POSITION_CURVE,
    DI_SWITCH_POSITION_STRAIGHT,
    HR_CMD_COUNTER,
    HR_COUNT,
    HR_LIGHT,
    HR_POWER,
    IR_CURRENT_POWER,
    IR_MAX_POWER,
    UNIT_ID,
    decode_signed_power,
    initial_input_registers,
)
from choochoo.protocol import MAX_POWER, Direction
from choochoo.switch_protocol import (
    UI_CURVE_WIRE_DIRECTION,
    UI_STRAIGHT_WIRE_DIRECTION,
    SwitchDiscovery,
    SwitchState,
    ThrowCommand,
    switch_cmd_topic,
    switch_discovery_topic,
    switch_state_topic,
)
from choochoo.train import TrainClient, build_train

log = logging.getLogger(__name__)


@dataclass
class ModbusControllerConfig:
    bind: str = "0.0.0.0"  # noqa: S104 — deliberately LAN-reachable
    port: int = 5020
    train_id: str = "t1"
    train_kind: str = "fake"


class SwitchMirror:
    """MQTT-side of the switch, mirrored into Modbus DIs.

    Subscribes to the switch's `state` and `discovery` topics on the switch
    broker; on every message, invokes `on_state_change(position, online)`
    so the outstation can update its DIs. `throw()` publishes to the
    `cmd/throw` topic so the outstation can turn a coil write into a
    real switch throw without needing BLE itself.

    Structurally a sibling of web.SwitchBridge — same LWT-aware discovery
    handling, different output surface (callback instead of asyncio queue
    fan-out) because pymodbus's data blocks are not asyncio-native."""

    def __init__(
        self,
        host: str,
        port: int,
        switch_id: str,
        on_state_change: Callable[[str, bool | None], None],
    ) -> None:
        self.host = host
        self.port = port
        self.switch_id = switch_id
        self._on_state_change = on_state_change
        self._position: str = "unknown"
        self._online: bool | None = None
        self._client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=f"choochoo-modbus-switch-{switch_id}",
        )
        mqtt_auth.configure(self._client)
        self._client.on_connect = self._on_connect
        self._client.on_message = self._on_message

    def start(self) -> None:
        self._client.connect_async(self.host, self.port, keepalive=30)
        self._client.loop_start()

    def stop(self) -> None:
        self._client.loop_stop()
        self._client.disconnect()

    def throw(self, direction: Direction) -> None:
        payload = ThrowCommand(direction=direction).model_dump()
        self._client.publish(
            switch_cmd_topic(self.switch_id, "throw"),
            json.dumps(payload),
        )

    def _on_connect(self, client, _userdata, _flags, reason_code, _props) -> None:
        state = switch_state_topic(self.switch_id)
        discovery = switch_discovery_topic(self.switch_id)
        log.info(
            "modbus switch-mirror connected rc=%s, subscribing to %s and %s",
            reason_code, state, discovery,
        )
        client.subscribe(state)
        client.subscribe(discovery)

    def _on_message(self, _client, _userdata, msg: mqtt.MQTTMessage) -> None:
        state_topic = switch_state_topic(self.switch_id)
        discovery_topic = switch_discovery_topic(self.switch_id)
        if msg.topic == state_topic:
            try:
                self._position = SwitchState.model_validate_json(msg.payload).position
            except ValidationError as e:
                log.warning("bad switch state payload: %s", e)
                return
        elif msg.topic == discovery_topic:
            try:
                self._online = SwitchDiscovery.model_validate_json(msg.payload).online
            except ValidationError as e:
                log.warning("bad switch discovery payload: %s", e)
                return
        else:
            return
        self._on_state_change(self._position, self._online)


class _TrainBlock(ModbusSequentialDataBlock):
    """Holding-register / coil block that drives the train when written.

    pymodbus calls `setValues(address, values)` on the block whenever the
    master issues a write. We let the parent class store the new value,
    then translate the side effect into a TrainClient action.

    pymodbus uses 1-based addressing in `ModbusSequentialDataBlock`: passing
    `address=1` and the start of the data array as our point 0 means the
    *master* writing to address 0 on the wire ends up at our index 0, which
    is what we want. (The block stores values as an offset from its base.)
    """

    def __init__(
        self,
        starting: int,
        values,
        *,
        train: TrainClient,
        is_coil: bool,
        on_command_applied,
        switch_mirror: SwitchMirror | None = None,
    ) -> None:
        super().__init__(starting, values)
        self._train = train
        self._is_coil = is_coil
        self._on_command_applied = on_command_applied
        # None in existing train-only tests; wired to a real mirror by
        # ModbusController in production.
        self._switch_mirror = switch_mirror

    def setValues(self, address: int, values) -> None:  # noqa: N802
        super().setValues(address, values)
        # pymodbus subtracts our base (1) when storing, but on this hook the
        # `address` we receive is the *raw* address from the master (0-based
        # on the wire). Treat it as such.
        if self._is_coil:
            self._handle_coil_writes(address, values)
        else:
            self._handle_holding_writes(address, values)
        self._on_command_applied()

    def _handle_coil_writes(self, address: int, values) -> None:
        for offset, val in enumerate(values):
            addr = address + offset
            if addr == CO_ESTOP and bool(val):
                log.info("ESTOP via coil write")
                self._train.stop()
                # Latch back to 0 — emergency stop is edge-triggered.
                super().setValues(CO_ESTOP, [False])
            elif addr == CO_SWITCH_TO_STRAIGHT and bool(val):
                if self._switch_mirror is not None:
                    log.info("switch throw to straight via coil write")
                    self._switch_mirror.throw(UI_STRAIGHT_WIRE_DIRECTION)
                # Latch back regardless — the coil is edge-triggered even
                # when no mirror is wired (the write is still valid Modbus).
                super().setValues(CO_SWITCH_TO_STRAIGHT, [False])
            elif addr == CO_SWITCH_TO_CURVE and bool(val):
                if self._switch_mirror is not None:
                    log.info("switch throw to curve via coil write")
                    self._switch_mirror.throw(UI_CURVE_WIRE_DIRECTION)
                super().setValues(CO_SWITCH_TO_CURVE, [False])

    def _handle_holding_writes(self, address: int, values) -> None:
        for offset, raw in enumerate(values):
            addr = address + offset
            if addr == HR_POWER:
                self._apply_power(decode_signed_power(int(raw)))
            elif addr == HR_LIGHT:
                self._apply_light(int(raw))
            elif addr == HR_CMD_COUNTER:
                # Operator-incremented edge marker. No side effect; useful
                # to a master that wants to make every command unique on
                # the wire (defeats coalescing in some monitors).
                pass

    def _apply_power(self, signed: int) -> None:
        signed = max(-100, min(100, signed))
        if signed == 0:
            self._train.stop()
            return
        direction = Direction.FORWARD if signed > 0 else Direction.REVERSE
        magnitude = min(abs(signed), MAX_POWER)
        if magnitude != abs(signed):
            log.warning("clamping |power| %d -> %d (MAX_POWER)", abs(signed), magnitude)
        self._train.motor(direction, magnitude)

    def _apply_light(self, brightness: int) -> None:
        brightness = max(0, min(10, brightness))
        self._train.light(brightness)


class ModbusController:
    def __init__(self, cfg: ModbusControllerConfig) -> None:
        self.cfg = cfg
        self.train: TrainClient = build_train(cfg.train_kind, cfg.train_id)

        # The outstation also mediates the track switch. The switch itself
        # is driven by a separate MQTT-speaking controller (BLE-owning);
        # the mirror gives us a fire-and-forget bridge into that world so
        # a Modbus master doesn't need to know the switch is MQTT.
        switch_host = os.environ.get("CHOOCHOO_SWITCH_BROKER", "localhost")
        switch_port = int(os.environ.get("CHOOCHOO_SWITCH_BROKER_PORT", "1883"))
        switch_id = os.environ.get("CHOOCHOO_SWITCH_ID", "sw1")
        self._switch_mirror = SwitchMirror(
            switch_host, switch_port, switch_id,
            on_state_change=self._on_switch_state,
        )

        # `address=0` means the data block starts at point 0; the master sees
        # 0-based addresses (FC03 read of address 0 returns our index 0).
        self._holding = _TrainBlock(
            0, [0] * HR_COUNT,
            train=self.train, is_coil=False,
            on_command_applied=self._refresh_telemetry,
        )
        self._coils = _TrainBlock(
            0, [False] * CO_COUNT,
            train=self.train, is_coil=True,
            on_command_applied=self._refresh_telemetry,
            switch_mirror=self._switch_mirror,
        )
        self._input_regs = ModbusSequentialDataBlock(0, initial_input_registers())
        self._discrete = ModbusSequentialDataBlock(0, [False] * DI_COUNT)

        slave = ModbusSlaveContext(
            di=self._discrete,
            co=self._coils,
            hr=self._holding,
            ir=self._input_regs,
            zero_mode=True,  # use 0-based addressing on the wire
        )
        self._context = ModbusServerContext(slaves={UNIT_ID: slave}, single=False)

    def run(self) -> None:
        self.train.connect()
        self._switch_mirror.start()
        self._refresh_telemetry()
        log.info(
            "Modbus/TCP controller listening on %s:%d (unit %d)",
            self.cfg.bind, self.cfg.port, UNIT_ID,
        )
        try:
            asyncio.run(self._serve())
        finally:
            self._switch_mirror.stop()
            self.train.stop()
            self.train.disconnect()

    async def _serve(self) -> None:
        await StartAsyncTcpServer(
            context=self._context,
            address=(self.cfg.bind, self.cfg.port),
        )

    def _refresh_telemetry(self) -> None:
        state = self.train.state()
        self._input_regs.setValues(IR_CURRENT_POWER, [state.power])
        self._input_regs.setValues(IR_MAX_POWER, [MAX_POWER])
        self._discrete.setValues(DI_CONNECTED, [bool(state.connected)])
        self._discrete.setValues(
            DI_DIRECTION,
            [state.direction is Direction.FORWARD],
        )

    def _on_switch_state(self, position: str, online: bool | None) -> None:
        """Called by the SwitchMirror on every state/discovery message.

        `position` is the string from `SwitchState.position` — `"forward"`,
        `"reverse"`, or `"unknown"`. `online` is None until the discovery
        beacon has been seen; we treat that as offline for safety.
        """
        self._discrete.setValues(
            DI_SWITCH_POSITION_STRAIGHT,
            [position == UI_STRAIGHT_WIRE_DIRECTION.value],
        )
        self._discrete.setValues(
            DI_SWITCH_POSITION_CURVE,
            [position == UI_CURVE_WIRE_DIRECTION.value],
        )
        self._discrete.setValues(DI_SWITCH_ONLINE, [bool(online)])
