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
import logging
from dataclasses import dataclass

from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusServerContext,
    ModbusSlaveContext,
)
from pymodbus.server import StartAsyncTcpServer

from choochoo.modbus_map import (
    CO_COUNT,
    CO_ESTOP,
    DI_CONNECTED,
    DI_COUNT,
    DI_DIRECTION,
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
from choochoo.train import TrainClient, build_train

log = logging.getLogger(__name__)


@dataclass
class ModbusControllerConfig:
    bind: str = "0.0.0.0"  # noqa: S104 — deliberately LAN-reachable
    port: int = 5020
    train_id: str = "t1"
    train_kind: str = "fake"


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
    ) -> None:
        super().__init__(starting, values)
        self._train = train
        self._is_coil = is_coil
        self._on_command_applied = on_command_applied

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
        self._refresh_telemetry()
        log.info(
            "Modbus/TCP controller listening on %s:%d (unit %d)",
            self.cfg.bind, self.cfg.port, UNIT_ID,
        )
        try:
            asyncio.run(self._serve())
        finally:
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
