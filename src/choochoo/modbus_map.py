"""Modbus point map for the enterprise control plane.

The mapping mirrors what you'd see on a real industrial controller's
I/O list: a flat namespace of analog/discrete points, no per-message
schemas. This is part of the realism — defenders monitoring on the
wire will only see register addresses, not field names.

Address space (all unit id 1):

    Holding regs (FC 03/06/16) — operator writes:
        0   power (signed int16)  -100..100  (sign = direction)
        1   light brightness 0..10
        2   command counter (operator increments to issue an "edge")

    Coils (FC 01/05) — operator writes:
        0   emergency stop (write True to trip; outstation clears)

    Input regs (FC 04) — read-only telemetry:
        0   current commanded power 0..100
        1   max power (mirrors protocol.MAX_POWER)

    Discrete inputs (FC 02) — read-only telemetry:
        0   train connected
        1   direction (0 = reverse, 1 = forward)
"""

from __future__ import annotations

from choochoo.protocol import MAX_POWER

UNIT_ID = 1

# Holding-register addresses
HR_POWER = 0
HR_LIGHT = 1
HR_CMD_COUNTER = 2
HR_COUNT = 3

# Coil addresses
CO_ESTOP = 0
CO_COUNT = 1

# Input-register addresses
IR_CURRENT_POWER = 0
IR_MAX_POWER = 1
IR_COUNT = 2

# Discrete-input addresses
DI_CONNECTED = 0
DI_DIRECTION = 1
DI_COUNT = 2


def encode_signed_power(value: int) -> int:
    """Pack -100..100 into a 16-bit unsigned register cell."""
    return value & 0xFFFF


def decode_signed_power(raw: int) -> int:
    """Reverse of encode_signed_power. Treats values >= 0x8000 as negative."""
    return raw - 0x10000 if raw & 0x8000 else raw


def initial_input_registers() -> list[int]:
    regs = [0] * IR_COUNT
    regs[IR_MAX_POWER] = MAX_POWER
    return regs
