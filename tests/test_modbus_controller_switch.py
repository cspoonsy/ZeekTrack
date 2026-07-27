"""Tests for the Modbus outstation's switch surface.

The SwitchMirror is mocked so no broker is needed. We verify:
- coil writes translate to mirror.throw() calls in the right direction,
- coils latch back to 0 immediately (edge-triggered),
- the DI callback maps position + online state to the three switch DIs.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from choochoo.modbus_controller import ModbusController, ModbusControllerConfig
from choochoo.modbus_map import (
    CO_SWITCH_TO_CURVE,
    CO_SWITCH_TO_STRAIGHT,
    DI_SWITCH_ONLINE,
    DI_SWITCH_POSITION_CURVE,
    DI_SWITCH_POSITION_STRAIGHT,
)
from choochoo.protocol import Direction


@pytest.fixture
def ctrl():
    """Build a ModbusController with a mocked SwitchMirror. FakeTrain is
    used for the train side; nothing hits BLE or a broker."""
    c = ModbusController(
        ModbusControllerConfig(train_id="t1", train_kind="fake")
    )
    mirror = MagicMock()
    c._switch_mirror = mirror
    # The coil block was constructed with the real (unstarted) mirror; swap
    # the reference the block holds so throws go through the mock.
    c._coils._switch_mirror = mirror
    return c, mirror


# --- Coil-write behavior ---------------------------------------------------


def test_coil_write_straight_calls_mirror_forward(ctrl):
    c, mirror = ctrl
    c._coils.setValues(CO_SWITCH_TO_STRAIGHT, [True])
    mirror.throw.assert_called_once_with(Direction.FORWARD)
    # Coil latched back to False.
    assert c._coils.getValues(CO_SWITCH_TO_STRAIGHT, 1) == [False]


def test_coil_write_curve_calls_mirror_reverse(ctrl):
    c, mirror = ctrl
    c._coils.setValues(CO_SWITCH_TO_CURVE, [True])
    mirror.throw.assert_called_once_with(Direction.REVERSE)
    assert c._coils.getValues(CO_SWITCH_TO_CURVE, 1) == [False]


def test_coil_write_false_is_noop(ctrl):
    c, mirror = ctrl
    c._coils.setValues(CO_SWITCH_TO_STRAIGHT, [False])
    c._coils.setValues(CO_SWITCH_TO_CURVE, [False])
    mirror.throw.assert_not_called()


def test_switch_coil_latches_even_when_mirror_missing():
    """Belt-and-braces: if a coil block is ever constructed without a
    mirror (e.g. in a train-only test rig), the coil must still latch
    back to False so a Modbus master doesn't see a stale True."""
    c = ModbusController(
        ModbusControllerConfig(train_id="t1", train_kind="fake")
    )
    c._coils._switch_mirror = None
    c._coils.setValues(CO_SWITCH_TO_STRAIGHT, [True])
    assert c._coils.getValues(CO_SWITCH_TO_STRAIGHT, 1) == [False]


# --- DI mirroring ----------------------------------------------------------


def _dis(c) -> tuple[bool, bool, bool]:
    return (
        c._discrete.getValues(DI_SWITCH_POSITION_STRAIGHT, 1)[0],
        c._discrete.getValues(DI_SWITCH_POSITION_CURVE, 1)[0],
        c._discrete.getValues(DI_SWITCH_ONLINE, 1)[0],
    )


def test_on_switch_state_forward_online(ctrl):
    c, _ = ctrl
    c._on_switch_state("forward", True)
    assert _dis(c) == (True, False, True)


def test_on_switch_state_reverse_online(ctrl):
    c, _ = ctrl
    c._on_switch_state("reverse", True)
    assert _dis(c) == (False, True, True)


def test_on_switch_state_unknown_offline(ctrl):
    """Both position DIs off + online DI off — the mid-throw or dead
    controller case. This is the "no known state" signal for the HMI."""
    c, _ = ctrl
    c._on_switch_state("unknown", False)
    assert _dis(c) == (False, False, False)


def test_on_switch_state_online_none_treated_as_offline(ctrl):
    """Discovery beacon hasn't been seen yet — the outstation must not
    tell a Modbus master the controller is online. Position DI still
    reflects the last known position."""
    c, _ = ctrl
    c._on_switch_state("forward", None)
    assert _dis(c) == (True, False, False)
