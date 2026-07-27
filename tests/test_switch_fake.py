"""FakeSwitch drives the cooldown + burst-clamp logic that the real BLE
backend also relies on. The real backend adds BLE I/O; the state machine
lives here and is tested here."""

from __future__ import annotations

from choochoo.protocol import Direction
from choochoo.switch import FakeSwitch
from choochoo.switch_protocol import (
    SWITCH_BURST_MS,
    SWITCH_COOLDOWN_S,
    SWITCH_MAX_BURST_MS,
    ThrowOutcome,
)


class Clock:
    def __init__(self, t: float = 1000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, dt: float) -> None:
        self.t += dt


def _make(switch_id: str = "sw1") -> tuple[FakeSwitch, Clock]:
    s = FakeSwitch(switch_id)
    clk = Clock()
    s.set_clock(clk)
    s.connect()
    return s, clk


def test_connect_marks_connected():
    s, _ = _make()
    assert s.state().connected is True


def test_first_throw_succeeds_and_updates_position():
    s, _ = _make()
    outcome = s.throw(Direction.FORWARD)
    assert outcome is ThrowOutcome.OK
    st = s.state()
    assert st.position == "forward"
    assert st.last_throw_ts == 1000.0
    assert st.cooldown_until_ts == 1000.0 + SWITCH_COOLDOWN_S


def test_second_throw_inside_cooldown_is_rejected():
    s, clk = _make()
    assert s.throw(Direction.FORWARD) is ThrowOutcome.OK
    clk.advance(SWITCH_COOLDOWN_S / 2)
    outcome = s.throw(Direction.REVERSE)
    assert outcome is ThrowOutcome.COOLDOWN_REJECTED
    assert s.state().position == "forward"  # unchanged
    assert s.throws == [(Direction.FORWARD, SWITCH_BURST_MS)]  # only the first ran


def test_throw_after_cooldown_succeeds():
    s, clk = _make()
    s.throw(Direction.FORWARD)
    clk.advance(SWITCH_COOLDOWN_S + 0.01)
    outcome = s.throw(Direction.REVERSE)
    assert outcome is ThrowOutcome.OK
    assert s.state().position == "reverse"


def test_burst_duration_is_clamped_to_max():
    s, _ = _make()
    s.throw(Direction.FORWARD, duration_ms=99999)
    assert s.throws == [(Direction.FORWARD, SWITCH_MAX_BURST_MS)]


def test_disconnect_marks_disconnected():
    s, _ = _make()
    s.disconnect()
    assert s.state().connected is False


def test_factory_builds_fake():
    from choochoo.switch import build_switch

    s = build_switch("fake", "sw1")
    assert isinstance(s, FakeSwitch)


def test_factory_rejects_unknown_kind():
    from choochoo.switch import build_switch

    try:
        build_switch("bogus", "sw1")
    except ValueError:
        return
    raise AssertionError("expected ValueError for unknown kind")
