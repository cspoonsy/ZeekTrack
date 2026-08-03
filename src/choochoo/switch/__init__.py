from choochoo.switch.base import SwitchClient
from choochoo.switch.fake import FakeSwitch

__all__ = ["SwitchClient", "FakeSwitch", "build_switch"]


def build_switch(kind: str, switch_id: str) -> SwitchClient:
    """Factory. `kind` comes from CHOOCHOO_SWITCH_KIND."""
    if kind == "fake":
        return FakeSwitch(switch_id)
    if kind == "circuit_cube":
        # Lazy import so `bleak` (from the `pi` extra) isn't required for
        # tests or the fake profile.
        from choochoo.switch.circuit_cube import CircuitCubeSwitch

        return CircuitCubeSwitch(switch_id)
    raise ValueError(f"Unknown switch kind: {kind!r}")
