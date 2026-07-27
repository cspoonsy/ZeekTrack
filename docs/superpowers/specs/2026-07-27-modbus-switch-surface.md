# Modbus surface for the track switch

**Status:** approved, ready to implement.
**Date:** 2026-07-27.
**Scope:** extend the single Modbus/TCP outstation (unit 1, port 5020) with 2 coils and 3 discrete inputs representing the track switch, so a defender polling Modbus sees position + liveness for the switch and an attacker can trigger throws with `mbpoll` alone — no MQTT client required.

## Motivation

The ChooChoo event runs the train on Modbus. Trainees investigating the Modbus wire today can only see train telemetry; the switch is on MQTT, invisible from the Modbus side. That splits the defender's tools artificially. Extending the outstation with switch points gives:

- Realistic rail SCADA — one PLC in the cabinet mediates several wayside devices.
- A single point of truth for the operator's HMI to poll.
- A new attack surface (write coil to throw) that Zeek's Modbus analyzer catches — M10 in the vulnerability catalog, complementing S1 on the MQTT side.

## Non-goals

- Removing the MQTT switch surface (S1 stays; the two surfaces are complementary).
- Adding a second outstation.
- Modbus point map for future multi-switch. The layout allows it (bump `CO_COUNT`, add per-switch DIs), but only sw1 is wired.
- ACLs / hardened Modbus profile.
- Limit-switch feedback path — position is still the controller's last-known-state guess.

## Point map extension

`src/choochoo/modbus_map.py`. Additive only — no existing address moves.

```python
# Holding regs — unchanged.
HR_POWER, HR_LIGHT, HR_CMD_COUNTER = 0, 1, 2
HR_COUNT = 3

# Coils.
CO_ESTOP              = 0     # existing
CO_SWITCH_TO_STRAIGHT = 1     # NEW — edge-triggered, latches back to 0
CO_SWITCH_TO_CURVE    = 2     # NEW — edge-triggered, latches back to 0
CO_COUNT = 3                  # was 1

# Input regs — unchanged.
IR_CURRENT_POWER, IR_MAX_POWER = 0, 1
IR_COUNT = 2

# Discrete inputs.
DI_CONNECTED                = 0     # existing (train BLE)
DI_DIRECTION                = 1     # existing (train direction)
DI_SWITCH_POSITION_STRAIGHT = 2     # NEW
DI_SWITCH_POSITION_CURVE    = 3     # NEW
DI_SWITCH_ONLINE            = 4     # NEW — LWT-driven controller liveness
DI_COUNT = 5                        # was 2
```

**Semantics.**
- `CO_SWITCH_TO_STRAIGHT` / `CO_SWITCH_TO_CURVE`: rising-edge command. Outstation processes the True immediately and writes back False so the coil looks momentarily set in `mbpoll` output but doesn't stay latched. Realistic wayside-signal pattern.
- Both DIs off (`STRAIGHT=0, CURVE=0`) = position unknown (mid-throw or never commanded). Standard "in motion / no known position" in real SCADA.
- Both DIs on simultaneously is not a valid state — the mirror never sets both.
- `DI_SWITCH_ONLINE=0` means either the controller is offline (LWT fired) or discovery hasn't been seen yet — the outstation treats "unknown" as "offline" for safety. `DI_SWITCH_ONLINE=1` requires an explicit `online: true` from the discovery topic.

## Wire ↔ physical mapping (shared constants)

`src/choochoo/switch_protocol.py` gains two module-level constants:

```python
UI_STRAIGHT_WIRE_DIRECTION = Direction.FORWARD
UI_CURVE_WIRE_DIRECTION    = Direction.REVERSE
```

These are the single Python-side source of truth for the 3-gear inversion. `modbus_controller.py` and `switch_controller.py` use them. `switch.js` keeps its own JS-side constants for the browser; a comment there notes the mapping must match the Python constants — the browser can't `import`.

## `SwitchMirror` (new class in `modbus_controller.py`)

Structural sibling of `web.SwitchBridge` — same paho background thread, same LWT-aware discovery handling, different output surface.

```python
class SwitchMirror:
    def __init__(
        self,
        host: str,
        port: int,
        switch_id: str,
        on_state_change: Callable[[str, bool | None], None],
    ) -> None: ...

    def start(self) -> None: ...
    def stop(self) -> None: ...

    def throw(self, direction: Direction) -> None:
        """Publish a ThrowCommand to choochoo/switch/<id>/cmd/throw."""
```

- Subscribes to `switch_state_topic(sw)` and `switch_discovery_topic(sw)`.
- On any message, calls `on_state_change(position_str, online_bool_or_none)`.
- `throw()` publishes the same JSON `ThrowCommand` payload the web UI does.
- `position_str` defaults to `"unknown"` until the first state message arrives.
- `online` is `None` until the first discovery message; `False` after LWT.

Config source: env vars `CHOOCHOO_SWITCH_BROKER`, `CHOOCHOO_SWITCH_BROKER_PORT`, `CHOOCHOO_SWITCH_ID`. Same convention `web.py` already uses.

## `ModbusController` changes

`__init__` — construct the mirror and pass to `_TrainBlock`:

```python
self._switch_mirror = SwitchMirror(
    host=os.environ.get("CHOOCHOO_SWITCH_BROKER", "localhost"),
    port=int(os.environ.get("CHOOCHOO_SWITCH_BROKER_PORT", "1883")),
    switch_id=os.environ.get("CHOOCHOO_SWITCH_ID", "sw1"),
    on_state_change=self._on_switch_state,
)
```

`_TrainBlock` — new constructor kwarg `switch_mirror: SwitchMirror | None = None`. Coil branches:

```python
elif addr == CO_SWITCH_TO_STRAIGHT and bool(val):
    if self._switch_mirror is not None:
        log.info("switch throw to straight via coil write")
        self._switch_mirror.throw(UI_STRAIGHT_WIRE_DIRECTION)
    super().setValues(CO_SWITCH_TO_STRAIGHT, [False])
elif addr == CO_SWITCH_TO_CURVE and bool(val):
    if self._switch_mirror is not None:
        log.info("switch throw to curve via coil write")
        self._switch_mirror.throw(UI_CURVE_WIRE_DIRECTION)
    super().setValues(CO_SWITCH_TO_CURVE, [False])
```

Default of `None` keeps existing train tests working — they don't have a mirror.

`_on_switch_state` — the callback:

```python
def _on_switch_state(self, position: str, online: bool | None) -> None:
    self._discrete.setValues(
        DI_SWITCH_POSITION_STRAIGHT,
        [position == UI_STRAIGHT_WIRE_DIRECTION.value],
    )
    self._discrete.setValues(
        DI_SWITCH_POSITION_CURVE,
        [position == UI_CURVE_WIRE_DIRECTION.value],
    )
    self._discrete.setValues(DI_SWITCH_ONLINE, [bool(online)])
```

`run()` — start/stop the mirror around the existing lifecycle:

```python
def run(self) -> None:
    self.train.connect()
    self._switch_mirror.start()
    self._refresh_telemetry()
    log.info(...)
    try:
        asyncio.run(self._serve())
    finally:
        self._switch_mirror.stop()
        self.train.stop()
        self.train.disconnect()
```

## Deployment

`docker-compose.fake.yml`:
- `controller-modbus` gets three new env vars: `CHOOCHOO_SWITCH_BROKER: mosquitto`, `CHOOCHOO_SWITCH_BROKER_PORT: "1883"`, `CHOOCHOO_SWITCH_ID: sw1`.
- `depends_on` gains `mosquitto`.

`docker-compose.real.yml`:
- The Modbus outstation runs bare-metal on the host in real mode. Operator sets `CHOOCHOO_SWITCH_BROKER=localhost` (or the actual broker host) explicitly when invoking `uv run choochoo controller --protocol modbus`. Documented in the README's real-train section.

## Tests

`tests/test_modbus_map.py` (new) — freeze the address layout so future rearrangement is deliberate:

```python
from choochoo.modbus_map import (
    CO_COUNT, CO_ESTOP, CO_SWITCH_TO_CURVE, CO_SWITCH_TO_STRAIGHT,
    DI_CONNECTED, DI_COUNT, DI_DIRECTION,
    DI_SWITCH_ONLINE, DI_SWITCH_POSITION_CURVE, DI_SWITCH_POSITION_STRAIGHT,
    HR_COUNT, IR_COUNT,
)

def test_train_layout_unchanged():
    assert (HR_COUNT, IR_COUNT) == (3, 2)
    assert CO_ESTOP == 0
    assert (DI_CONNECTED, DI_DIRECTION) == (0, 1)

def test_switch_layout():
    assert CO_SWITCH_TO_STRAIGHT == 1
    assert CO_SWITCH_TO_CURVE == 2
    assert CO_COUNT == 3
    assert DI_SWITCH_POSITION_STRAIGHT == 2
    assert DI_SWITCH_POSITION_CURVE == 3
    assert DI_SWITCH_ONLINE == 4
    assert DI_COUNT == 5
```

`tests/test_modbus_controller_switch.py` (new) — behavior tests with a MagicMock switch mirror:

- Writing `True` to `CO_SWITCH_TO_STRAIGHT` calls `mirror.throw(Direction.FORWARD)` once and latches the coil back to False.
- Writing `True` to `CO_SWITCH_TO_CURVE` calls `mirror.throw(Direction.REVERSE)` once and latches back.
- Writing `False` to either coil calls nothing.
- `_on_switch_state("forward", True)` → DIs `[..., 1, 0, 1]`.
- `_on_switch_state("reverse", True)` → DIs `[..., 0, 1, 1]`.
- `_on_switch_state("unknown", False)` → DIs `[..., 0, 0, 0]`.
- `_on_switch_state("forward", None)` → DIs `[..., 1, 0, 0]` (position known, online unknown = offline).

`tests/test_modbus_controller.py` (existing) — regression: existing writes still work with the enlarged coil/DI banks. Update any hard-coded `CO_COUNT` / `DI_COUNT` expectations.

## Docs

`README.md`:
- "Modbus point map" table gains rows for `Coil 1`, `Coil 2`, `DI 2`, `DI 3`, `DI 4`.
- New env-var rows: `CHOOCHOO_SWITCH_BROKER` (default `localhost`), `CHOOCHOO_SWITCH_BROKER_PORT` (default `1883`) — client-side env table.

`VULNERABILITIES.md` — new **M10** at the end of Part 2:

> **M10 — Anonymous switch throws via Modbus coil write.**
> Baseline: an attacker who has enumerated the outstation on `5020/tcp` (see M1 recon) can write `1` to Coil 1 (`CO_SWITCH_TO_STRAIGHT`) or Coil 2 (`CO_SWITCH_TO_CURVE`) to divert the train. No auth, no rate limit at the Modbus layer.
> Attacker action: `mbpoll -m tcp -a 1 -t 0 -r 2 -c 1 <host> 1`.
> Mitigation delta: the switch controller's client-side cooldown (`SWITCH_COOLDOWN_S`) still fires — an attacker cannot burn the motor by spamming coils; but they can time a throw for the moment the train is approaching the switch. Safety mitigation, not security.
> What Zeek sees: `modbus.log` records the Write-Single-Coil (FC 5) with the target coil address. A rapid coil-1/coil-2 alternation is a distinctive signature — the outstation's own operator would not touch both coils in quick succession.
> Detection hook: count `func=WRITE_COILS OR WRITE_SINGLE_COIL` messages targeting `addr in {1, 2}` per source over a rolling window; flag anything faster than one per 2 s.

`attacker/SOLUTIONS.md` — extend Section 3 (Modbus command injection) with the switch coils. Reference the M10 entry.

## Manual verification

1. Full pytest + ruff green.
2. `docker compose --profile modbus --profile mqtt up -d` with the session host-port override still in place. Bare-metal switch controller running against the real Cube.
3. Web UI throw still works end-to-end (baseline). Position DIs should also reflect the new state.
4. From an attacker container (or `mbpoll` on the host):
   ```sh
   mbpoll -a 1 -m tcp -t 0 -r 3 -c 3 <host> 1     # read DIs 2/3/4
   mbpoll -a 1 -m tcp -t 0 -r 2 -c 1 <host> 1     # write coil 1 = throw straight
   mbpoll -a 1 -m tcp -t 0 -r 3 -c 1 <host> 1     # write coil 2 = throw curve
   ```
5. Watch `docker logs choochoo-controller-modbus` for `switch throw to <dir> via coil write` immediately followed by the bare-metal controller's BLE writes (`+130a` / `-130a` → 850 ms → `+000a`).
6. Fire coil-1 twice within 2 s — second attempt publishes `outcome: cooldown_rejected` on MQTT; Modbus coil still latches to 0 (attacker has no negative feedback signal, which is realistic).
7. Kill the switch controller: `DI_SWITCH_ONLINE` flips to 0 within a few seconds via LWT.

## Deferred

- Hardened-profile Modbus ACLs.
- Limit-switch feedback for authoritative position.
- Multi-switch on one outstation.
- Documentation of the shared broker's dependency (both `web.py` and `modbus_controller.py` are now MQTT clients of the switch broker).
- **BLE-stale-handle recovery in `CircuitCubeSwitch`.** Observed on macOS
  after ~5 hours idle: `write_gatt_char` returns
  "Service Discovery has not been performed yet" and the throw fails with
  `BLE_ERROR`. The controller then sits with a dead handle until manually
  restarted. Real fix: catch the specific bleak exception in `_run_burst`,
  tear down and reconnect, then retry once. Non-blocking for the event
  since the trainer can restart the controller between sessions, but
  it will surprise trainees who leave a session running overnight.
