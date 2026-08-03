# Track-switch BLE + MQTT design

**Status:** design approved, awaiting implementation plan.
**Date:** 2026-07-27.
**Scope:** add a BLE-controlled track switch (Circuit Cubes Bluetooth Bit) driving a Lego gear-rack switch, exposed via MQTT alongside the existing train.

## Motivation

The train can now be diverted onto a second track by a motorized switch. The switch motor is driven by a Circuit Cubes "Bluetooth Bit" — a BLE-controllable motor cube — geared through a 16-tooth spur, an idler, and a 4-stud gear rack. The motor **burns out if held on**, so control must come in short bursts. We want to operate the switch over MQTT so it becomes part of the same attack/defense range as the train, and so Zeek sees switch commands on the wire.

## Non-goals

- Modbus/Enterprise-mode surface for the switch (may be added later; the point map lives in a follow-up).
- Auto-homing on startup. `position` begins as `"unknown"` until the operator issues the first throw.
- Multi-switch operation on one Cube. The design permits it (one process per switch, distinct `CHOOCHOO_SWITCH_ID`), but only one is built and tested here.
- Dedicated hardened-profile ACL role for the switch. `mqtt_auth` covers it if you point at the hardened broker, but the training scenarios don't yet reference the switch.
- Changes to the train / BuWizz code paths.

## Circuit Cubes BLE protocol (verified against public reverse-engineering; must confirm on hardware)

Community-reversed; there is no vendor spec. Sources:
- https://github.com/repkovsky/CircuitCubesRemote — JS/Web Bluetooth, clearest wire-format docs.
- https://github.com/made-by-simon/CircuitCubes — Python `bleak` PyPI package.
- https://github.com/dsobotta/mqtt-circuit-cubes — BLE↔MQTT bridge.

| Item                        | Value |
|-----------------------------|-------|
| Advertised name             | substring `"Tenka"` (default; overridable via `CHOOCHOO_CUBE_NAME`) |
| Service UUID                | `6e400001-b5a3-f393-e0a9-e50e24dcca9e` (Nordic UART) |
| Write characteristic        | `6e400002-b5a3-f393-e0a9-e50e24dcca9e` — write-without-response, MTU 20 |
| Notify characteristic       | `6e400003-b5a3-f393-e0a9-e50e24dcca9e` |
| Command frame               | 5-byte ASCII `dNNNc` — `d`=`'+'`/`'-'`, `NNN`=zero-padded magnitude 000–255, `c`=port `'a'`/`'b'`/`'c'` |
| Stop frame                  | `+000<port>` (coasts; no separate brake opcode) |
| Motor ports                 | 3 (`a`, `b`, `c`), addressed by the trailing ASCII byte |
| Watchdog                    | **None documented** — we assume the cube keeps driving until told to stop. This is exactly why the client owns the burst duration. |
| Deadband                    | Community reports "below 80 may not move" — but our switch is geared down; `SWITCH_POWER=60` may or may not be enough. Verify on hardware and adjust the constant. |
| Auth / encryption           | None. Plain NUS, ASCII payloads. |
| Likely SoC                  | TI CC2640-family (based on second vendor UUID). Not load-bearing for us. |

## Component layout

Three new modules under `src/choochoo/`, plus a CLI subcommand. Nothing existing is restructured.

```
src/choochoo/
├── switch/                        # NEW package
│   ├── __init__.py                # build_switch() factory
│   ├── base.py                    # SwitchClient ABC
│   ├── fake.py                    # FakeSwitch — logs only, no BLE
│   └── circuit_cube.py            # CircuitCubeSwitch — real BLE via bleak
├── switch_controller.py           # NEW — mirror of controller.py
├── switch_protocol.py             # NEW — topics + Pydantic models + safety constants
└── cli.py                         # extend: add `switch-controller` and `switch-send`
```

### `SwitchClient` ABC (`src/choochoo/switch/base.py`)

Mirrors `TrainClient` in shape (see `src/choochoo/train/base.py`). One method carries the entire hardware interaction:

```python
def throw(self, direction: Direction, duration_ms: int = SWITCH_BURST_MS) -> ThrowOutcome: ...
```

`ThrowOutcome` is one of `"ok"`, `"cooldown_rejected"`, `"ble_error"`. The abstraction owns the burst — callers cannot hold the motor on. `duration_ms` is a defensive parameter for the internal caller; it is clamped to `SWITCH_MAX_BURST_MS`.

### `CircuitCubeSwitch` (`src/choochoo/switch/circuit_cube.py`)

Follows the BuWizz pattern verbatim: **background asyncio loop on a daemon thread**, synchronous `TrainClient`-style API on top. Reuses the plumbing of `src/choochoo/train/buwizz.py:271-307`.

- Connect: `BleakScanner.find_device_by_name(<name>, timeout=10)` filtering by substring match on the advertised name; then `BleakClient(device).connect()`; then locate the write characteristic by UUID.
- Throw: write `dNNNc` as UTF-8 bytes to the write characteristic (write-without-response), `await asyncio.sleep(duration_ms/1000)`, then write `+000<port>` in a `try/finally` so the stop write runs even if the sleep is cancelled.
- Disconnect: write `+000<port>` best-effort, then `client.disconnect()`.

The Circuit Cube has no documented watchdog. That absence is the whole reason the burst is a client-side timer.

### `FakeSwitch` (`src/choochoo/switch/fake.py`)

In-memory. `throw()` records `(direction, clamped_duration_ms)`, applies the same cooldown logic as the real client, updates `position`. No sleep — the test time-travels by monkey-patching the cooldown clock. Follows `src/choochoo/train/fake.py`.

## MQTT surface (`src/choochoo/switch_protocol.py`)

### Topics

```
choochoo/switch/<switch_id>/cmd/throw       # publisher -> controller
choochoo/switch/<switch_id>/state           # controller -> subscribers (retained)
choochoo/switch/<switch_id>/discovery       # controller -> subscribers (retained)
choochoo/switch/<switch_id>/event           # controller -> subscribers (throw results, non-retained)
```

### Payloads

`ThrowCommand`:

```json
{ "action": "throw", "direction": "forward" | "reverse" }
```

Duration is **not** on the wire. The caller cannot ask for a longer burst.

`SwitchState` (retained):

```json
{ "switch_id": "sw1",
  "position": "forward" | "reverse" | "unknown",
  "connected": true,
  "last_throw_ts": 1730000000.0,
  "cooldown_until_ts": 1730000002.0 }
```

`ThrowEvent` (per-throw, **non-retained**):

```json
{ "switch_id": "sw1",
  "direction": "forward",
  "outcome": "ok" | "cooldown_rejected" | "ble_error",
  "ts": 1730000000.0 }
```

`outcome` values:
- `"ok"` — burst wrote both start and stop frames without exception.
- `"cooldown_rejected"` — `now < cooldown_until_ts`; no BLE writes issued.
- `"ble_error"` — the start frame or the stop frame raised. The `finally` still attempted the stop write; this outcome tells the operator to check BLE health before another throw.

`SwitchDiscovery` mirrors `DiscoveryAnnouncement` (`protocol.py:76-93`): retained "I exist" beacon with LWT on the same topic, same trainee-visible attack surface.

### Direction enum

Reuse `choochoo.protocol.Direction` (`FORWARD`, `REVERSE`). Semantically the two "positions" of the switch — the mapping to physical rail alignment is a decal on the layout, not something the code has to know.

## Safety envelope

Hard-coded constants in `switch_protocol.py`:

```python
SWITCH_BURST_MS       = 400   # duration of one throw burst
SWITCH_POWER          = 60    # 0..255; tune after real-hardware test (see deadband note above)
SWITCH_COOLDOWN_S     = 2.0   # min gap between throws (per switch_id)
SWITCH_MAX_BURST_MS   = 800   # hard ceiling — clamps duration_ms in throw() regardless of caller
```

Enforcement lives in `SwitchClient.throw()`, in this order:

1. If `now < cooldown_until_ts`: log a warning, publish `ThrowEvent { outcome: "cooldown_rejected" }`, **return without any BLE write**.
2. Clamp `duration_ms` to `SWITCH_MAX_BURST_MS`.
3. Write `dNNNc` at `SWITCH_POWER` in the requested direction.
4. `await asyncio.sleep(duration_ms / 1000)`.
5. In `finally`: write the stop frame `+000<port>`.
6. Update `cooldown_until_ts = now + SWITCH_COOLDOWN_S`, update `position` if the throw succeeded, publish `SwitchState`.

Two independent brakes against burnout:

- **Bounded burst** — the `sleep`/`finally` pair guarantees the stop frame is written even if the task is cancelled, the BLE write raises, or the controller receives SIGINT mid-burst.
- **Dead-man on process exit** — `SwitchController._shutdown()` calls `switch.disconnect()`, which sends `+000<port>` before dropping BLE. Same shape as `Controller._shutdown` (`controller.py:76`).

## Controller (`src/choochoo/switch_controller.py`)

Structural copy of `controller.py`, retargeted to the switch topics. Key details:

- MQTT client id `choochoo-switch-controller-<switch_id>`.
- Subscribes to `choochoo/switch/<switch_id>/cmd/+` on connect.
- LWT: retained `SwitchDiscovery { online: false }` on the discovery topic.
- `_on_message` matches on `action == "throw"`, validates with `ThrowCommand`, calls `switch.throw(direction)`, then publishes `SwitchState` and a `ThrowEvent`.
- Unknown action, non-JSON payload, and Pydantic validation errors are logged and ignored — same failure modes as the train (`controller.py:104-134`).
- `_shutdown` on SIGINT/SIGTERM calls `switch.disconnect()` first, then `client.disconnect()`.

## CLI (`src/choochoo/cli.py`)

Two new subcommands:

```
uv run choochoo switch-controller           # runs SwitchController.run()
uv run choochoo switch-send throw forward   # ad-hoc publish for smoke tests
```

Flags mirror the existing `controller` / `send`: `--switch-id`, `--kind fake|circuit_cube`, `--broker`, `--broker-port`. Global `-v` flag continues to gate the DEBUG logs.

## Environment variables (new)

| Var                    | Default | Meaning                                             |
|------------------------|---------|-----------------------------------------------------|
| `CHOOCHOO_SWITCH_ID`   | `sw1`   | Switch identifier for topic prefix                  |
| `CHOOCHOO_SWITCH_KIND` | `fake`  | `fake` or `circuit_cube`                            |
| `CHOOCHOO_CUBE_NAME`   | `Tenka` | Substring match against the Cube's BLE advertised name |
| `CHOOCHOO_CUBE_PORT`   | `a`     | Which Cube port drives this switch: `a` / `b` / `c` |

`CHOOCHOO_BROKER` / `CHOOCHOO_BROKER_PORT` / `CHOOCHOO_USER` / `CHOOCHOO_PASSWORD` / `CHOOCHOO_TLS_CA` are reused from the existing MQTT stack.

## Deployment

- `docker-compose.real.yml`: **no change.** BLE is host-only; the switch controller runs bare-metal alongside the train controller. Third terminal:
  ```sh
  CHOOCHOO_SWITCH_KIND=circuit_cube \
  CHOOCHOO_CUBE_NAME=Tenka \
  CHOOCHOO_CUBE_PORT=a \
      uv run choochoo -v switch-controller
  ```
- `docker-compose.fake.yml`: add one new service under the `mqtt` profile — `switch-controller-fake`. Same image as the train controller, `CHOOCHOO_SWITCH_KIND=fake`. Runs alongside `controller-mqtt-fake`. Roughly 8 lines of YAML. No new host ports.
- `docker-compose.hardened.yml`: no direct change; the switch controller picks up hardened auth via `CHOOCHOO_USER`/`CHOOCHOO_PASSWORD`/`CHOOCHOO_TLS_CA` like the train.

## Tests

Three new test files. None require real BLE.

### `tests/test_switch_protocol.py`

- Pydantic round-trip for `ThrowCommand`, `SwitchState`, `ThrowEvent`, `SwitchDiscovery`.
- Topic-builder helpers return the expected strings.
- `SWITCH_MAX_BURST_MS` is strictly greater than `SWITCH_BURST_MS` (constant relationship).

### `tests/test_switch_controller.py`

Modeled on `tests/test_controller.py`. Instantiate `SwitchController` with a mocked MQTT client and a `FakeSwitch`, feed synthetic messages, assert:

- Valid `throw` drives the fake and updates `position`.
- Bad direction (`"sideways"`) is ignored, position unchanged.
- Non-JSON payload is ignored.
- Unknown action is ignored.
- **Cooldown rejection:** two throws within `SWITCH_COOLDOWN_S` — the second publishes a `ThrowEvent` with `outcome == "cooldown_rejected"` and the fake records only one throw. Time is advanced via a monkey-patched clock in `FakeSwitch`, not `time.sleep`.
- **Burst clamp:** calling `switch.throw(direction, duration_ms=99999)` directly on `FakeSwitch` records the clamped value `SWITCH_MAX_BURST_MS`.
- **Shutdown:** `SwitchController._shutdown()` calls `switch.disconnect()` even if the MQTT client is already dead.

### `tests/test_switch_circuit_cube.py`

Monkey-patch `bleak.BleakScanner` and `bleak.BleakClient` (same approach as the absence of real-BLE tests for BuWizz today). Assert:

- On `throw(FORWARD, 400)` with `CHOOCHOO_CUBE_PORT=a`, the write characteristic receives exactly `b"+060a"`.
- After the burst duration elapses, it receives exactly `b"+000a"`.
- If the mocked BleakClient's write raises during the burst, the `finally` still attempts the stop write.
- `disconnect()` sends `b"+000a"` before calling `client.disconnect()`.

## Real-hardware verification (motor physically unplugged)

Physically **disconnect the motor lead from `CHOOCHOO_CUBE_PORT`** before running any BLE-live test. All four checks below run against a powered Cube with no motor attached:

1. Start the controller — `uv run choochoo -v switch-controller` with `CHOOCHOO_SWITCH_KIND=circuit_cube`. Expect a log line `connected to Cube at <mac-addr>` and a retained `discovery` beacon on MQTT.
2. Fire a single throw — `uv run choochoo switch-send throw forward` (from another shell). Expect log lines showing the `+060a` frame written, a ~400 ms pause, then `+000a` written, and an MQTT `event` with `outcome: "ok"`.
3. Fire two throws in quick succession — same command twice inside 2 s. Expect the second one to publish `event.outcome == "cooldown_rejected"` and **no** BLE writes for the rejected throw.
4. Kill the controller mid-burst — SIGINT to the controller while the 400 ms sleep is active. Expect a `+000a` stop frame in the log before shutdown completes.

Only after all four pass, reconnect the motor and repeat step 2 once to verify direction. Then step 3 to confirm the gear rack doesn't bind on rapid throws. If the switch doesn't move because `SWITCH_POWER=60` is below the geared-down stall threshold, raise `SWITCH_POWER` in `switch_protocol.py` and retest — this is expected to need tuning.

## `VULNERABILITIES.md` — new S-series entry

Add a **Part 3 — Track-switch surface (MQTT)** section with one entry to start:

**S1 — Anonymous throw commands drive real hardware.**
- Same baseline as V1: anonymous plaintext MQTT lets anyone on the LAN publish `choochoo/switch/sw1/cmd/throw` and move the track.
- Attacker action: `mosquitto_pub -h <broker> -t choochoo/switch/sw1/cmd/throw -m '{"action":"throw","direction":"forward"}'`.
- Mitigation delta vs V1: the client-side cooldown means an attacker cannot burn out the motor by spamming throws, but they can still divert the train at chosen moments — a *safety*-oriented mitigation, not a security one. Zeek sees each MQTT PUBLISH; a rapid burst of `cmd/throw` messages against the cooldown is a distinctive detection signal.
- Zeek detection hook: on `mqtt.log`, count PUBLISH events with `topic ~ "choochoo/switch/.*/cmd/throw"` per source in a rolling window; flag any source exceeding one per 2 s (matches the cooldown floor).

## Follow-ups (not this change)

- Modbus point map for the switch (coil for direction, coil for "throw now" trigger, HR for position readback).
- Second switch on the same Cube (port `b`) — proves the multi-switch topology.
- Hardened-profile ACL role `switch` scoped to `choochoo/switch/+/cmd/+` publish and `.../state`+`.../event` subscribe.
- Position readback via a physical limit switch (would let `position` start `"forward"` or `"reverse"` on boot instead of `"unknown"`).
