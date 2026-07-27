# Switch web UI design

**Status:** approved, ready to implement.
**Date:** 2026-07-27.
**Scope:** add a track-switch panel to the existing FastAPI web UI so the operator can see switch position + connection status and issue throws from the same page as the train controls. Also add a soft deprecation for the MQTT train (the event runs Modbus-only) and retarget attacker docs.

## Motivation

For an upcoming training event the physical train runs on Modbus/TCP and the track switch runs on MQTT. Trainees and instructors need one dashboard that shows both. The existing web UI already renders the train from either bridge; this change adds a peer `SwitchBridge` and a switch panel that renders regardless of `CHOOCHOO_PROTOCOL`.

The MQTT train stack is not deleted — it stays as a demonstrable legacy surface and remains testable — but every entry point emits a deprecation warning.

## Non-goals

- Deleting any MQTT train code paths.
- Modbus surface for the switch. Still MQTT-only.
- Multi-switch UI. Single switch, single set of buttons.
- Auth / per-role ACLs on the new endpoints (baseline is deliberately wide open).
- Adding the switch to the packet-animation SVG topology diagram.
- JS unit tests.

## Architecture

Two independent bridges, both instantiated for every web app boot regardless of the train protocol:

```
FastAPI app
├── train bridge  (MqttBridge if CHOOCHOO_PROTOCOL=mqtt, else ModbusBridge)
│      └── /api/motor, /api/stop, /api/light, /api/state, /ws/state
└── switch bridge (SwitchBridge — MQTT only)
       └── /api/switch/state, /api/switch/throw, /ws/switch/state
```

Independent lifecycles: a broker glitch that stalls one bridge does not stall the other. `SwitchBridge` is a byte-for-byte structural copy of `MqttBridge`, scoped to switch topics and typed to `SwitchState` / `ThrowCommand` from `switch_protocol.py`.

## `SwitchBridge` contract

```python
class SwitchBridge:
    def __init__(self, host: str, port: int, switch_id: str) -> None: ...
    def start(self) -> None: ...          # connect_async + loop_start
    def stop(self) -> None: ...           # loop_stop + disconnect
    def publish(self, action: str, payload: dict) -> None: ...
    def subscribe(self) -> asyncio.Queue[SwitchState]: ...
    def unsubscribe(self, q) -> None: ...

    state: SwitchState | None
```

- Subscribes to `switch_state_topic(switch_id)` on connect.
- Caches latest `SwitchState`; delivers it immediately to any new subscriber.
- Fan-out via `set[asyncio.Queue[SwitchState]]`, `maxsize=16`, drop-oldest on full.
- `publish("throw", payload)` writes to `switch_cmd_topic(switch_id, "throw")`.

## REST + WebSocket endpoints

- `GET /api/switch/state` → cached `SwitchState.model_dump()`, or `{"switch_id": ...}` if not yet seen.
- `POST /api/switch/throw` → validates against `ThrowCommand` (Pydantic 422 on bad direction), publishes to broker.
- `WS /ws/switch/state` → mirror of `/ws/state`: per-connection queue, streams `SwitchState.model_dump_json()`.

Wide-open CORS / no auth carries over from the existing endpoints. Any attacker on the LAN who can hit `POST /api/switch/throw` can also just `mosquitto_pub` the topic directly — the endpoint doesn't widen the attack surface.

## Environment

- `CHOOCHOO_SWITCH_ID` (default `sw1`) — same as the CLI already reads.
- Broker host/port reused from `CHOOCHOO_BROKER` / `CHOOCHOO_BROKER_PORT` (both bridges point at the same broker for MQTT).

## UI

New HTML section between `.controls` and `<details>` in `static/index.html`:

- `<h2>Track switch</h2>` with a connection pill (`Switch • Connected` / `Disconnected` / `…`) mirroring the train BLE pill.
- Position row: colored pill (`Straight` green / `Curve` orange / `Unknown` grey) plus a cooldown progress bar labeled `Cooldown: <n.n>s` / `ready`.
- Two throw buttons: **Throw to Straight** and **Throw to Curve**. Disabled during cooldown.
- Muted "last event" line under the buttons echoing each attempt or failure.

CSS extends the existing dark palette (`#21262d` cards, `#30363d` borders, `#8b949e` muted, `#f0883e` accent).

JS in a new file `static/switch.js`, loaded via a second `<script>` after `app.js`. Owns:

- WebSocket subscription with auto-reconnect (1.5 s backoff).
- Cooldown timer ticked every 100 ms locally against `cooldown_until_ts` from the last state — smooth countdown regardless of state push rate. Disables buttons while cooldown > 0.
- Fetch-based throw POST with error surfacing.

### Wire ↔ visual mapping

The switch has three gears between the motor and the rack, which inverts rotation direction from motor to rack. Every planned switch in this range uses the same mechanism, so the mapping is a fixed system invariant:

```javascript
const UI_STRAIGHT_WIRE_DIRECTION = "forward";
const UI_CURVE_WIRE_DIRECTION    = "reverse";
```

These two constants at the top of `switch.js` are the single source of truth for how the UI's user-facing labels map to on-wire `Direction` values. The controller and MQTT payload use the enum values (`forward`/`reverse`) verbatim — no inversion in the controller, no inversion in the payload. The UI is the only place that translates.

## Deprecation nudges

Retain all MQTT train code; add non-fatal warnings so operators pointing at it during the event get a nudge:

- `controller.py` — one `log.warning("MQTT train controller is deprecated for the ChooChoo event; the event runs Modbus-only. Set CHOOCHOO_PROTOCOL=modbus.")` at the end of `Controller.__init__`.
- `cli.py` — one `click.echo("warning: `choochoo send <action>` targets the MQTT train, which is deprecated for the event. Use `choochoo controller --protocol modbus` and drive from the web UI.", err=True)` at the top of each of `send_motor`, `send_stop`, `send_light`.

No compose changes; `controller-mqtt-fake` stays in `docker-compose.fake.yml`.

## Docs

`README.md`:
- Top intro paragraph: note the event runs Modbus for the train, MQTT for the switch.
- Track switch subsection: add "The switch panel is always visible in the web UI, regardless of the train's protocol."

`VULNERABILITIES.md`:
- Part 1 (MQTT/IoT) — note that the MQTT train surface is deprecated for the event, but the V-series still applies to anyone running the legacy controller.
- Part 3 (S1) — note the switch broker is the only MQTT surface the event exercises.

`attacker/cheatsheet.md`:
- Keep the tool list. Update the "where you are on the network" hint to point trainees at both a Modbus target and an MQTT target without naming which is which.

`attacker/SOLUTIONS.md`:
- Reorder the suggested progression so Modbus M-series comes first (train), and S1 (switch) is the MQTT chapter.
- Legacy V1-V10 stay as reference material.

## Tests

`tests/test_switch_bridge.py` (new, ~50 lines):
- `_on_message` with valid `SwitchState` JSON caches state and fans out.
- `_on_message` with malformed JSON logs and drops without evicting cached state.
- `publish("throw", {...})` writes to `choochoo/switch/<id>/cmd/throw` with JSON payload.
- Backpressure: full queue drops oldest.

`tests/test_web_switch.py` (new, ~40 lines):
- `GET /api/switch/state` before any state → `{"switch_id": "sw1"}`.
- `GET /api/switch/state` after cached state → full `SwitchState` payload.
- `POST /api/switch/throw` valid → 200, `bridge.publish` called once with correct payload.
- `POST /api/switch/throw` bad direction → 422, bridge untouched.

`tests/test_web.py` (existing):
- Extend `test_index_serves_html` with `assert 'id="switch-position-pill"' in r.text`.

Ruff clean on every changed file. Full suite green.

## Manual verification

1. `uv run pytest -q && uv run ruff check` — all green.
2. `docker compose -f docker-compose.fake.yml --profile modbus up --build -d` then start the switch controller with `CHOOCHOO_SWITCH_KIND=fake` in a sidecar container (or run manually). Open `http://localhost:8000/`:
   - Both train and switch sections render.
   - Click **Throw to Straight**: switch position pill flips to Straight after ~50 ms; cooldown bar starts full and counts down; both buttons are disabled during cooldown.
   - Click again during cooldown: buttons are disabled, no request goes out (verify from browser devtools).
   - Wait 2 s; cooldown clears; buttons re-enable.
   - Kill the switch controller: connection pill flips to Disconnected within a few seconds.
3. Real-hardware smoke (motor connected): the switch controller runs bare-metal with `CHOOCHOO_SWITCH_KIND=circuit_cube`. Click each button, confirm physical movement matches label.

## Deferred

- Deletion of MQTT train code.
- Modbus point map for the switch.
- Hardened ACL role for the switch.
- Switch position readback from a limit switch.
- Multi-switch panel.
