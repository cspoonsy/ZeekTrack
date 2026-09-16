# ChooChoo

Dual-protocol control plane for a Lego train, deployed on two Raspberry
Pis and a managed switch as a hands-on attack/defense cybersecurity
training range. Same physical train, two control planes:

- **Enterprise mode** (primary): Modbus/TCP. Mirrors industrial / OT
  control. Zeek's built-in Modbus analyzer decodes it out of the box;
  Corelight sensors with `icsnpp_modbus_enable` produce
  `modbus_detailed.log` with register addresses and values.
- **IoT mode** (legacy): MQTT over Mosquitto. Mirrors a consumer / SMB
  IoT deployment. Kept for the V-series MQTT vulnerabilities in
  `VULNERABILITIES.md`; the event runs Modbus for the train.

Both are intentionally vulnerable at baseline — no auth, no TLS, no
integrity. See `VULNERABILITIES.md` for the attack catalog (V1–V10
MQTT, M1–M10 Modbus, S1–S3 switch).

**Track switch is always MQTT** and always runs alongside the train
controller on the same Pi (both need BLE). A Modbus master can still
throw the switch by writing coils 1/2 on the outstation — that's the
M10 cross-protocol path.

## Physical topology

```
                                    ┌─────────────────────────────────────────┐
                                    │           MANAGED L2 SWITCH             │
                                    │        (physical, with SPAN port)       │
                                    └──┬──────┬────────┬───────┬───────┬──────┘
                                       │      │        │       │       │
                                       │      │        │       │       │ (mirror out — RX only)
                                       │      │        │       │       ▼
                                       │      │        │       │   ┌────────────────────────────┐
                                       │      │        │       │   │ SENSOR BOX  (bare-metal)   │
                                       │      │        │       │   │   Corelight Microsensor    │
                                       │      │        │       │   │   Zeek + ICSNPP Modbus     │
                                       │      │        │       │   │   → SIEM / Investigator    │
                                       │      │        │       │   └────────────────────────────┘
                                       │      │        │       │
       ┌───────────────────────────────┘      │        │       └────────────────┐
       │                                      │        │                        │
       ▼                                      ▼        ▼                        ▼
┌────────────────────┐        ┌─────────────────────────────────┐     ┌─────────────────────────┐
│  ATTACKER LAPTOP   │        │  WEB-UI Pi                      │     │  CONTROLLER Pi          │
│  (bare-metal, DHCP)│        │  192.168.88.253                 │     │  192.168.88.250         │
│                    │        │  (Docker Compose)               │     │  (bare-metal + systemd) │
│  Tools:            │        │                                 │     │                         │
│  • nmap            │        │  ┌───────────────────────────┐  │     │  systemd units:         │
│  • tcpdump         │        │  │ mosquitto  :1883          │  │     │   • choochoo-           │
│  • mbpoll          │        │  │  (container)              │  │     │       controller        │
│  • mosquitto_pub   │        │  └───────────┬───────────────┘  │     │   • choochoo-switch-    │
│  • mosquitto_sub   │        │              │ MQTT             │     │       controller        │
│  • python          │        │              ▼                  │     │                         │
│                    │        │  ┌───────────────────────────┐  │     │  Modbus outstation      │
└─────────┬──────────┘        │  │ web-modbus  :8000         │  │     │    on 0.0.0.0:502       │
          │                   │  │  (container, FastAPI)     │  │     │                         │
          │                   │  │  ├─ Modbus master ────────┼──┼─────┼─▶ train setpoints       │
          │                   │  │  ├─ MQTT client (switch) ─┼──┼──┐  │                         │
          │                   │  │  ├─ HTTP /api/*  :8000    │  │  │  │  MQTT client (M10) ─┐   │
          │                   │  │  └─ WS /ws/*    :8000     │  │  │  │                     │   │
          │                   │  └───────────────────────────┘  │  │  └─────────────────────┼───┘
          │                   │                    ▲            │  │                        │
          │                   └────────────────────┼────────────┘  │                        │
          │                                        │               │                        │
          │       Modbus/TCP :502 (attack)         │               │                        │
          ├────────────────────────────────────────┼───────────────┼────────────────────────┼──▶
          │                                        │               │                        │
          │       MQTT :1883 (direct pub/sub)      │               │                        │
          └───────────────────────────────────────▶┤               │                        │
                                                   │               │                        │
                                          ┌────────┴──────┐        │                        │
                                          │   OPERATOR    │        │                        │
                                          │   BROWSER     │        │                        │
                                          │  (trainer PC) │        │                        │
                                          │  HTTP+WS :8000│        │                        │
                                          └───────────────┘        │                        │
                                                                   │                        │
                            MQTT :1883 (switch cmd) ◀──────────────┘                        │
                                                                                            │
                            Modbus poll (web → controller) ◀───────────────────────────────┘
                                                                                            │
                                                                                            │  BLE (radio, off-network)
                                                                                            ├──────────────────┐
                                                                                            │                  │
                                                                                            ▼                  ▼
                                                                                       ┌─────────┐        ┌─────────┐
                                                                                       │ BuWizz3 │        │  Cube   │
                                                                                       │  hub    │        │ Tenka…  │
                                                                                       └────┬────┘        └────┬────┘
                                                                                            │                  │
                                                                                            ▼                  ▼
                                                                                       ┌─────────┐        ┌─────────┐
                                                                                       │  TRAIN  │        │ SWITCH  │
                                                                                       └─────────┘        └─────────┘
```

Static IPs. All hosts on one VLAN. The switch's SPAN mirrors the trunk to
the sensor's capture NIC.

## Physical inventory

| Role | Hardware | Static IP | Runs |
|---|---|---|---|
| Web-UI Pi | Raspberry Pi 4/5 | `192.168.88.253` | Docker: `mosquitto`, `web-modbus` |
| Controller Pi | Raspberry Pi 4/5 (owns BLE) | `192.168.88.250` | systemd: train controller (Modbus outstation), switch controller (MQTT) |
| Sensor | Corelight Microsensor | *(mgmt IP)* | Zeek + ICSNPP Modbus + shipper to SIEM |
| Switch | Any managed L2 with SPAN | — | mirrors the trunk to sensor's capture NIC |
| Attacker | Student laptop | DHCP | `nmap`, `tcpdump`, `mbpoll`, `mosquitto-clients`, `python` |
| Operator | Trainer's browser | any | `http://192.168.88.253:8000` |

**BLE hardware** (radio, off-network):
- BuWizz 3.0 Pro hub (train motor)
- Circuit Cubes Bluetooth Bit (`TenkaBCFD` for sw1, `TenkaBEEA` for sw2)

## Prerequisites

- **Docker Engine + Compose v2** on the web-UI Pi.
- **`uv`** on the controller Pi (`curl -LsSf https://astral.sh/uv/install.sh | sh`).
- **`bluez`** and `bluetooth` group membership on the controller Pi (both installed by `scripts/pi-setup.sh`).
- **`libcap` / `setcap`** on the controller Pi (usually preinstalled on Raspberry Pi OS).

## Setup — Web-UI Pi (`192.168.88.253`)

Clone the repo and drop a compose override that points `web-modbus` at
the controller Pi's real LAN IP:

```sh
git clone <repo> ~/ZeekTrack && cd ~/ZeekTrack
```

Create `docker-compose.override.yml` next to `docker-compose.real.yml`:

```yaml
services:
  web-modbus:
    environment:
      CHOOCHOO_BROKER: 192.168.88.250     # controller Pi IP
      CHOOCHOO_MODBUS_PORT: "502"          # standard Modbus port
```

Compose auto-loads `docker-compose.override.yml` — no CLI flag needed.

Bring up mosquitto + web-modbus:

```sh
docker compose -f docker-compose.real.yml \
    --profile modbus --profile mqtt up --build -d
```

Confirm both containers are up and env vars took:

```sh
docker compose -f docker-compose.real.yml ps
docker exec choochoo-web-modbus-real printenv | grep CHOOCHOO
```

Web UI at `http://192.168.88.253:8000`. It will log Modbus poll failures
until the controller Pi comes online — that's expected.

## Setup — Controller Pi (`192.168.88.250`)

Clone and run the setup script:

```sh
git clone <repo> ~/ZeekTrack && cd ~/ZeekTrack
./scripts/pi-setup.sh
```

The script installs system packages (bluez, build deps), adds the user to
`bluetooth`, installs `uv`, syncs the `pi` extra, and drops two templated
systemd units. Re-runs are idempotent.

Grant the venv's Python permission to bind privileged ports (needed for
port 502):

```sh
sudo setcap 'cap_net_bind_service=+ep' \
    $(readlink -f ~/ZeekTrack/.venv/bin/python)

# Verify
sudo getcap $(readlink -f ~/ZeekTrack/.venv/bin/python)
# expect: ... cap_net_bind_service=ep
```

Edit the two env files:

```sh
sudo $EDITOR /etc/choochoo/controller.env
```

```env
CHOOCHOO_PROTOCOL=modbus
CHOOCHOO_TRAIN=buwizz
CHOOCHOO_BUWIZZ_NAME=BuWizz3
CHOOCHOO_MODBUS_PORT=502
CHOOCHOO_MODBUS_BIND=0.0.0.0
CHOOCHOO_SWITCH_BROKER=192.168.88.253     # web-UI Pi (for M10 mirror + switch panel)
CHOOCHOO_BUWIZZ_LED_BRIGHTNESS=8          # onboard LED brightness, 0..100
```

```sh
sudo $EDITOR /etc/choochoo/switch-controller.env
```

```env
CHOOCHOO_SWITCH_KIND=circuit_cube
CHOOCHOO_CUBE_NAME=TenkaBCFD              # unique per Cube — see "Multiple Cubes" below
CHOOCHOO_CUBE_PORT=a
CHOOCHOO_SWITCH_ID=sw1
CHOOCHOO_BROKER=192.168.88.253            # web-UI Pi
```

Enable both units:

```sh
sudo systemctl enable --now choochoo-controller choochoo-switch-controller
sudo journalctl -u choochoo-controller -u choochoo-switch-controller -f
```

## Startup order

The web-UI Pi must come up first. Controllers dial out to the broker
(`mosquitto`) on startup; if the broker isn't there yet, they crash
rather than retry. The web UI's Modbus master, by contrast, retries
happily.

1. **Web-UI Pi** → `docker compose … up -d` → mosquitto (:1883) + web-modbus (:8000)
2. **Sanity check from controller Pi:** `nc -zv 192.168.88.253 1883` — must say "succeeded"
3. **Controller Pi** → `systemctl start choochoo-controller choochoo-switch-controller`
4. **Sanity check from web-UI Pi:** `nc -zv 192.168.88.250 502` — must say "succeeded"

If either `nc` step refuses, fix that before proceeding. Missing setcap
on the controller Pi produces `[Errno 13] permission denied` binding
:502 (visible in `journalctl -u choochoo-controller`).

## What the operator sees

- `http://192.168.88.253:8000` — dashboard with train + switch panels
- Header pills: **ENTERPRISE / MODBUS** and **BLE • Connected** (green when both hubs are up)
- Throttle slider drives HR 0; every write flashes the onboard LEDs red then back to idle blue

## What Zeek sees

With `Corelight::icsnpp_modbus_enable` on the sensor and the SPAN mirror
configured, every attacker Modbus write shows up as one line in
`modbus_detailed.log` with the source IP, function code, register
address, and value written. Register semantics live in the point map
below.

MQTT traffic on 1883 goes to `mqtt_connect.log`, `mqtt_publish.log`,
`mqtt_subscribe.log`. Attackers subscribing to `#` show up as one
long-lived MQTT connection.

## Multiple Cubes with unique names

`CHOOCHOO_CUBE_NAME` is a *substring* match against the BLE advertised
name. Two Cubes in range advertise as `Tenka<HHHH>` with a unique
4-hex-char suffix. Setting the bare prefix `Tenka` would pick one
non-deterministically. Always set the full unique name.

Scan for advertised names from the controller Pi:

```sh
uv run python -c "
import asyncio
from bleak import BleakScanner
async def go():
    devs = await BleakScanner.discover(timeout=8, return_adv=True)
    for _, (d, adv) in devs.items():
        if 'Tenka' in (d.name or '') or 'BuWizz' in (d.name or ''):
            print(f'{d.address}  {d.name!r}  rssi={adv.rssi}')
asyncio.run(go())
"
```

Same trick works for `CHOOCHOO_BUWIZZ_NAME` if you have multiple BuWizz
hubs.

## Modbus point map

Unit ID `1`. No auth, no TLS — baseline posture.

| Address | Type | Meaning |
|---|---|---|
| HR 0 | Holding reg, signed int16 | Motor power, -100..100 (sign = direction) |
| HR 1 | Holding reg | Light brightness 0..10 |
| HR 2 | Holding reg | Operator-incremented command counter |
| Coil 0 | Coil | Emergency stop (edge-triggered; latches back to 0) |
| Coil 1 | Coil | Switch: throw to straight (edge-triggered) |
| Coil 2 | Coil | Switch: throw to curve (edge-triggered) |
| IR 0 | Input reg | Current commanded power 0..100 |
| IR 1 | Input reg | `MAX_POWER` constant |
| DI 0 | Discrete input | Train connected |
| DI 1 | Discrete input | Direction (0 = reverse, 1 = forward) |
| DI 2 | Discrete input | Switch position = straight (0 if unknown / mid-throw) |
| DI 3 | Discrete input | Switch position = curve (0 if unknown / mid-throw) |
| DI 4 | Discrete input | Switch controller online (LWT-driven) |

Coils 1/2 (M10) are the cross-protocol switch surface: coil write on
the outstation → outstation publishes an MQTT `cmd/throw` to
mosquitto → switch controller drives the Cube via BLE. Zeek sees the
coil write in `modbus.log` and the throw in `mqtt_publish.log` — but
`id.orig_h` on the MQTT side is the controller Pi, not the attacker.

## Switch — MQTT topics

`choochoo/switch/<switch_id>/…`:

| Topic | Retained | Direction | Payload |
|---|---|---|---|
| `cmd/throw` | no | publisher → controller | `{"action":"throw","direction":"forward|reverse"}` |
| `state` | **yes** | controller → subscribers | `SwitchState` — position, connected, last_throw_ts, cooldown_until_ts |
| `event` | no | controller → subscribers | `ThrowEvent` — direction + outcome (`ok` / `cooldown_rejected` / `ble_error`) |
| `discovery` | **yes** | controller → subscribers | `SwitchDiscovery` — capabilities, safety envelope, `online` (LWT-driven) |

**Motor safety.** Fixed-burst timer (250 ms at 130/255 power) + 2 s
cooldown. Constants live in `switch_protocol.py`. Every code path that
starts the motor guarantees a stop frame via `try/finally`.

**3-gear inversion.** sw1's mechanism has 3 gears between motor and
rack, so motor direction is inverted at the rack. On the wire,
`direction: "forward"` throws to **Straight**, `direction: "reverse"`
throws to **Curve**. Do not "fix" in code.

**Liveness — `discovery.online` is authoritative.** LWT-driven and
flips to `false` on ungraceful controller disconnect. `state.connected`
is a payload field about the *BLE link*; it's whatever the controller
last published and is stale after controller death. UI pill and Modbus
DI 4 both read `discovery.online`.

## Train — MQTT topics (legacy)

`choochoo/train/<train_id>/…`:

- `cmd/motor` — `{"direction": "forward|reverse", "power": 0-100}`
- `cmd/stop` — `{}`
- `cmd/light` — `{"brightness": 0-10}`
- `state` — retained; current direction / power / connection
- `discovery` — retained; device manifest

Under the event configuration the train runs Modbus, not MQTT — every
MQTT-mode entry point logs a deprecation warning. Kept in-repo for the
V-series IoT vulnerabilities.

## Attacker access

Attacker joins the LAN via DHCP on the switch. From their laptop:

```sh
# Discover services
nmap -sV -p 1-1024,1883,8000 192.168.88.0/24

# Read Modbus registers (unit 1)
mbpoll -a 1 -r 1 -t 4 -c 3 -1 192.168.88.250        # holding regs
mbpoll -a 1 -r 1 -t 3 -c 2 -1 192.168.88.250        # input regs
mbpoll -a 1 -r 1 -t 1 -c 5 -1 192.168.88.250        # discrete inputs

# Write throttle (M-series attacks live off writes)
mbpoll -a 1 -r 1 -t 4 192.168.88.250 42

# Snoop MQTT (unauthenticated broker)
mosquitto_sub -h 192.168.88.253 -t '#' -v

# Throw the switch directly (V-series)
mosquitto_pub -h 192.168.88.253 -t 'choochoo/switch/sw1/cmd/throw' -m 'forward'
```

Full attack progression in `VULNERABILITIES.md`.

## Local development (Mac)

For iterating without hardware, the workstation-hybrid layout is
supported: `web-modbus` + `mosquitto` in Docker Desktop, bare-metal
controllers on the Mac itself. See `docs/network-flow.html` and the
committed override at `docker-compose.override.session.yml.example`.
This path is intentionally minimal — the production topology is the
two-Pi setup above.

## Layout

```
.
├── Dockerfile                       # main controller / web image
├── docker-compose.real.yml          # web + mosquitto containers on the web-UI Pi
├── docker-compose.hardened.yml      # TLS + auth + ACL mosquitto (see "Security posture")
├── pyproject.toml + uv.lock         # uv-managed Python deps
├── src/choochoo/
│   ├── protocol.py                  # train MQTT schemas (legacy)
│   ├── switch_protocol.py           # switch MQTT schemas + safety envelope
│   ├── modbus_controller.py         # Modbus outstation (train + M10 switch surface)
│   ├── modbus_bridge.py             # Modbus master (used by web-modbus)
│   ├── modbus_map.py                # register/coil/DI addresses
│   ├── switch_controller.py         # MQTT-driven Circuit Cube switch controller
│   ├── mqtt_auth.py                 # env-driven auth + TLS for paho
│   ├── web.py + static/             # FastAPI UI: train + switch panels
│   ├── cli.py                       # `controller`, `switch-controller`, `web`, `send`, `switch-send`
│   ├── train/                       # BuWizzTrain (BLE) + FakeTrain (dev)
│   └── switch/                      # CircuitCubeSwitch (BLE) + FakeSwitch (dev)
├── deploy/                          # systemd unit templates
│   ├── choochoo-controller.service
│   ├── choochoo-switch-controller.service
│   ├── controller.env.example
│   └── switch-controller.env.example
├── scripts/
│   ├── pi-setup.sh                  # one-shot Pi installer
│   ├── bootstrap-hardened.sh        # generate TLS certs + creds
│   └── run-hardened.sh              # launch with per-role creds
├── docs/
│   └── network-flow.html            # screenshot-friendly topology diagram
├── VULNERABILITIES.md               # V/M/S attack catalog with Zeek hooks
└── tests/                           # pytest suite
```

## Environment variables

Controller Pi (`/etc/choochoo/controller.env`):

| Variable | Default | Meaning |
|---|---|---|
| `CHOOCHOO_PROTOCOL` | `mqtt` | `modbus` for the event; unset falls back to MQTT legacy |
| `CHOOCHOO_TRAIN` | `fake` | `buwizz` on the range; `fake` for CI/dev |
| `CHOOCHOO_BUWIZZ_NAME` | `BuWizz3` | BLE substring match |
| `CHOOCHOO_MODBUS_PORT` | `5020` | Set to `502` for range (standard Modbus, needs setcap) |
| `CHOOCHOO_MODBUS_BIND` | `0.0.0.0` | Outstation bind address |
| `CHOOCHOO_SWITCH_BROKER` | `localhost` | Web-UI Pi's IP on the range |
| `CHOOCHOO_SWITCH_BROKER_PORT` | `1883` | |
| `CHOOCHOO_SWITCH_ID` | `sw1` | Topic namespace |
| `CHOOCHOO_BUWIZZ_LED_BRIGHTNESS` | `25` | Onboard LED brightness 0..100 (subdue for demo rooms) |

Switch controller (`/etc/choochoo/switch-controller.env`):

| Variable | Default | Meaning |
|---|---|---|
| `CHOOCHOO_SWITCH_KIND` | `fake` | `circuit_cube` on the range |
| `CHOOCHOO_CUBE_NAME` | `Tenka` | BLE substring match — use full unique suffix (`TenkaBCFD` etc.) |
| `CHOOCHOO_CUBE_PORT` | `a` | Motor port on the Cube |
| `CHOOCHOO_SWITCH_ID` | `sw1` | Topic namespace |
| `CHOOCHOO_BROKER` | `localhost` | Web-UI Pi's IP on the range |
| `CHOOCHOO_BROKER_PORT` | `1883` | |

Web-modbus container (via compose override):

| Variable | Default | Meaning |
|---|---|---|
| `CHOOCHOO_PROTOCOL` | `modbus` | Set by base compose file |
| `CHOOCHOO_BROKER` | `host.docker.internal` | Override to controller Pi IP on the range |
| `CHOOCHOO_MODBUS_PORT` | `5020` | Override to `502` on the range |
| `CHOOCHOO_SWITCH_BROKER` | `mosquitto` | Compose network alias — leave alone |

## Security posture

Baseline is deliberately vulnerable — no auth, no TLS, `*` CORS on the
web UI, anonymous mosquitto. This is the state students attack.

A hardened profile exists (`docker-compose.hardened.yml`, TLS-only 8883,
per-role credentials, ACLs) as a "here's how you fix it" demo. Bootstrap:

```sh
./scripts/bootstrap-hardened.sh                 # once — certs + creds
docker compose -f docker-compose.hardened.yml up -d
./scripts/run-hardened.sh controller
```

Generated secrets live in `mosquitto/certs/` and `mosquitto/auth/`
(gitignored). See `VULNERABILITIES.md` for the full catalog.

## Troubleshooting

**`Not connected[AsyncModbusTcpClient 192.168.88.250:502]` on `web-modbus`.**
The web container can't reach the outstation. Check in order:
1. Is the outstation running? On controller Pi: `sudo ss -lntp | grep ':502'`
2. Did setcap take? `sudo getcap $(readlink -f ~/ZeekTrack/.venv/bin/python)` should show `cap_net_bind_service=ep`. If not, the outstation logs `[Errno 13] permission denied` in `journalctl`.
3. From the web-UI Pi: `nc -zv 192.168.88.250 502` — succeeded?

**`ConnectionRefusedError [Errno 111]` on either controller startup.**
Broker isn't reachable. Usually means:
- `CHOOCHOO_BROKER=localhost` on a controller when the broker is on the web-UI Pi (bug — use the LAN IP).
- The controller started before mosquitto did — restart it after the web-UI Pi is up.

**Switch drops BLE after a few seconds on the Pi.** Historically caused by BlueZ dropping idle links on the LL supervision timer. The current backend probes the link with periodic battery reads and has a 10s liveness watchdog; if you still see drops, `sudo btmon` on the controller Pi during a disconnect gives the definitive reason code (0x08 = timeout, 0x13 = remote user terminated).

**Multiple Cubes but only one connects.** `CHOOCHOO_CUBE_NAME` is a substring match. Setting it to bare `Tenka` picks one non-deterministically — use the unique `Tenka<HHHH>` suffix.

## Tests

```sh
uv run pytest
uv run ruff check
```
