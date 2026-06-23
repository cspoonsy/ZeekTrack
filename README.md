# ChooChoo

Dual-protocol control plane for a Lego Powered Up train, built as a
hands-on attack/defense cybersecurity training exercise. Same train, two
control planes that the trainer can flip between with a single flag:

- **IoT mode** (default): MQTT over a Mosquitto broker. Mirrors a
  consumer/SMB IoT deployment.
- **Enterprise mode**: Modbus/TCP. Mirrors industrial / OT control
  (rail wayside, building automation, water utilities). The controller
  is a Modbus outstation; the web UI is a Modbus master. **Zeek has a
  built-in Modbus analyzer** so defender tooling lights up out of the box.

Both modes drive the same physical train and are intentionally vulnerable in
their baseline configuration. See `VULNERABILITIES.md` for the catalog.

## Prerequisites

The fully containerized path needs **only Docker**. The host-mode and
Raspberry Pi paths additionally need **`uv`**.

- **Docker Desktop** (macOS / Windows) or Docker Engine + Compose v2 (Linux).
  Verify: `docker --version && docker compose version`.
- **`uv`** (only for the host / Pi paths):

  ```sh
  curl -LsSf https://astral.sh/uv/install.sh | sh
  ```

  uv handles the Python install, the venv, and the lockfile — you do *not*
  need a separate `python3` or `pip` setup.

- **`git`** to clone the repo.

For the real-train path on a Raspberry Pi, `scripts/pi-setup.sh` installs
the Linux-side prerequisites (bluez, build deps, `bluetooth` group
membership). Mac users with a Powered Up hub can also run BLE locally;
the terminal app needs Bluetooth permission (System Settings → Privacy
& Security → Bluetooth).

## Get the code

```sh
git clone <repo-url> choochoo && cd choochoo
```

(Substitute the actual URL once the repo exists.)

## Layout

```
.
├── Dockerfile                       # main controller / web image
├── docker-compose.yml               # Mosquitto broker only (legacy / host path)
├── docker-compose.hardened.yml      # TLS + auth + ACL Mosquitto
├── docker-compose.fake.yml          # full hardwareless stack (mqtt | modbus profiles)
├── pyproject.toml + uv.lock         # uv-managed Python deps
├── src/choochoo/
│   ├── protocol.py                  # MQTT topic names + Pydantic schemas
│   ├── controller.py                # MQTT controller (subscribes + drives train)
│   ├── modbus_controller.py         # Modbus/TCP outstation
│   ├── modbus_bridge.py             # Modbus master used by the web UI
│   ├── modbus_map.py                # point map (HR / coils / IRs / DIs)
│   ├── mqtt_auth.py                 # env-driven auth + TLS for paho clients
│   ├── web.py + static/             # FastAPI UI: serves both protocols
│   ├── cli.py                       # entry: `controller` / `web` / `send`
│   └── train/                       # FakeTrain (dev) + PoweredUpTrain (BLE)
├── tests/                           # pytest suite
├── attacker/                        # Kali container for virtual events
│   ├── Dockerfile
│   ├── cheatsheet.md                # brief tool list (shipped to trainees)
│   └── SOLUTIONS.md                 # full playbook (trainer-only, never in image)
├── noise/                           # background-traffic profile
│   ├── intranet/                    # nginx-served fake corporate portal
│   ├── share/                       # files for the SMB share
│   └── user/                        # workstation simulator
├── sensor/                          # Corelight Microsensor profile
│   ├── Dockerfile                   # installs the official package
│   ├── corelight-softsensor.conf    # default config (mounted into the container)
│   └── license/                     # gitignored drop-zone for your license file
├── mosquitto/
│   ├── config/                      # baseline broker config (anonymous)
│   ├── config-hardened/             # TLS + auth + ACL config
│   ├── auth/                        # generated passwords, gitignored
│   └── certs/                       # generated CA + server cert, gitignored
├── deploy/                          # systemd unit template for the Pi
├── scripts/
│   ├── pi-setup.sh                  # one-shot Pi installer
│   ├── bootstrap-hardened.sh        # generate certs + creds for hardened mode
│   └── run-hardened.sh              # launch with the right per-role creds
└── VULNERABILITIES.md               # full attack catalog (V1–V10 MQTT, M1–M9 Modbus)
```

If you cloned the repo on Windows, `git` may have stripped the executable
bit from the shell scripts; run `chmod +x scripts/*.sh attacker/*.sh` once
after cloning.

## Deployment matrix

|                | Hardwareless (FakeTrain)                 | Hardware (real BLE train)                                       |
|----------------|------------------------------------------|-----------------------------------------------------------------|
| **MQTT**       | 3 containers: web + mosquitto + controller-fake | 2 containers (web + mosquitto) + controller bare-metal on the Pi (BLE) |
| **Modbus**     | 2 containers: web + controller-fake      | 1 container (web) + controller bare-metal on the Pi (BLE)       |

## Quick start — fully containerized, no hardware

```sh
# Build + start in one shot. Add --profile attacker / --profile noise as needed.
docker compose -f docker-compose.fake.yml --profile mqtt   up --build -d
docker compose -f docker-compose.fake.yml --profile modbus up --build -d

# http://localhost:8000

docker compose -f docker-compose.fake.yml --profile mqtt   down
```

Subsequent `up -d` runs reuse the cached images; pass `--build` again only
when you've changed a Dockerfile or its build context.

The two profiles share the same image; only the topology and env vars differ.

### Adding background traffic (recommended for any demo)

Stack the `noise` profile to add a fake corporate intranet (`nginx`), an
SMB file share, and a workstation simulator that walks human-paced
HTTP/SMB/DNS/dashboard traffic in active/idle cycles:

```sh
docker compose -f docker-compose.fake.yml --profile mqtt --profile noise up --build -d
docker logs -f choochoo-user      # watch the simulator do its thing
```

The point is realism: Zeek will see normal HTTP/SMB/DNS traffic alongside
the train control plane, so the attacker's MQTT/Modbus probes have a
real baseline to stand out against. The intranet is browsable at
`http://intranet/` (from inside the network) and serves a fake corporate
portal; the SMB share `//fileshare/section7` holds a few documents.

`noise` stacks freely with `attacker`, so a fully populated session looks
like:

```sh
docker compose -f docker-compose.fake.yml \
  --profile mqtt --profile attacker --profile noise up -d
```

### Adding a Corelight Microsensor (defender side)

Stack the `sensor` profile to run an actual Corelight Microsensor in a
container. Zeek + Suricata logs land in a named volume, so trainees on
the defender side can run real detection logic against real traffic
instead of theoretical packets:

```sh
# Two prerequisites (both from Corelight, neither in the repo):
#  1. Package-repo auth token from https://my.corelight.cloud/
#  2. License file at sensor/license/corelight-license.txt

CORELIGHT_TOKEN=<your-token> docker compose -f docker-compose.fake.yml \
  --profile mqtt --profile noise --profile sensor up --build -d

docker exec -it choochoo-sensor bash
tail -f /var/corelight/logs/current/conn.log
```

See [`sensor/README.md`](sensor/README.md) for the full setup, the
caveats around bridge-network sniffing, and notes on enabling streaming
exporters (Splunk HEC, Kafka, JSON-over-TCP, Syslog).

### Adding Gravwell (SIEM destination)

Stack the `gravwell` profile to run Gravwell Community Edition next to
the sensor. The softsensor's JSON-over-TCP exporter (already enabled in
[`sensor/corelight-softsensor.conf`](sensor/corelight-softsensor.conf))
ships every Zeek log to Gravwell's `simple_relay` listener under the
`zeek` tag, so the defender side gets a real searchable UI instead of
`tail -f`:

```sh
# Drop a Community license at gravwell/license/gravwell.lic
# (free up to 13.5 GB/day from https://www.gravwell.io/community-edition).

CORELIGHT_TOKEN=<your-token> docker compose -f docker-compose.fake.yml \
  --profile mqtt --profile noise --profile sensor --profile gravwell up --build -d

# Web UI on http://localhost:8080 — default creds admin / changeme.
# Sample query (after a few minutes of traffic):
#   tag=zeek json _path | table _path id.orig_h id.resp_h
```

To redirect to a different SIEM, edit `Corelight::json_server` in
[`sensor/corelight-softsensor.conf`](sensor/corelight-softsensor.conf)
and `docker compose restart sensor`.

### Adding a Kali attacker box (virtual events)

Stack the `attacker` profile with whichever control plane you're demoing —
it puts a Kali container on the same Docker network with `nmap`,
`mosquitto-clients`, `mbpoll`, `pymodbus`, `tcpdump`, and a brief
tool-list cheatsheet:

```sh
docker compose -f docker-compose.fake.yml --profile mqtt --profile attacker up -d
docker exec -it choochoo-attacker bash
cat /opt/cheatsheet.md
```

The cheatsheet inside the container is intentionally minimal — it lists
the available tools and tells the trainee where they are on the network.
**No protocol names, no hostnames, no payloads, no source code.** The
trainee has to discover the attack surface from the wire, the way a real
LAN-side attacker would. The container is also **not** port-forwarded to
the host.

Trainer answer key (host-side, never inside the container):
- `attacker/SOLUTIONS.md` — suggested progression with concrete payloads
- `VULNERABILITIES.md` — full vulnerability catalog with Zeek detection hooks

## Quick start — host, no hardware (legacy path)

If you'd rather run the controller / web outside Docker (faster iteration):

```sh
docker compose up -d                     # Mosquitto only
uv run choochoo -v controller            # FakeTrain by default
uv run choochoo web                      # http://127.0.0.1:8000

# ad-hoc commands instead of the web UI:
uv run choochoo send motor forward 60
uv run choochoo send stop
```

`-v` is a group-level flag and goes *before* the subcommand.

## On the Raspberry Pi (real train, BLE)

The controller has to run **bare metal** on whatever host talks BLE — Docker
on macOS has no BLE passthrough, and on Linux it requires `--privileged` +
host networking, which we'd rather avoid. The Pi runs the controller; the
web UI (and broker, in MQTT mode) can run anywhere reachable, including
in a container alongside.

Two BLE backends are supported:

- `CHOOCHOO_TRAIN=powered_up` — Lego Powered Up SmartHub (88009) via `pylgbst`.
- `CHOOCHOO_TRAIN=buwizz` — BuWizz 3.0 / 3.0 Pro via direct `bleak` GATT.
  Train motor must be on **PU port 1**.

Manual one-shot:

```sh
uv sync --extra pi

# Lego Powered Up SmartHub:
CHOOCHOO_TRAIN=powered_up \
CHOOCHOO_HUB_NAME='Smart Hub' \
CHOOCHOO_BROKER=<broker-host> \
    uv run choochoo controller

# BuWizz 3.0 / 3.0 Pro (motor in port 1):
CHOOCHOO_TRAIN=buwizz \
CHOOCHOO_BUWIZZ_NAME='BuWizz3' \
CHOOCHOO_BROKER=<broker-host> \
    uv run choochoo controller
```

Reproducible Pi deploy (systemd):

```sh
git clone <repo> ~/choochoo && cd ~/choochoo
./scripts/pi-setup.sh
sudo $EDITOR /etc/choochoo/controller.env   # set broker host, hub name, etc.
sudo systemctl enable --now choochoo-controller
sudo journalctl -u choochoo-controller -f
```

The setup script installs system packages (bluez, build deps), adds the user
to the `bluetooth` group, installs `uv`, syncs dependencies with the `pi`
extra, and drops a templated systemd unit at
`/etc/systemd/system/choochoo-controller.service`. Re-running is idempotent.

`CHOOCHOO_HUB_NAME` defaults to `Smart Hub` (the factory default). If the
hub was renamed via the Lego Powered Up app, set this to the exact
advertised name. `CHOOCHOO_BUWIZZ_NAME` defaults to `BuWizz3` and works
the same way for BuWizz hubs renamed via their app. To find either:

```sh
uv run python -c "import asyncio, bleak; print(asyncio.run(bleak.BleakScanner.discover(timeout=8)))"
```

For Powered Up, look for the entry whose service includes
`00001623-1212-efde-1623-785feabcd123` (LEGO Wireless Protocol). For
BuWizz, look for service `500592d1-74fb-4481-88b3-9919b1676e93`.

## Switching between IoT and Enterprise mode

Both the controller and the web UI take a `--protocol` flag (or
`CHOOCHOO_PROTOCOL=mqtt|modbus`). They must agree.

```sh
# Enterprise / Modbus mode — no broker, controller listens on TCP/5020
CHOOCHOO_PROTOCOL=modbus uv run choochoo controller
CHOOCHOO_PROTOCOL=modbus uv run choochoo web
```

The web UI shows a colored **IOT / MQTT** or **ENTERPRISE / MODBUS** pill
in the header, and the network topology panel auto-relabels itself to
match. In Enterprise mode the broker disappears (Modbus is point-to-point).

### Modbus point map

| Address | Type | Meaning |
|---|---|---|
| HR 0 | Holding reg, signed int16 | Motor power, -100..100 (sign = direction) |
| HR 1 | Holding reg | Light brightness 0..10 |
| HR 2 | Holding reg | Operator-incremented command counter |
| Coil 0 | Coil | Emergency stop (write True to trip; latches back) |
| IR 0 | Input reg | Current commanded power 0..100 |
| IR 1 | Input reg | MAX_POWER constant |
| DI 0 | Discrete input | Train connected |
| DI 1 | Discrete input | Direction (0 = reverse, 1 = forward) |

Unit ID `1`. No auth, no TLS — same baseline posture as MQTT mode.

## Topics

- `choochoo/train/<train_id>/cmd/motor` — `{"direction": "forward|reverse", "power": 0-100}`
- `choochoo/train/<train_id>/cmd/stop` — `{}`
- `choochoo/train/<train_id>/cmd/light` — `{"brightness": 0-10}`
- `choochoo/train/<train_id>/state` — retained; current direction / power / connection
- `choochoo/train/<train_id>/discovery` — retained; device manifest (auto-discovery)

## Security posture

This system ships with **two profiles** so the trainer can flip between
"baseline" and "hardened" to demonstrate how each weakness is fixed at the
broker layer.

### Baseline (default)

Deliberately vulnerable. Anonymous Mosquitto on plaintext 1883/9001, web UI
on `0.0.0.0` with `*` CORS, retained discovery beacon, no auth anywhere.
Attackers run from a separate LAN host using `nmap`, `mosquitto_pub/sub`,
`curl`, Wireshark.

```sh
docker compose up -d
uv run choochoo controller
uv run choochoo web
```

### Hardened

TLS-only on 8883, no plaintext listener, per-role usernames + passwords,
ACLs scoped per role (controller / web / operator). Same client code —
auth + TLS are picked up from `CHOOCHOO_USER` / `CHOOCHOO_PASSWORD` /
`CHOOCHOO_TLS_CA` env vars by `mqtt_auth.py`.

```sh
./scripts/bootstrap-hardened.sh                 # one-time: certs + creds
docker compose -f docker-compose.hardened.yml up -d
./scripts/run-hardened.sh controller
./scripts/run-hardened.sh web --http-port 8000
./scripts/run-hardened.sh send motor forward 30
```

Generated secrets land in `mosquitto/certs/` and `mosquitto/auth/` and are
gitignored. Re-running bootstrap is idempotent; wipe both directories to
rotate everything.

See [`VULNERABILITIES.md`](VULNERABILITIES.md) for the full catalog of
baseline weaknesses, the suggested attacker progression, and the Zeek-side
detection hooks.

## Tests

```sh
uv run pytest
uv run ruff check
```
