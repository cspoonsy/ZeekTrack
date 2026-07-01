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
├── zeek/                            # FOSS Zeek NSM (sensor profile)
│   ├── Dockerfile                   # zeek/zeek:latest + our site policy
│   └── local.zeek                   # loads MQTT + Modbus analyzers, JSON output
├── vector/                          # Zeek → Gravwell shipper (sensor profile)
│   └── vector.yaml                  # tails zeek-logs volume, TCP sink to gravwell:7777
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

## Networking reference

All containers share the default Docker bridge network `choochoo_default`
(created automatically by Compose from the project name). Inside that
network, services address each other by **service name** — the compose
`hostname:` field makes each name resolve via Docker's embedded DNS.
Only the ports in the "Host" column below are reachable from outside
the network.

### What the host binds

| Purpose                       | Host URL / endpoint             | Container         | Container port | Profile     |
|-------------------------------|---------------------------------|-------------------|----------------|-------------|
| Web UI (both control planes)  | `http://localhost:8000`         | `choochoo-web-*`  | 8000/tcp       | `mqtt` / `modbus` |
| Gravwell UI                   | `http://localhost:8080`         | `choochoo-gravwell` | 80/tcp       | `gravwell`  |

Nothing else on the host is published. The Mosquitto broker, Modbus
outstation, Kali attacker, Zeek sensor, Vector shipper, and internal
noise services are all **only reachable from inside** the compose
network, on purpose — trainees who need to reach the broker or the
Modbus port do so from the `attacker` container (`docker exec -it
choochoo-attacker bash`), which mirrors a LAN-side adversary.

### Internal service map (compose network)

Addressable via the hostname shown, from any other container on the
same compose network:

| Service (compose name)   | Hostname (DNS) | Container port(s)      | Speaks           | Purpose |
|--------------------------|----------------|------------------------|------------------|---------|
| `mosquitto`              | `mosquitto`    | 1883/tcp               | MQTT             | Anonymous broker (baseline profile) |
| `controller-mqtt`        | *(default)*    | —                      | MQTT client      | Bridges MQTT ↔ train |
| `web-mqtt`               | *(default)*    | 8000/tcp               | HTTP             | FastAPI UI (MQTT mode) |
| `controller-modbus`      | `controller`   | 5020/tcp               | Modbus/TCP       | Modbus outstation (unit ID 1) |
| `web-modbus`             | *(default)*    | 8000/tcp               | HTTP             | FastAPI UI (Modbus mode) |
| `attacker`               | `attacker`     | —                      | shell / tools    | Kali box with `nmap`, `mosquitto-clients`, `mbpoll`, `pymodbus`, `tcpdump` |
| `intranet`               | `intranet`     | 80/tcp                 | HTTP             | Fake corporate portal (`http://intranet/`) |
| `fileshare`              | `fileshare`    | 139/tcp, 445/tcp       | SMB              | Guest-readable share `//fileshare/section7` |
| `user`                   | `workstation`  | —                      | client only      | Workstation traffic simulator |
| `zeek`                   | `zeek`         | —                      | pcap capture     | FOSS Zeek sniffs its own `eth0`, writes JSON logs to the `zeek-logs` volume |
| `vector`                 | `vector`       | —                      | file → TCP       | Tails `zeek-logs` volume, ships to `simple-relay:7777` |
| `simple-relay`           | `simple-relay` | 7777/tcp               | TCP (line JSON)  | Gravwell ingester — receives from Vector, forwards to `gravwell:4023` |
| `gravwell`               | `gravwell`     | 80/tcp, 4023/tcp       | HTTP + TCP       | SIEM: 80 = UI, 4023 = cleartext ingester backend |

### Data flow

```
                    ┌──────────────┐
     (from host) ───▶│   web-mqtt   │──MQTT──▶ ┌─────────────┐──▶ controller-mqtt ──▶ (train)
   http://:8000     │  :8000       │           │  mosquitto  │
                    └──────────────┘           │   :1883     │──MQTT──▶  attacker (docker exec)
                                               └─────────────┘

                    ┌──────────────┐
     (from host) ───▶│   web-modbus │──Modbus/TCP──▶ controller-modbus:5020 ──▶ (train)
   http://:8000     │  :8000       │
                    └──────────────┘

                    (sniff eth0)
   any traffic  ──▶ zeek ──▶ /logs volume ──▶ vector ──TCP:7777──▶ simple-relay ──TCP:4023──▶ gravwell ──▶ UI :8080
```

### Environment variables (name → default → meaning)

Client-side (controller / web / send):

| Variable                  | Default          | Meaning                                                            |
|---------------------------|------------------|--------------------------------------------------------------------|
| `CHOOCHOO_PROTOCOL`       | `mqtt`           | `mqtt` (broker) or `modbus` (TCP outstation)                       |
| `CHOOCHOO_BROKER`         | `localhost`      | Broker hostname (MQTT mode) or Modbus outstation host (Modbus mode) |
| `CHOOCHOO_BROKER_PORT`    | `1883` / `8883`  | Broker port; hardened profile flips to 8883                        |
| `CHOOCHOO_MODBUS_PORT`    | `5020`           | Modbus/TCP port on the outstation                                  |
| `CHOOCHOO_MODBUS_BIND`    | `0.0.0.0`        | Bind address for the Modbus outstation                             |
| `CHOOCHOO_TRAIN_ID`       | `t1`             | Train identifier used in topic prefixes                            |
| `CHOOCHOO_TRAIN`          | `fake`           | Train backend: `fake` / `powered_up` / `buwizz`                    |
| `CHOOCHOO_HUB_NAME`       | `Smart Hub`      | BLE-advertised name of the Powered Up hub                          |
| `CHOOCHOO_BUWIZZ_NAME`    | `BuWizz3`        | BLE-advertised name of the BuWizz hub                              |
| `CHOOCHOO_USER` / `_PASSWORD` / `_TLS_CA` | *(unset)* | Broker auth + TLS for the hardened profile             |

Noise-simulator (`user` service):

| Variable                  | Default                         | Meaning                                       |
|---------------------------|---------------------------------|-----------------------------------------------|
| `CHOOCHOO_DASHBOARD`      | `http://web-mqtt:8000`          | Dashboard the simulator polls                 |
| `CHOOCHOO_INTRANET`       | `http://intranet`               | Fake corporate portal URL                     |
| `CHOOCHOO_FILESHARE_HOST` | `fileshare`                     | SMB server hostname                           |
| `CHOOCHOO_FILESHARE_NAME` | `section7`                      | Share name                                    |

### Ports at a glance

| Port | Where           | Protocol       | Reachable from                        |
|------|-----------------|----------------|---------------------------------------|
| 8000 | host            | HTTP           | Anywhere on the host LAN              |
| 8080 | host            | HTTP           | Anywhere on the host LAN (Gravwell UI) |
| 1883 | mosquitto       | MQTT           | Compose network only (baseline)       |
| 8883 | mosquitto       | MQTT + TLS     | Compose network only (hardened)       |
| 5020 | controller      | Modbus/TCP     | Compose network only                  |
| 7777 | simple-relay    | TCP (line JSON) | Compose network only (from `vector`) |
| 4023 | gravwell        | TCP (ingester) | Compose network only (from `simple-relay`) |
| 80   | intranet        | HTTP           | Compose network only                  |
| 139, 445 | fileshare   | SMB            | Compose network only                  |

**BLE (real train only)** — the Powered Up SmartHub and BuWizz Pro advertise
over Bluetooth Low Energy; no IP addresses or ports are involved. The
Pi / Mac running the controller must own the BLE radio.
`00001623-1212-efde-1623-785feabcd123` is the LEGO Wireless Protocol
service UUID; `500592d1-74fb-4481-88b3-9919b1676e93` is the BuWizz
service UUID.

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

### Adding Zeek (defender side)

Stack the `sensor` profile to run FOSS **Zeek** in a container alongside
a **Vector** log-shipper sidecar. Zeek writes JSON logs
(`conn`, `dns`, `http`, `ssl`, `mqtt`, `modbus`, `files`, ...) into a
shared volume; Vector tails those files and, when the `gravwell` profile
is also up, streams each line to Gravwell over plain TCP. No license, no
vendor auth token, no account required.

```sh
docker compose -f docker-compose.fake.yml \
  --profile mqtt --profile noise --profile sensor up --build -d

# Tail the raw JSON logs directly:
docker exec -it choochoo-zeek sh -c 'tail -F /logs/conn.log'
docker exec -it choochoo-zeek sh -c 'tail -F /logs/modbus.log'
```

Bridge-network caveat: on the default Docker bridge, `eth0` only sees
broadcast + the sensor's own traffic, not east-west between siblings.
For a full defender view of container-to-container traffic, deploy on a
host with a SPAN/mirror port and run the sensor with
`network_mode: host` pointed at the mirror interface.

To swap Gravwell for a different SIEM later (or dual-ship), edit the
`sinks:` block in [`vector/vector.yaml`](vector/vector.yaml). To load
additional Zeek analyzers or tune site policy, edit
[`zeek/local.zeek`](zeek/local.zeek).

### Adding Gravwell (SIEM destination)

Stack the `gravwell` profile to run Gravwell Community Edition next to
the Vector shipper. Vector ships every Zeek log line to Gravwell's
`simple_relay` listener under the `zeek` tag, so the defender side gets
a real searchable UI instead of `tail -f`.

**One-time Gravwell setup (first launch only):**

1. Grab a free Community license from
   <https://www.gravwell.io/community-edition> (13.5 GB/day, no expiry,
   registration required). Save the key somewhere handy — you'll paste
   it in step 4.
2. Start the profile:
   ```sh
   docker compose -f docker-compose.fake.yml \
     --profile mqtt --profile noise --profile sensor --profile gravwell up --build -d
   ```
3. Open <http://localhost:8080>. On first launch Gravwell walks you
   through an EULA + license activation flow.
4. Accept the EULA, paste your license key, then log in with default
   creds `admin` / `changeme` — **change the admin password immediately**
   at Profile → Change Password.

Both the license and the admin password persist in the
`choochoo_gravwell-storage` Docker volume, so subsequent `up -d` runs
skip the wizard. Nothing license-related lives in the repo tree — the
key file never touches disk in the working directory (and the
`.gitignore` guards `*.lic` / `*.license` regardless, in case a future
config change bind-mounts one).

To reset Gravwell to a factory state (re-run the EULA + license flow):
```sh
docker compose -f docker-compose.fake.yml --profile gravwell down
docker volume rm choochoo_gravwell-storage choochoo_gravwell-log
```

Sample queries once traffic is flowing. Gravwell's pipeline is strict
about extraction — every field you reference later must appear in the
first `json` module call. Wrap field names with dots in quotes:

```gravwell
# All Zeek events, one row per record, with the log stream label:
tag=zeek json "_path" "id.orig_h" "id.resp_h" "id.resp_p"
    | table _path id.orig_h id.resp_h id.resp_p

# Any client publishing an MQTT command (attacker-style behavior):
tag=zeek json "_path"=="mqtt_publish" "id.orig_h" topic payload
    | table _write_ts id.orig_h topic payload

# MQTT CONNECT events — spot rogue clients, empty client IDs:
tag=zeek json "_path"=="mqtt_connect" "id.orig_h" client_id connect_status
    | table _write_ts id.orig_h client_id connect_status
```

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
