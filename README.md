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

**Event posture.** The ChooChoo training event runs **Modbus** for the train
and **MQTT** for a separate track-switch device (Circuit Cubes Bluetooth
Bit — see the "Track switch" section below). The legacy MQTT train
controller stays in-repo as a demonstrable IoT surface and is still
covered by V1–V10 in `VULNERABILITIES.md`, but every entry point logs a
deprecation warning; operators running the event should use
`--protocol modbus`. The switch panel is always visible in the web UI
regardless of the train's protocol.

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
├── docker-compose.real.yml          # hardware stack: web/broker in containers, controller bare-metal
├── pyproject.toml + uv.lock         # uv-managed Python deps
├── src/choochoo/
│   ├── protocol.py                  # train MQTT topic names + Pydantic schemas
│   ├── switch_protocol.py           # switch MQTT topics + models + safety envelope
│   ├── controller.py                # train MQTT controller (subscribes + drives train)
│   ├── switch_controller.py         # switch MQTT controller (subscribes + drives Cube)
│   ├── modbus_controller.py         # Modbus/TCP outstation (train + switch surface)
│   ├── modbus_bridge.py             # Modbus master used by the web UI
│   ├── modbus_map.py                # point map (HR / coils / IRs / DIs, both devices)
│   ├── mqtt_auth.py                 # env-driven auth + TLS for paho clients
│   ├── web.py + static/             # FastAPI UI: train + switch panels, both protocols
│   ├── cli.py                       # `controller` / `switch-controller` / `web` / `send` / `switch-send`
│   ├── train/                       # FakeTrain (dev) + PoweredUpTrain + BuWizz backends
│   └── switch/                      # FakeSwitch (dev) + CircuitCubeSwitch (BLE) backends
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
└── VULNERABILITIES.md               # full attack catalog (V1–V10 MQTT train, M1–M10 Modbus, S1–S3 switch)
```

If you cloned the repo on Windows, `git` may have stripped the executable
bit from the shell scripts; run `chmod +x scripts/*.sh attacker/*.sh` once
after cloning.

## Deployment matrix

Two compose files, one per posture. Pick by whether you have a real
train on the table.

|                | Hardwareless — `docker-compose.fake.yml`                                                             | Hardware — `docker-compose.real.yml`                                                                                    |
|----------------|------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------|
| **MQTT train** | 3 containers: web-mqtt + mosquitto + controller-mqtt (legacy — `--profile legacy-web` for the web)   | 2 containers (web + mosquitto) + controller bare-metal on the host (BLE). Legacy — web is under `--profile legacy-web`. |
| **Modbus train** | 2 containers: web-modbus + controller-modbus                                                       | 1 container (web) + controller bare-metal on the host (BLE outstation)                                                  |
| **Switch (MQTT)** | Stacks on top of either train mode: mosquitto + switch-controller-mqtt (FakeSwitch inside compose) | mosquitto in container + switch controller bare-metal on the host (owns Cube BLE). Same host as the train's BLE radio.  |

The `.real.yml` file has no controller service on purpose: the
train controller has to run on whatever machine owns the BLE radio (a
Raspberry Pi, or a Mac / Linux workstation with Bluetooth), because
Docker Desktop on macOS has no BLE passthrough and Linux would need
`--privileged` + host networking to get one. The switch controller has
the same constraint — it owns the Circuit Cube's BLE handle. Both live
alongside each other bare-metal in real mode. The containers in
`.real.yml` reach the host train controller via
`host.docker.internal:5020` (Modbus) or by publishing 1883 on the host
loopback (MQTT); the bare-metal switch controller connects out to the
containerized mosquitto over the same host-loopback 1883.

**Event configuration.** Stack `--profile modbus --profile mqtt` on the
fake stack (or use `.real.yml` for hardware). The `mqtt` profile brings
up mosquitto and (on `.fake.yml`) the FakeSwitch controller, both
*without* the legacy MQTT web UI (that lives under `--profile
legacy-web`), so port 8000 is free for the Modbus web to bind. On
`.real.yml` the switch controller is bare-metal via the systemd unit
`choochoo-switch-controller.service` (see "On the Raspberry Pi" below);
the `mqtt` profile there only brings up mosquitto.

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
| `mosquitto`              | `mosquitto`    | 1883/tcp               | MQTT             | Anonymous broker (baseline profile). Shared by the legacy MQTT train AND the switch. |
| `controller-mqtt`        | *(default)*    | —                      | MQTT client      | Bridges MQTT ↔ train (legacy; deprecated for the event). Logs a deprecation warning on startup. |
| `switch-controller-mqtt` | *(default)*    | —                      | MQTT client      | Bridges MQTT ↔ track switch (Circuit Cubes Bit). FakeSwitch in `.fake.yml`; bare-metal on the host in `.real.yml` (owns Cube BLE). |
| `web-mqtt`               | *(default)*    | 8000/tcp               | HTTP             | FastAPI UI (MQTT-train mode). Under `--profile legacy-web` only. |
| `controller-modbus`      | `controller`   | 5020/tcp               | Modbus/TCP + MQTT client | Modbus outstation (unit ID 1). Under the event config it *also* speaks MQTT — subscribes to switch state/discovery on `mosquitto` and publishes ThrowCommands on coil writes (M10). `.fake.yml` only; under `.real.yml` the outstation runs on the host at `host.docker.internal:5020`. |
| `web-modbus`             | *(default)*    | 8000/tcp               | HTTP + MQTT client | FastAPI UI (Modbus mode). Talks Modbus to the outstation for the train AND MQTT to `mosquitto` for the switch panel. |
| `attacker`               | `attacker`     | —                      | shell / tools    | Kali box with `nmap`, `mosquitto-clients`, `mbpoll`, `pymodbus`, `tcpdump` |
| `intranet`               | `intranet`     | 80/tcp                 | HTTP             | Fake corporate portal (`http://intranet/`) |
| `fileshare`              | `fileshare`    | 139/tcp, 445/tcp       | SMB              | Guest-readable share `//fileshare/section7` |
| `user`                   | `workstation`  | —                      | client only      | Workstation traffic simulator |
| `zeek`                   | `zeek`         | —                      | pcap capture     | FOSS Zeek sniffs its own `eth0`, writes JSON logs to the `zeek-logs` volume |
| `vector`                 | `vector`       | —                      | file → TCP       | Tails `zeek-logs` volume, ships to `simple-relay:7777` |
| `simple-relay`           | `simple-relay` | 7777/tcp               | TCP (line JSON)  | Gravwell ingester — receives from Vector, forwards to `gravwell:4023` |
| `gravwell`               | `gravwell`     | 80/tcp, 4023/tcp       | HTTP + TCP       | SIEM: 80 = UI, 4023 = cleartext ingester backend |

### Data flow

The switch is reachable over two protocols simultaneously. A throw
initiated from any of the three surfaces below (web button, Modbus coil,
raw MQTT publish) ends up producing the same 5-byte ASCII BLE frame
(`dNNNc`) to the Cube. Same physical outcome, three attack surfaces.

**Train — MQTT path (legacy; deprecated for the event):**

```
                    ┌──────────────┐
     (from host) ───▶│   web-mqtt   │──MQTT──▶ ┌─────────────┐──▶ controller-mqtt ──▶ (train)
   http://:8000     │  :8000       │           │  mosquitto  │
                    └──────────────┘           │   :1883     │──MQTT──▶  attacker (docker exec)
                                               └─────────────┘
```

**Train — Modbus path (event config):**

```
                    ┌──────────────┐
     (from host) ───▶│   web-modbus │──Modbus/TCP──▶ controller-modbus:5020 ──▶ (train)
   http://:8000     │  :8000       │
                    └──────────────┘
```

**Switch — MQTT path (S1). Web button, `switch-send throw`, or attacker `mosquitto_pub`:**

```
   ┌───────────┐   POST /api/switch/throw    ┌─────────────┐   cmd/throw    ┌──────────────────────────┐
   │  browser  │────────────────────────────▶│  web-*      │───MQTT────────▶│  mosquitto :1883         │
   └───────────┘                             │  SwitchBridge│                └───────────┬──────────────┘
        ▲                                    └─────────────┘                             │
        │  view.online (via WebSocket)             ▲                                     │ cmd/throw
        │                                          │                                     ▼
        │        state + discovery (retained)      │                     ┌────────────────────────────┐
        └──────────────────────────────────────────┤                     │  switch-controller-mqtt    │
                                                   │                     │  (bare-metal in real mode) │
                                                   │                     └───────────────┬────────────┘
                                                   │                                     │ dNNNc
                                                   │        state + discovery            ▼
                                                   └────────────────────────────── (Circuit Cube via BLE)
```

**Switch — Modbus path (M10). Attacker writes coil 1 or 2 on the train outstation:**

```
   ┌───────────┐   Write-Single-Coil (FC 5)  ┌──────────────────┐  MQTT cmd/throw
   │  attacker │────────────────────────────▶│  controller-modbus│──────────────────▶ mosquitto :1883
   │  (mbpoll) │       coil 1 or 2 = True    │  (SwitchMirror)  │                     (as if from operator)
   └───────────┘                             └──────────────────┘                            │
                                                    ▲                                        │ cmd/throw
                                                    │  state + discovery                     ▼
                                                    │  → DI 2/3/4                 switch-controller-mqtt
                                                    └────────────────────────── ... ─▶ (Circuit Cube via BLE)
```

Key observation: on the Modbus path the outstation publishes the MQTT
throw *on the attacker's behalf* — a Zeek sensor listening on the broker
sees `id.orig_h = controller-modbus`, not the attacker's IP. Correlating
back to the real source requires joining `modbus.log` (coil write from
attacker) with `mqtt_publish.log` (throw from outstation) on timestamp.

**Controller liveness (LWT).** Both the switch controller's retained
`discovery` topic and its Last Will & Testament are the authoritative
liveness signal:

```
   switch-controller  ─── on connect ───▶ mosquitto: retain discovery {online: true}
                     ─── if ungraceful ─▶ mosquitto broadcasts LWT: discovery {online: false}
                                                        │
                                                        ▼
                             web-* SwitchBridge  ── view.online → UI pill
                             controller-modbus SwitchMirror ── DI_SWITCH_ONLINE

   The payload's `SwitchState.connected` field is NOT reliable for
   controller-liveness — it stays cached in retention with whatever value
   the controller last published, even after the controller dies. Both
   the UI pill and DI 4 read `discovery.online` instead.
```

**Zeek / SIEM ingest (unchanged; both switch surfaces are visible):**

```
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
| `CHOOCHOO_SWITCH_ID`      | `sw1`            | Track-switch identifier used in topic prefixes                     |
| `CHOOCHOO_SWITCH_KIND`    | `fake`           | Switch backend: `fake` / `circuit_cube`                            |
| `CHOOCHOO_CUBE_NAME`      | `Tenka`          | Substring match against the Circuit Cube's BLE advertised name     |
| `CHOOCHOO_CUBE_PORT`      | `a`              | Circuit Cube motor port for this switch: `a` / `b` / `c`           |
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

## Quick start — real hardware on Mac / Linux workstation (hybrid)

For local hardware demos where the developer machine has the BLE
radio — a Mac with Bluetooth permission, or a Linux box with `bluez`.
The BLE-owning **controllers run bare-metal on the host** (Docker on
macOS has no BLE passthrough; on Linux it needs `--privileged` + host
networking); everything else runs in containers via
`docker-compose.real.yml`. Each bare-metal controller needs its own
terminal.

**Prerequisites — install the BLE extra once:**

```sh
uv sync --extra pi
```

The extra is called `pi` for historical reasons but works fine on
macOS (bleak's CoreBluetooth backend). On macOS, grant your terminal
Bluetooth permission the first time it scans: System Settings →
Privacy & Security → Bluetooth.

Two BLE devices, two bare-metal processes. Neither is in
`docker-compose.real.yml` on purpose.

### Train — Modbus mode (Enterprise / OT)

```sh
# Terminal 1 — web UI in a container. It polls the host outstation at
# host.docker.internal:5020 for the train and reaches mosquitto for
# the switch panel (--profile mqtt below).
docker compose -f docker-compose.real.yml --profile modbus up --build -d

# Terminal 2 — train controller bare-metal. Owns the BuWizz BLE
# radio, hosts the Modbus outstation on 0.0.0.0:5020, and also
# subscribes to the switch broker so its M10 coil handlers work
# (see the event-configuration section below).
CHOOCHOO_PROTOCOL=modbus \
CHOOCHOO_TRAIN=buwizz \
CHOOCHOO_BUWIZZ_NAME='BuWizz3' \
CHOOCHOO_SWITCH_BROKER=localhost \
    uv run choochoo -v controller
```

Open <http://localhost:8000>. When the controller logs
`connected to BuWizz at <mac-addr>` and the outstation starts
responding to polls, the header pill flips to **BLE • Connected**
(green) and the topology line linking the controller to the train
turns solid green. If the pill stays at `BLE • …`, the web
container can't reach the host outstation — see the troubleshooting
sub-section below.

### Train — MQTT mode (legacy IoT)

```sh
# Terminal 1 — Mosquitto broker + web UI in containers. The broker
# publishes 1883 on the host loopback so the bare-metal controller
# can reach it at localhost:1883.
docker compose -f docker-compose.real.yml --profile mqtt --profile legacy-web up --build -d

# Terminal 2 — train controller bare-metal.
CHOOCHOO_TRAIN=buwizz \
CHOOCHOO_BUWIZZ_NAME='BuWizz3' \
CHOOCHOO_BROKER=localhost \
    uv run choochoo -v controller
```

The legacy MQTT web UI is under `--profile legacy-web` so it doesn't
collide with `web-modbus` on host port 8000.

### Track switch — MQTT (any train mode)

The switch is always MQTT-only and always runs bare-metal on the
host. It reaches the containerized `mosquitto` at `localhost:1883`
(the broker publishes on the host loopback under both `--profile mqtt`
and `--profile modbus`, provided `--profile mqtt` is included).

```sh
# Terminal 3 — switch controller bare-metal. Owns the Circuit Cube
# BLE handle. Connects out to the containerized broker.
CHOOCHOO_SWITCH_KIND=circuit_cube \
CHOOCHOO_CUBE_NAME=Tenka \
CHOOCHOO_CUBE_PORT=a \
CHOOCHOO_BROKER=localhost \
    uv run choochoo -v switch-controller
```

When it logs `connected to Cube at <addr>` and `connected rc=Success,
subscribing to choochoo/switch/sw1/cmd/+`, the "Track switch" panel
in the web UI flips its liveness pill to **Switch · Connected**
(green). The retained state also updates on every throw, so the
position pill (Straight / Curve) reflects the last commanded
direction.

Ad-hoc throw from a fourth terminal (useful for verifying without
clicking the UI):

```sh
uv run choochoo switch-send throw forward   # wire direction (see mapping notes)
```

### Event configuration — Modbus train + MQTT switch stacked

The ChooChoo event runs the train under Modbus and the switch under
MQTT. On the workstation:

```sh
# Terminal 1 — containers: mosquitto + web-modbus.
docker compose -f docker-compose.real.yml \
    --profile modbus --profile mqtt up --build -d

# Terminal 2 — bare-metal train outstation. CHOOCHOO_SWITCH_BROKER
# lets the outstation's SwitchMirror publish MQTT throws when a
# Modbus master writes coil 1 or coil 2 (M10).
CHOOCHOO_PROTOCOL=modbus \
CHOOCHOO_TRAIN=buwizz \
CHOOCHOO_BUWIZZ_NAME='BuWizz3' \
CHOOCHOO_SWITCH_BROKER=localhost \
    uv run choochoo -v controller

# Terminal 3 — bare-metal switch controller.
CHOOCHOO_SWITCH_KIND=circuit_cube \
CHOOCHOO_CUBE_NAME=Tenka \
CHOOCHOO_CUBE_PORT=a \
CHOOCHOO_BROKER=localhost \
    uv run choochoo -v switch-controller
```

Web UI at <http://localhost:8000>. Both surfaces (train + switch)
should show connected pills once both bare-metal processes are up.

### Stacking defender / attacker / noise

Same `--profile` flags as `.fake.yml`:

```sh
docker compose -f docker-compose.real.yml \
    --profile modbus --profile mqtt \
    --profile attacker up -d
```

On the physical RaspPi box:
```sh
./scripts/noise-scripts/start.sh
```

And to tear down:
```sh
./scripts/noise-scripts/stop.sh
```

Caveat for **Modbus + Zeek**: the outstation lives on the host, not
inside Docker's netns, so the `sensor` profile can't see the Modbus
wire under `.real.yml`. For real Modbus defender visibility on the
physical train, run Zeek on the host directly (or mirror the switch
port into a Zeek box on the same LAN).

### Troubleshooting the hybrid setup

**Pill stays on `BLE • …` forever.** The web container's ModbusBridge
can't reach the host outstation. Check, in order:

```sh
# 1. Is the outstation actually bound on the host?
lsof -nP -iTCP:5020 -sTCP:LISTEN

# 2. Only ONE controller instance should be listed. A stale process
#    from a previous run will silently prevent the new one from binding.
ps aux | grep -i choochoo | grep -v grep

# 3. Can the web container reach the host?
docker exec choochoo-web-modbus-real python3 -c \
    "import socket; s=socket.socket(); s.settimeout(2); \
     s.connect(('host.docker.internal',5020)); print('tcp ok')"

# 4. Watch the bridge logs live for pymodbus errors.
docker logs -f choochoo-web-modbus-real
```

If step 3 fails on Linux and `host.docker.internal` doesn't resolve,
`docker-compose.real.yml` already sets
`extra_hosts: "host.docker.internal:host-gateway"`; if you still see
resolution failures, replace it with the Mac / Linux LAN IP.

**`ModuleNotFoundError: No module named 'bleak'`** when starting the
controller — you forgot `uv sync --extra pi`.

**BuWizz debug spam floods the terminal** (`peripheral_didUpdateValueForCharacteristic_error_`
lines). These are CoreBluetooth's notification-callback selector names,
**not** errors — the trailing `error_` is just Objective-C's parameter
slot. Drop the `-v` flag to quiet them.

**Switch panel stays on "Switch · …" or "Switch · Offline".** The web
container's SwitchBridge can't see the switch controller's retained
discovery beacon. Check:

```sh
# 1. Is the bare-metal switch controller running?
ps aux | grep 'switch-controller' | grep -v grep

# 2. Can the web container reach mosquitto? (mosquitto is only in the
#    compose network under --profile mqtt — if the profile isn't
#    active, no broker exists.)
docker exec choochoo-web-modbus-real python3 -c \
    "import socket; s=socket.socket(); s.settimeout(2); \
     s.connect(('mosquitto',1883)); print('tcp ok')"

# 3. Is the switch controller actually connected to the broker?
docker exec choochoo-mosquitto-real mosquitto_sub \
    -t 'choochoo/switch/+/discovery' -C 1 -W 2
# Expect a JSON blob with online:true. If online:false, the LWT
# fired — the controller crashed or lost broker connectivity.
```

**Switch controller finds no BLE device.** The Cube's advertised name
must contain the `CHOOCHOO_CUBE_NAME` substring (default `Tenka`).
Vendor ships each Cube as `Tenka<4-char-suffix>` — the default matches
any of them. If you renamed it via the vendor app, set the env var to
match. To list what's advertising nearby:

```sh
uv run python -c "import asyncio, bleak; print(asyncio.run(bleak.BleakScanner.discover(timeout=8)))"
```

**Switch throws visible in the UI but the motor doesn't move.** The
controller likely lost its BLE handle (macOS CoreBluetooth quirk after
long idle periods). The reconnect loop will recover on its own within
~10 s; watch the switch-controller terminal for a fresh `connected to
Cube at <addr>` log line. If it doesn't recover, restart the process.

## Quick start — host, no hardware (legacy path)

If you'd rather run the controller / web outside Docker with the
FakeTrain backend (fastest inner loop for code changes):

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
sudo $EDITOR /etc/choochoo/controller.env         # train: broker host, hub name, protocol
sudo $EDITOR /etc/choochoo/switch-controller.env  # switch: cube name, port, switch id
sudo systemctl enable --now choochoo-controller choochoo-switch-controller
sudo journalctl -u choochoo-controller -u choochoo-switch-controller -f
```

The setup script installs system packages (bluez, build deps), adds the user
to the `bluetooth` group, installs `uv`, syncs dependencies with the `pi`
extra, and drops two templated systemd units at
`/etc/systemd/system/choochoo-controller.service` (the train — MQTT or
Modbus outstation depending on env) and
`/etc/systemd/system/choochoo-switch-controller.service` (the track switch
— MQTT). Re-running is idempotent.

### Event configuration (Modbus train + MQTT switch)

For the ChooChoo training event the whole stack lives on the Pi:

1. **Bare-metal (BLE-owning) processes** — the two systemd units above.
   Each owns one BLE peer and reconnects automatically on power-cycle.
   - `choochoo-controller.service` — Modbus outstation on `0.0.0.0:5020`
     driving the BuWizz. Config via `/etc/choochoo/controller.env`; the
     example file has a commented Modbus block ready to uncomment.
   - `choochoo-switch-controller.service` — MQTT client driving the
     Circuit Cube. Config via `/etc/choochoo/switch-controller.env`.
2. **Containerized surfaces** — everything else:
   ```sh
   docker compose -f docker-compose.real.yml \
       --profile modbus --profile mqtt up -d
   ```
   `mqtt` brings up mosquitto (both the bare-metal switch controller and
   the containerized web-modbus point at it). `modbus` brings up the
   operator's web UI. `web-mqtt` is on a separate `legacy-web` profile
   so it doesn't collide with `web-modbus` on host port 8000.

Stack `--profile attacker`, `--profile noise`, `--profile sensor`,
`--profile gravwell` alongside for trainee attack surfaces, background
traffic, and defender tooling. All four match how they're used in
`docker-compose.fake.yml`.

The web UI is at `http://<pi>:8000`. Zeek's Modbus and MQTT analyzers
both light up under the event configuration: `modbus.log` covers M1–M10
(train HRs/coils + M10 switch throw), `mqtt_publish.log` covers S1–S3
(switch commands + retained-topic recon + LWT-driven liveness).

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

A second pill next to it — **BLE • Connected** (green, pulsing) /
**BLE • Disconnected** (red) / **BLE • …** (muted, waiting on first
state) — reflects the controller-to-train link. It reads the same
`connected` bit that flows through the state channel (MQTT retained
`state` topic, or the Modbus `DI_CONNECTED` discrete input), so it works
identically in both control planes. The topology diagram's
controller↔train segment recolors to match.

### Modbus point map

| Address | Type | Meaning |
|---|---|---|
| HR 0 | Holding reg, signed int16 | Motor power, -100..100 (sign = direction) |
| HR 1 | Holding reg | Light brightness 0..10 |
| HR 2 | Holding reg | Operator-incremented command counter |
| Coil 0 | Coil | Emergency stop (write True to trip; latches back) |
| Coil 1 | Coil | Switch: throw to straight (write True; latches back) |
| Coil 2 | Coil | Switch: throw to curve (write True; latches back) |
| IR 0 | Input reg | Current commanded power 0..100 |
| IR 1 | Input reg | MAX_POWER constant |
| DI 0 | Discrete input | Train connected |
| DI 1 | Discrete input | Direction (0 = reverse, 1 = forward) |
| DI 2 | Discrete input | Switch position = straight (0 if unknown / mid-throw) |
| DI 3 | Discrete input | Switch position = curve (0 if unknown / mid-throw) |
| DI 4 | Discrete input | Switch controller online (LWT-driven; 0 if never seen) |

Unit ID `1`. No auth, no TLS — same baseline posture as MQTT mode.

The switch coils/DIs are populated by the Modbus outstation acting as an
MQTT client to the switch broker (a bridge from OT to IoT that mirrors
how a real rail HMI unifies protocols). Env vars: `CHOOCHOO_SWITCH_BROKER`
(default `localhost`), `CHOOCHOO_SWITCH_BROKER_PORT` (default `1883`),
`CHOOCHOO_SWITCH_ID` (default `sw1`).

## Topics

- `choochoo/train/<train_id>/cmd/motor` — `{"direction": "forward|reverse", "power": 0-100}`
- `choochoo/train/<train_id>/cmd/stop` — `{}`
- `choochoo/train/<train_id>/cmd/light` — `{"brightness": 0-10}`
- `choochoo/train/<train_id>/state` — retained; current direction / power / connection
- `choochoo/train/<train_id>/discovery` — retained; device manifest (auto-discovery)

### Track switch (BLE via Circuit Cubes)

A second BLE device — a Circuit Cubes Bluetooth Bit — drives a Lego
gear-rack track switch. The switch controller is a separate process that
runs alongside the train controller; both share the same broker. The
switch is reachable from three surfaces (MQTT, Modbus coil, web button)
and all three end up at the same BLE frame on the wire.

**Topics** (`choochoo/switch/<switch_id>/…`):

| Topic | Retained? | Direction | Payload |
|---|---|---|---|
| `cmd/throw` | no | publisher → controller | `{"action":"throw","direction":"forward|reverse"}` |
| `state` | **yes** | controller → subscribers | `SwitchState` — position, connected, last_throw_ts, cooldown_until_ts |
| `event` | no | controller → subscribers | `ThrowEvent` — direction + outcome (`ok` / `cooldown_rejected` / `ble_error`) + ts |
| `discovery` | **yes** | controller → subscribers | `SwitchDiscovery` — capabilities + safety envelope + `online` flag. LWT-driven. |

**Motor safety.** The switch motor burns out if held on. The controller
enforces a bounded-burst timer (250 ms) at fixed power (130/255), plus a
2 s cooldown per switch. Values live as constants in `switch_protocol.py`
— retune if your gear ratio, rack length, or motor differs from the
reference sw1 setup. Every code path that writes a start frame guarantees
a stop frame via `try/finally`, so an interrupted throw still stops the
motor.

**Controller liveness — `discovery.online` vs `state.connected`.** The
controller publishes two retained payloads with overlapping-looking
booleans:

- `discovery.online` — set to `true` on the controller's initial connect,
  and the controller registers a Last Will & Testament with the broker
  that flips it to `false` on ungraceful disconnect. This is the
  **authoritative controller-liveness signal**. Both the web UI's pill
  and the Modbus `DI_SWITCH_ONLINE` DI read it.
- `state.connected` — a payload field the controller writes about **its
  own BLE link to the Cube**. It's whatever the controller last published;
  when the controller dies uncleanly, the retained value stays true forever.
  Do NOT use this to decide whether the controller is alive.

**3-gear inversion.** The mechanism has 3 gears between the motor and
the rack, so motor direction is inverted at the rack. On the wire,
`direction: "forward"` throws the switch to the **Straight** position,
and `direction: "reverse"` throws to **Curve**. Every planned switch
uses this mechanism; the mapping is a fixed system invariant. The web
UI and Modbus outstation both know about it and label buttons/coils
accordingly (`Throw to Straight` ↔ coil 1 ↔ wire `forward`).

Run bare-metal alongside the train controller (BLE is host-only):

```sh
CHOOCHOO_SWITCH_KIND=circuit_cube \
CHOOCHOO_CUBE_NAME=Tenka \
CHOOCHOO_CUBE_PORT=a \
    uv run choochoo -v switch-controller
```

Ad-hoc throw from any host:

```sh
# Wire direction (matches the MQTT payload).
uv run choochoo switch-send throw forward   # → Straight (rack backward)
uv run choochoo switch-send throw reverse   # → Curve (rack forward)
```

**Modbus surface (M10).** The Modbus outstation also carries the switch.
Coils 1 (`throw to straight`) and 2 (`throw to curve`) are edge-triggered
throw commands; DIs 2/3/4 mirror position + controller online. The
outstation subscribes to the same MQTT topics as the web bridge and
publishes ThrowCommands on coil writes — a Modbus master doesn't need
to speak MQTT to throw the switch. See `VULNERABILITIES.md` (M10) for
the attack pattern and Zeek detection hooks.

**Deferred: BLE stale-handle reconnect.** After long idle periods on
macOS (~5 h observed), `bleak`'s cached service handles go stale and
the next `write_gatt_char` raises "Service Discovery has not been
performed yet". The throw returns `outcome: "ble_error"`, and the
controller doesn't currently reconnect on its own. Workaround: restart
the switch controller (`Ctrl-C`, re-run the command above). See the
"Deferred" section of `docs/superpowers/specs/2026-07-27-modbus-switch-surface.md`
for the proper fix.

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
