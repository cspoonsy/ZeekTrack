# ChooChoo Project — Full Handoff Writeup

## What This Project Is

**ChooChoo** is a DefCon-style live hacking demo built around a physical model train. Attendees are given network access to a live Modbus TCP + MQTT control network and can discover, attack, and take control of the train in real time. A Corelight Microsensor captures all traffic; Gravwell dashboards show the attack progression live for the audience.

---

## Physical Network (192.168.88.x)

| IP | Role |
|----|------|
| 192.168.88.246 | Admin Pi — runs the operator control panel (admin / corelight) |
| 192.168.88.249 | Web-Modbus Pi — authorized Modbus master; proxies web UI commands to train |
| 192.168.88.250 | Modbus outstation (PLC) — listens TCP:502, controls train motor/switch |
| 192.168.88.251 | Corelight Microsensor — all-in-one Zeek + Gravwell (corelight/corelight) |
| 192.168.88.253 | Web-Modbus + MQTT broker Pi — runs train stack Docker containers (analyst/corelight) |

---

## Protocol Architecture

- **Train control:** Exclusively Modbus TCP (port 502). The web UI on .253 writes to .250.
- **Switch control:** MQTT only, topic `sw1/cmd/throw`, broker on .253.
- `.249` is the authorized Modbus master (not an attacker). All dashboards filter it out with `grep -v "192.168.88.249"`.
- **Infra filter pattern** for all dashboard queries: `grep -v "192.168.88.249" | grep -v "192.168.88.253"` (and add `.250`, `.251` for attacker-identity queries).

---

## Modbus Register Map

```
WRITE_MULTIPLE_REGISTERS to addr 0  → power command (signed int16, 0-100)
WRITE_SINGLE_COIL                   → e-stop
READ_INPUT_REGISTERS RESPONSE       → values = "power,max_power"
READ_DISCRETE_INPUTS RESPONSE       → values = "connected,direction,sw_straight,sw_curve,sw_online,F,F,F"
  position 0 = DI0: train connected (T/F)
  position 1 = DI1: direction (T=forward)
  position 2 = DI2: switch at straight
  position 3 = DI3: switch at curve
  position 4 = DI4: switch controller online
```

---

## Corelight Microsensor — Gravwell

- **URL:** http://192.168.88.251 — **creds: admin / changeme**
- **Version:** Gravwell 5.8.6 ("Andrew Bird")
- **Tag schema:** per-log tags (`corelight_conn`, `corelight_modbus`, `corelight_modbus_detailed`, `corelight_mqtt_publish`, `corelight_mqtt_subscribe`, `corelight_mqtt_connect`, `corelight_http`, `corelight_notice`). NOT `tag=zeek`.

### Dashboard IDs (live)

| ID | Name |
|----|------|
| 137856853281928 | ChooChoo — Live Feed [15m] (Spoiler-Free) |
| 206695622031598 | ChooChoo — Live Ops [15m] |
| 137839982570166 | ChooChoo — Command Forensics [1h] |
| 57872805109233 | ChooChoo — Analyst Intel [1h] |
| 255469018958211 | ChooChoo — SOC Overview |

### Dashboard Push Pattern (CRITICAL)

Direct `curl -d @file.json` does NOT work — Gravwell wraps dashboards in an envelope with capitalized keys and integer IDs.

```python
import json, urllib.request

JWT = "<get via POST /api/login with {'User':'admin','Pass':'changeme'}>"

DASHBOARDS = [
    (137856853281928, "dashboards/ChooChoo — Live Feed [15m] (Spoiler-Free).json"),
    (206695622031598, "dashboards/ChooChoo — Live Ops [15m].json"),
    (137839982570166, "dashboards/ChooChoo — Command Forensics [1h].json"),
    (57872805109233,  "dashboards/ChooChoo — Analyst Intel [1h].json"),
    (255469018958211, "dashboards/ChooChoo — SOC Overview.json"),
]

for live_id, fname in DASHBOARDS:
    req = urllib.request.Request(
        f"http://192.168.88.251/api/dashboards/{live_id}",
        headers={'Authorization': f'Bearer {JWT}'}
    )
    wrapper = json.loads(urllib.request.urlopen(req).read().decode())
    wrapper['Data'] = json.load(open(fname))
    body = json.dumps(wrapper).encode()
    req2 = urllib.request.Request(
        f"http://192.168.88.251/api/dashboards/{live_id}",
        data=body, method='PUT',
        headers={'Authorization': f'Bearer {JWT}', 'Content-Type': 'application/json'}
    )
    urllib.request.urlopen(req2)
```

### Tile Schema Translation

Repo JSON uses Proxmox lab schema; live Gravwell 5.8.6 uses a different tile layout format. A `translate_dashboard()` function must be applied at push time:

- Repo: `dimensions.columns/rows` + `position.x/y` + `searchIndex`
- Live: `span: {col, row, x, y}` + `searchesIndex`

---

## Dashboard Audit Status (as of 2026-08-05)

All 5 repo JSON files under `dashboards/` are fully audited and fixed. **These changes are NOT yet committed and NOT yet pushed to the live appliance.** The files are untracked (`??`) in git on branch `add-gravwell-dashboards`.

### Fixes applied across all dashboards:
- All `tag=zeek` replaced with correct `corelight_*` per-log tags
- All `172.x` Docker IP filters removed and replaced with `192.168.88.x` infra filters
- All `grep -v "192.168.88.249"` added to MQTT switch command counters (`.249` was inflating "attack" metrics by proxying all authorized switch throws)
- All deprecated `lineChart` renderers replaced with `chart` + `rendererOptions: {"chartType": "line"}`
- All `over W` removed from static distribution charts (pie/bar) — `over W` on a static chart produces one flat bucket
- `grep "8001"` port filters removed from HTTP queries (web traffic is on port 80 only on this network)
- Renderer/query terminal mismatches fixed (e.g. `numbercard` renderer with `chart` query)

### Per-dashboard notable fixes:

**Live Feed (Spoiler-Free):**
- Added `grep -v "192.168.88.249"` to all MQTT switch counters
- Fixed s[20]: chart renderer + count over 30s for Modbus WRITEs over time
- Fixed s[21]: unique attacker IP count
- Fixed s[22]: HTTP useragent wordcloud
- Fixed s[23]: CREDS SNIFFED — now counts `corelight_notice` SNIFFPASS events
- Added s[24]: new tile "THREW THE SWITCH" counting `sw1/cmd/throw` MQTT from non-infra IPs
- KPI row rebalanced across 16 columns with 7 tiles

**Live Ops:**
- Infra filters added to all MQTT queries
- `pieChart` renderer fix for Modbus Function Breakdown and Connection Outcomes
- Web UI section fixed (removed `grep "8001"`, added infra exclusions)
- Full layout redesign for Gravwell 5.8.6

**Command Forensics:**
- Title fixes for several tiles
- `grep -v "192.168.88.249"` added to all switch queries

**Analyst Intel:**
- s[6] Client ID Collisions: renderer `numbercard` → `table`
- s[22] Web UI Top URIs: terminal changed to `chart count by uri`
- s[24] ATTENDEE TOOLING: fixed field name (`useragent` not `user_agent`)
- s[19] Off-Namespace Topic: fixed to use `grep -v "sw1/cmd/throw"`
- `over 1h` removed from all static distribution charts

**SOC Overview:**
- s[2]: `over 1h` removed from protocol mix chart
- s[4] Top Talkers: replaced duplicate tile with ranked table + full infra filter
- s[13] Anonymous MQTT Sessions: added `grep client_id ""`

---

## Admin Panel (192.168.88.246:9999)

**Creds:** admin / choochoo-admin

The panel lives in `admin/` in the repo. It is a FastAPI app running as a Docker container on .246. Modified files (not yet committed):

- `admin/app.py`
- `admin/Dockerfile`
- `admin/templates/index.html`

### Current docker run command on .246:

```bash
docker run -d --name choochoo-admin \
  -p 9999:9999 \
  --cap-add NET_ADMIN \
  -e TRAIN_API_URL=http://192.168.88.253:8000 \
  -e SWITCH_API_URL=http://192.168.88.253:8000 \
  -e STATS_IFACE=eth0 \
  -e STACK_HOST=192.168.88.253 \
  -e STACK_USER=analyst \
  -e STACK_PASS=corelight \
  -e COMPOSE_FILE=/home/analyst/Projects/ZeekTrack/docker-compose.real.yml \
  -e SENSOR_HOST=192.168.88.251 \
  -e SENSOR_USER=corelight \
  -e SENSOR_PASS=corelight \
  choochoo-admin
```

### Features implemented this session:

**Fleet health grid** — top of page, polls `/api/fleet` every 10s. Shows up/down + latency for all 4 Pis (Admin .246, Web-Modbus .253, Outstation .250, Microsensor .251). Uses async parallel health checks: self-report for .246, HTTP GET for .253 and .251, TCP connect for .250.

**Admin Pi local stats** — CPU/RAM/disk/eth0 throughput, polls `/api/stats` every 5s.

**Switch position safety guard** — Forward/Reverse motor direction buttons start disabled on page load. They only enable once the switch state API confirms `forward` or `reverse`. E-STOP is never gated. Shows yellow warning banner `⚠ Switch position unknown — confirm track position before moving` when guard is active.

**Switch display logic** — API `reverse` = STRAIGHT (physical), API `forward` = CURVE (physical). This is intentionally inverted from the API values to match what the web-modbus UI shows.

**Microsensor Services section** — polls `/api/sensor/services` every 8s via SSH to .251. Shows status of `corelight-softsensor`, `gravwell_webserver`, `gravwell_indexer`, `gravwell_simple_relay`. Each has a Restart button that runs `sudo systemctl restart <service>` over SSH.

**Train Stack Containers section** — polls `/api/containers` every 5s via SSH to .253. Shows `choochoo-web-modbus-real` and `choochoo-mosquitto-real`. Restart uses `docker restart`; rebuild uses `docker compose up -d --build --no-deps <service>`.

**Log streaming** — Web-Modbus and MQTT tabs stream `docker logs --follow` from .253 over SSH.

**IP blocking** — iptables DOCKER-USER chain on .246 (requires NET_ADMIN cap).

### SSH architecture:
- `.253` (train stack): `_ssh()` helper using `sshpass` + `analyst/corelight`
- `.251` (Microsensor): `_ssh_sensor()` helper using `sshpass` + `corelight/corelight`, `sudo` works passwordless for systemctl

---

## Pending / Not Yet Done

1. **Dashboard push to live appliance** — All 5 `dashboards/*.json` files are updated locally but have NOT been pushed to the live Gravwell at 192.168.88.251. Push when on the 192.168.88.x network using the Python push pattern above (with `translate_dashboard()` for tile schema conversion).

2. **Git commit** — `admin/app.py`, `admin/Dockerfile`, `admin/templates/index.html` are modified but not committed. The `dashboards/` folder is entirely untracked. Branch is `add-gravwell-dashboards`.

3. **Gravwell link in topbar** — Updated from CT 201 (192.168.1.201) to 192.168.88.251 in the template.

---

## Key Gotchas

- **Gravwell grep has no alternation** — `grep "foo|bar"` matches nothing. Use separate grep calls.
- **grep after json is a no-op** — always grep raw text BEFORE `| json`.
- **eval on dotted field names silently passes everything** — use `grep -v` on raw text for IP exclusions.
- **`over W` on static charts = one flat bucket** — omit `over` entirely for pie/bar distribution queries.
- **Gravwell dashboard push requires envelope** — GET wrapper first, set `wrapper['Data']`, PUT back.
- **Tile schema differs between lab (CT 201) and live (Microsensor 5.8.6)** — translate at push time.
- **`.249` inflates attack metrics** — it's the authorized web UI proxy for ALL Modbus and switch commands. Always filter it out of attacker-facing queries.
- **Switch API values are inverted from physical labels** — `forward` = curve track, `reverse` = straight track. This matches the web-modbus UI but is opposite of what you'd expect from the field names.
