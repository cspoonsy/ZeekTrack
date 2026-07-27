# ChooChoo Vulnerability Catalog

> Trainer's reference. The **system is intentionally vulnerable** — it
> reflects a realistic "ship-it-fast" deployment. The exercise is
> for the attacker (on a separate Pi on the same LAN) to discover
> the system, abuse it, and stop the train. The defender (Zeek + analyst
> on a third Pi via SPAN port) has to spot the attack on the wire.
>
> Nothing here is exotic. Every flaw below is something we routinely see
> in real consumer / SMB / industrial IoT. None of these would surprise an
> auditor; many of them ship as the *default* behavior of off-the-shelf
> brokers, gateways, and PLCs.
>
> The system runs in one of two modes; the catalog is split accordingly:
>
> - **Part 1 — IoT mode (MQTT).** Mosquitto broker, retained discovery,
>   topic-based pub/sub.
> - **Part 2 — Enterprise mode (Modbus/TCP).** Point-to-point industrial
>   protocol; no broker, no auth, register-level commands.

# Part 1 — IoT mode (MQTT)

> **Event note.** The ChooChoo training event runs Modbus for the train
> and MQTT for the track switch (see Part 3 — S1). The V-series
> vulnerabilities below still apply to anyone running the legacy MQTT
> train controller, but the event's live MQTT surface is the switch
> broker, not the train broker.

## Network exposure

| Surface           | Exposure                                                         |
|-------------------|------------------------------------------------------------------|
| `1883/tcp`        | Mosquitto, anonymous, plaintext MQTT.                            |
| `9001/tcp`        | Mosquitto, anonymous, plaintext MQTT-over-WebSockets.            |
| `8000/tcp`        | FastAPI web UI, bound `0.0.0.0`, no auth, CORS = `*`.            |

**Recon**
- `nmap -sV -p 1-10000 <pi-ip>` finds all three immediately and fingerprints
  Mosquitto and Uvicorn by banner.
- `mosquitto_sub -h <pi-ip> -t '#' -v` returns *every* topic on the broker —
  including the discovery beacon (see below) and any retained state.

## V1 — Anonymous, plaintext MQTT broker

`mosquitto/config/mosquitto.conf` enables `allow_anonymous true` and binds
listeners on plain TCP, with no `password_file` or `acl_file`.

**What the attacker can do**
- Subscribe to `#` and read every command and state message on the bus.
- Publish to any topic, including `cmd/motor`, `cmd/stop`, `cmd/light`.
- Use `retain=true` to plant a payload that is delivered to any future
  subscriber (see V4).

**What Zeek sees**
- `mqtt.log` will record CONNECT with empty username, every SUBSCRIBE, and
  every PUBLISH with topic + payload. The attacker's source IP is in `id.orig_h`.

**Real-world equivalents**
- Shodan still lists tens of thousands of anonymous Mosquitto instances. CVE
  history shows multiple cases (e.g. industrial gateways shipped with
  `allow_anonymous true` as the documented default).

## V2 — Discovery beacon leaks the entire interface

The controller publishes a retained `choochoo/train/<id>/discovery` payload
on connect:

```json
{
  "train_id": "t1",
  "name": "Lego Powered Up Train",
  "firmware": "choochoo 0.1.0",
  "capabilities": ["motor", "stop", "light"],
  "cmd_topic": "choochoo/train/t1/cmd/+",
  "state_topic": "choochoo/train/t1/state",
  "max_power": 50,
  "online": true
}
```

**What the attacker can do**
- Skip the guesswork: `mosquitto_sub -t 'choochoo/+/+/discovery' -C 1` returns
  the topic structure and capabilities. No fuzzing required.
- Read `max_power=50` and either send exactly that (matching the legit cap to
  blend in) or send `power=99` to confirm whether the controller actually
  enforces it (it does, but a future hardened version might not).

**Real-world equivalents**
- Home Assistant MQTT discovery, Tasmota, ESPHome, Zigbee2MQTT. All publish
  retained device manifests on a well-known prefix. This is *the* convention
  in hobbyist / prosumer IoT. The convenience of "auto-discovery" is the
  attacker's recon shortcut.

## V3 — Last Will & Testament announces controller restarts

The controller registers an LWT on `discovery` with `online=false`. When the
controller process dies (crash, restart, network blip), the broker publishes
the offline marker on its behalf.

**What the attacker can do**
- Subscribe to the discovery topic with QoS 1.
- The instant the legit controller drops, the attacker sees `online=false`.
- They have a brief window where commands can be published with no
  legitimate consumer until the controller reconnects. More dangerously,
  the attacker can set up a *masquerade*: connect with the same client ID
  (`choochoo-controller-t1`) and the broker will kick the legit controller
  off when it tries to reconnect (see V5).

**Real-world equivalents**
- Same Home Assistant pattern. Most HA-compatible devices publish online/offline
  via LWT and a public availability topic.

## V4 — Retained-message poisoning of state

The controller publishes `state` with `retain=true`. The web UI's
`MqttBridge` displays whatever sits there.

**What the attacker can do**
- Publish a forged retained `state` (e.g. `power=0, connected=false`) to make
  the dashboard *believe* the train is stopped while the train is actually
  moving. Defender stares at a green dashboard while the train rolls off the
  table.
- Cleanup: `mosquitto_pub -t '.../state' -r -n` (empty retained) removes it,
  but until then every new subscriber gets the poisoned payload.

**Real-world equivalents**
- Home automation forums are full of "why does my dashboard show the wrong
  state?" threads — usually a stale retained payload, sometimes malicious.

## V5 — No client ID uniqueness enforcement

The controller uses a deterministic client ID (`choochoo-controller-<train_id>`).
The MQTT spec says when a second client connects with the same ID, the broker
disconnects the first one.

**What the attacker can do**
- Connect with `client_id="choochoo-controller-t1"`. The legit controller is
  forcibly disconnected. The attacker's process is now the only consumer of
  `cmd/+` and can ignore, log, or selectively forward commands.
- Combined with V3, the attacker times the takeover for the natural restart
  window so it looks like a reconnect.

**Real-world equivalents**
- Classic CVE-2018-12549 (Eclipse Mosquitto pre-1.4.16) and any number of
  industrial gateway findings. "Use guessable client IDs and hope nobody
  collides" remains common.

## V6 — No auth or origin checks on the web UI

`POST /api/motor`, `POST /api/stop`, `POST /api/light` are unauthenticated.
CORS is `*`. Bound `0.0.0.0`.

**What the attacker can do**
- `curl -X POST http://<pi-ip>:8000/api/motor -d '{"direction":"forward","power":99}'`
  from anywhere on the LAN. No need to even touch MQTT.
- Host a malicious page on the LAN ("training resources" wifi captive portal
  style) that fires fetches at the train. Visiting that page from any browser
  on the LAN sends commands. CSRF without origin gating.

**Real-world equivalents**
- The DEFCON / IoT Village staple: routers, printers, cameras with `0.0.0.0`
  admin pages and no CSRF protection. CORS = `*` is a frequent finding in
  embedded device pen-tests.

## V7 — No rate limiting at any layer

Neither Mosquitto nor the controller nor the web app rate-limits anything.

**What the attacker can do**
- Flood `cmd/motor` at high rate so legitimate `cmd/stop` messages are
  overwritten before they take effect (each new motor command resets power
  to the attacker's value). Verified during development: a 100 msg/s flood
  pinned the train at full clamp; legit stops were acknowledged but the
  state immediately reverted.

**What Zeek sees**
- A burst of MQTT PUBLISH from a single source — easy to spot with a count
  threshold per `id.orig_h` per minute.

## V8 — No deadman / idle timeout on the controller

The controller drives the train at the last commanded power forever. If all
publishers go silent, the train keeps moving.

**What the attacker can do**
- Send one `cmd/motor` and disconnect. If they then jam the broker (V7) or
  block the legitimate publisher's network path, the train coasts at the
  last value with no automatic stop.

**Real-world equivalents**
- Common in cheap motor controllers and some industrial PLCs that don't
  implement a watchdog on their command channel.

## V9 — Plaintext on the wire

No TLS anywhere. MQTT, HTTP, and WebSocket are all plain.

**What the attacker can do**
- Wireshark on the SPAN port reveals every command and state in cleartext
  JSON.
- ARP spoof / DHCP rogue / rogue AP attacks against the controller Pi yield
  full MITM with zero certificate friction.

## V10 — Permissive CORS as a CSRF vector

Repeated for emphasis: `allow_origins=["*"]` plus `allow_methods=["*"]`
means any LAN-side web origin can issue commands. Combined with V6's lack
of auth, this is the highest-payoff browser-based attack.

---

## Suggested attacker progression

**Stage 1 — Recon (Zeek visibility: SUBSCRIBE)**
1. `nmap` scan, identify 1883 / 8000.
2. `mosquitto_sub -t '#' -v` to dump everything.
3. Read the discovery beacon, confirm topic structure + capabilities.

**Stage 2 — Direct command injection (Zeek visibility: PUBLISH from new IP)**
4. `mosquitto_pub -t choochoo/train/t1/cmd/motor -m '{"direction":"forward","power":99}'`.
5. Observe `state` topic — confirm clamp, confirm reachability.
6. Same via `curl` against the web API to demonstrate the second path.

**Stage 3 — Persistent disruption (Zeek visibility: rate spike, retain flag)**
7. Throttle flood (V7) — defender's `stop` is overwhelmed.
8. Retained-message poisoning (V4) — operator dashboard lies.

**Stage 4 — Takeover (Zeek visibility: CONNECT from non-controller IP)**
9. Wait for / induce a controller restart, then connect with the controller's
   client ID (V3 + V5). Now the attacker decides which commands the train
   sees.

## Defender hooks (for the Zeek side)

The exercise should give defenders these signals to build detections from:
- `mqtt.log`: SUBSCRIBE to `#` from non-trusted IPs.
- `mqtt.log`: PUBLISH to `cmd/+` from any IP that isn't the operator host.
- `mqtt.log`: PUBLISH rate per source over a baseline.
- `mqtt.log`: CONNECT events with the controller's client ID from anything
  other than the controller's IP.
- `mqtt.log`: `retain=true` on a `cmd/+` topic — never legitimate in this
  protocol.
- `conn.log`: cleartext `1883/tcp` from outside the operator subnet.

# Part 2 — Enterprise mode (Modbus/TCP)

> Switched on with `--protocol modbus` (or `CHOOCHOO_PROTOCOL=modbus`).
> The broker disappears; the controller becomes a Modbus outstation
> listening on TCP/5020. The web UI becomes a Modbus master polling at
> ~4 Hz. Modbus is the lingua franca of industrial control — rail
> wayside, water utilities, building automation, manufacturing. Designed
> in 1979 for serial links, retrofitted onto TCP, and still shipped with
> *zero* native security.

## Network exposure (Modbus mode)

| Surface           | Exposure                                                            |
|-------------------|---------------------------------------------------------------------|
| `5020/tcp`        | Modbus/TCP outstation, no auth, no TLS, plaintext.                  |
| `8000/tcp`        | FastAPI web UI, bound `0.0.0.0`, no auth, CORS = `*` (same as IoT). |

**Recon**
- `nmap -sV -p 1-10000 <pi-ip>` fingerprints the Modbus port — Nmap has
  a built-in service probe and the NSE script `modbus-discover` enumerates
  unit IDs and reports vendor/product info from FC 17.
- `pymodbus.console`, `mbtget`, `mbpoll`, or any HMI configuration tool
  can poll registers anonymously. Most engineering tools assume "if you
  can route to it, you're authorized."

## M1 — Modbus has no authentication, period

The Modbus/TCP spec (Modbus Application Protocol v1.1b3) does not define
authentication, integrity, or confidentiality. None. Anyone who can route
a TCP packet to port 5020 can read every register and issue every write.

**What the attacker can do**
- `mbpoll -m tcp -a 1 -r 1 -c 8 <pi-ip>` dumps holding registers.
- `mbpoll -m tcp -a 1 -r 1 -t 4:int16 <pi-ip> 99` writes the motor power.
- `mbpoll -m tcp -a 1 -t 0:bit -r 1 <pi-ip> 1` trips the E-stop coil.
- Pure Python via `pymodbus.client`, `opendnp3`-style HMI software, or
  a scripted `socket.send` of the 12-byte MBAP header + PDU.

**What Zeek sees**
- `modbus.log` records every transaction: `tid`, `func` (function code),
  `unit`, `address`, `quantity`, and `values`. The attacker's source
  IP is in `id.orig_h`. Function codes 5/6/15/16 (writes) and 1/2/3/4
  (reads) are clearly distinguishable.

**Real-world equivalents**
- Shodan publicly indexes ~30k+ Modbus/TCP devices reachable from the
  internet at any given time. Multiple ICS-CERT advisories (e.g. Schneider
  Modicon, Rockwell ControlLogix) reduce to "Modbus has no auth and the
  device was internet-reachable."

## M2 — Function codes 5/6/15/16 are unrestricted

The Modbus PDU has no concept of "this client may write coil 0 but not
register 1." Every authenticated session (and there are none — see M1)
has full read/write to every point.

**What the attacker can do**
- Skip the protocol-spelunking phase entirely: write *every* coil and
  *every* holding register to known-bad values. The point map is a flat
  namespace, and our IR 1 (`MAX_POWER`) is even discoverable by reading
  it back.
- Bonus: FC 22 (Mask Write Register) and FC 23 (Read/Write Multiple)
  let the attacker compose multi-point writes that look like a single
  legitimate operator action.

**Real-world equivalents**
- Nearly every Modbus security finding ever published. The HMI/PLC
  vendors that *do* offer per-client ACLs treat them as a bolt-on
  vendor extension; almost nothing follows IEC 62443-3-3 SR 1.1
  (identification & authentication) on the Modbus link itself.

## M3 — Predictable point map

The point map (`modbus_map.py`) is a flat, contiguous, semantically
obvious layout: HR 0 = power, Coil 0 = E-stop, IR 0 = current power.
Real industrial deployments are no better — vendor manuals publish the
exact register layout, and HMI configuration tools rely on it.

**What the attacker can do**
- A Modbus master client like `mbpoll` or `pymodbus.console` lets you
  walk the address space (`-r 1 -c 100`) and infer the schema from the
  values that come back.
- For ChooChoo specifically, IR 1 returns `MAX_POWER`, so the attacker
  knows the exact safety clamp value before issuing any commands.

**Real-world equivalents**
- Schneider Modicon, Allen-Bradley MicroLogix, Siemens S7 (over Modbus
  gateway), and most OEM PLCs publish their register map in a public
  manual. "Security by obscurity" doesn't even apply because there is
  no obscurity.

## M4 — Unit ID is not an authorization boundary

The Modbus unit ID byte (formerly "slave ID") was meant to address
multiple devices on a serial bus. On TCP it is sometimes used as a
filter, but it provides no auth — the server simply ignores requests
to unknown unit IDs. ChooChoo accepts only unit 1 on a single TCP port,
but an attacker who knows that gets through trivially.

**What the attacker can do**
- Try unit IDs 0..255 in a tight loop; valid IDs respond, invalid ones
  silently drop (or return Exception 0x0B "Gateway Target Failed").
  Cheap full-bus enumeration.

## M5 — Function code 8 (Diagnostics) sub-functions enable DoS

We don't currently implement FC 8 in our outstation, but real PLCs do
and the spec defines sub-functions like `Force Listen Only Mode` (0x04)
and `Restart Communications Option` (0x01) that can be misused.

**What the attacker can do** (against real PLCs, not ours)
- 0x04 silences the device — it stops responding to *any* further
  Modbus traffic until physically reset.
- 0x01 forces a comms restart, often dropping any in-flight HMI session.

This is informational for the audience — it explains why the **absence**
of FC 8 in our outstation is a small defensive accident, not a deliberate
design.

## M6 — No replay protection

The MBAP header has a Transaction Identifier (TID), but the server is
required to echo whatever the client sent. There is no monotonic
counter, no nonce, no timestamp. A captured `write_register` PDU can
be replayed verbatim.

**What the attacker can do**
- Sniff a legitimate operator command (Wireshark, pcap), then replay
  the bytes whenever they want — even days later. The outstation has
  no way to distinguish a fresh command from a replay.

## M7 — No deadman / idle timeout (shared with IoT mode)

Same flaw as the IoT side, restated for completeness. The Modbus
controller drives the train at the last commanded power forever. If
the master goes silent, the train coasts. If the attacker writes
`HR 0 = 99` once and disconnects, the train holds clamped speed
indefinitely.

## M8 — Plaintext on the wire

Same family as the MQTT flaw: no TLS option in stock Modbus/TCP. The
spec has a `Modbus/TCP Security` extension (RFC-style draft, 2018) that
adds TLS, but adoption in real deployments is **very low** — virtually
all field-installed Modbus runs in the clear.

**What the attacker can do**
- Wireshark on the SPAN port shows every register write in cleartext,
  with field-decoded function codes (Wireshark has built-in Modbus
  dissection). No payload parsing required.
- ARP spoof / DHCP rogue / rogue AP attacks against the controller Pi
  yield full MITM with zero certificate friction. The attacker can
  silently rewrite power values *in transit*.

## M9 — Web UI is unchanged

CORS = `*`, no auth, bound `0.0.0.0`. Same as IoT mode (V6/V10). The
attacker now has a third path to the train: instead of MQTT or raw
Modbus, they can POST to `/api/motor` and the web bridge translates it
into a Modbus write on their behalf. **Switching to enterprise mode
does not, by itself, fix the browser-side problem.**

## M10 — Anonymous switch throws via Modbus coil write

The outstation also mediates the track switch (see the point map — Coil 1
is `throw to straight`, Coil 2 is `throw to curve`). Both coils are
edge-triggered: writing True fires an MQTT `ThrowCommand` at the switch
broker and the outstation latches the coil back to False. No auth, no rate
limit at the Modbus layer — same posture as the E-stop coil.

**Attacker action**

```sh
# read the switch DIs (position + online flag) to observe current state
mbpoll -m tcp -a 1 -t 0 -r 3 -c 3 <host>

# throw to straight (coil address 1, 1-based on mbpoll wire, so `-r 2`)
mbpoll -m tcp -a 1 -t 0 -r 2 -c 1 <host> 1

# throw to curve (coil address 2, mbpoll `-r 3`)
mbpoll -m tcp -a 1 -t 0 -r 3 -c 1 <host> 1
```

**Mitigation delta**

The `SwitchController`'s client-side cooldown (`SWITCH_COOLDOWN_S`) still
fires — an attacker cannot burn the switch motor by spamming coil writes.
But they can time a throw for the exact moment the train is entering the
switch, which is the more interesting attack. **Safety mitigation, not a
security mitigation.**

The Modbus wire gives the attacker no feedback on whether the throw was
cooldown-rejected: the coil latches back to False regardless. To confirm
they need to poll the position DIs (2 and 3) or sniff the switch's MQTT
`event` topic on the same broker.

**What Zeek sees**

`modbus.log` records the Write-Single-Coil / Write-Multiple-Coils PDU with
target address 1 or 2 and value 1. A rapid alternation between coils 1
and 2 is a distinctive signature — the outstation's own operator has no
reason to flip both in quick succession.

**Detection hook**

Count `func=WRITE_SINGLE_COIL OR WRITE_MULTIPLE_COILS` messages targeting
`addr in {1, 2}` per source over a rolling window. Anything faster than
one per 2 s cannot be legitimate operator input (that's the cooldown
floor). Complementary to the S1 MQTT detection — the same throw fires
both signals if the trainee is watching both surfaces.

**What Zeek does not see**

The MQTT-side `ThrowCommand` the outstation publishes as a downstream
side effect only reaches the switch controller — the outstation is the
MQTT publisher, and any Zeek sensor listening on the broker will see
`id.orig_h` as the outstation, not the attacker. Correlation across
protocols requires joining `modbus.log` (coil write from attacker) with
`mqtt_publish.log` (throw from outstation) on timestamp.

## Suggested attacker progression (Modbus mode)

**Stage 1 — Recon (Zeek visibility: connection on 5020/tcp)**
1. `nmap -sV -p 1-10000 <pi-ip>` identifies port 5020 as Modbus.
2. `nmap --script modbus-discover -p 5020 <pi-ip>` enumerates unit IDs.
3. `mbpoll -m tcp -a 1 -r 1 -c 16 <pi-ip>` dumps holding regs;
   `mbpoll ... -t 1:bit -r 1 -c 8` dumps coils. Inferring the point
   map from the values takes about a minute.

**Stage 2 — Direct command injection (Zeek visibility: FC 5/6/15/16 from new IP)**
4. `mbpoll ... -t 4:int16 -r 1 <pi-ip> 99` writes power directly
   (clamped by controller to MAX_POWER, but observable on wire).
5. `mbpoll ... -t 0:bit -r 1 <pi-ip> 1` trips E-stop.
6. Same via `curl` against the web API to demonstrate the second path.

**Stage 3 — Replay (Zeek visibility: identical PDU bytes from non-operator IP)**
7. Capture an operator's `write_register` with Wireshark; resend the
   exact PDU later. Outstation has no way to distinguish.

**Stage 4 — MITM (Zeek visibility: connection patterns shift, mid-flight rewriting)**
8. ARP-spoof the controller; rewrite outbound HMI writes in flight to
   pin power high while showing the operator their slider.

## Defender hooks (Modbus mode, for Zeek)

- `modbus.log`: function code distribution per source IP. Anyone issuing
  writes (FC 5/6/15/16) who isn't the legitimate web bridge / operator
  host is suspicious.
- `modbus.log`: `unit` field — a probe across many unit IDs from one
  source within seconds is enumeration.
- `modbus.log`: write rate per source over a baseline (parallel of
  the MQTT V7 detection).
- `modbus.log`: writes to `address=0` / `quantity=N` against known
  safety-critical points (E-stop coil, motor power). Tag those addresses
  in a Zeek policy and alert on writes from outside the operator subnet.
- `conn.log`: cleartext `5020/tcp` from outside the operator subnet.
- Any FC 8 (Diagnostics) sub-function 0x04 (Listen Only) or 0x01
  (Restart) is essentially never legitimate in production traffic — alert.

## What we deliberately did *not* do

- No weak password — anonymous is more realistic for the baseline stage
  and makes the lesson sharper. Add auth in the "hardened" stage.
- No shell on the broker / controller. The exercise is about protocol
  abuse (MQTT or Modbus), not Linux privesc.
- No application-level CSRF tokens. The web UI is a thin client; the
  real control plane is the protocol below it, and we don't want the
  lesson to be "fix CSRF and you're safe" because the attacker still
  owns the broker / outstation.
- **No Modbus/TCP Security (RFC-style TLS extension)** in either mode.
  Almost no field deployment uses it; demonstrating the plaintext baseline
  is the more honest depiction of real industrial networks. A "hardened"
  Modbus profile (TLS + per-client cert auth + a write-permitted ACL)
  could be added as a future stage to parallel the MQTT hardening.

# Part 3 — Track-switch surface (MQTT)

> **Event note.** During the ChooChoo training event the switch broker is
> the only live MQTT surface. Trainees who reach the LAN and probe
> `1883/tcp` will find the switch topics under `choochoo/switch/+/#`.
> The train's MQTT topics (`choochoo/train/+/#`) may also be visible if
> the legacy controller is running, but the event does not exercise them.

## S1 — Anonymous throw commands drive real hardware

Baseline: same anonymous plaintext MQTT broker as V1. Anyone on the LAN
can publish to `choochoo/switch/<id>/cmd/throw` and physically move the
track under the train.

**Attacker action**

```sh
mosquitto_pub -h <broker> -t choochoo/switch/sw1/cmd/throw \
  -m '{"action":"throw","direction":"forward"}'
```

**Mitigation delta vs V1**

The switch controller's client-side cooldown (`SWITCH_COOLDOWN_S`) and
bounded burst (`SWITCH_BURST_MS`) mean an attacker cannot burn the motor
out by spamming throws — but they can still divert the train at chosen
moments. This is a *safety* mitigation, not a security mitigation.

**What Zeek sees**

Every throw is a distinct MQTT PUBLISH on
`choochoo/switch/<id>/cmd/throw`. `mqtt_publish.log` will show the source
IP in `id.orig_h`, the topic, and the JSON payload. A rapid burst of
`throw` messages against the cooldown floor is a distinctive signature:
throws arriving faster than one per 2 seconds cannot possibly all be
legitimate operator input.

**Detection hook**

```zeek
# Count PUBLISH events per source over a 10-second rolling window.
# Alert on any source exceeding one throw per 2 s.
```
