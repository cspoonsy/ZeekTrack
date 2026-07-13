# ChooChoo — Gravwell Detection Queries

Defender-side queries for the Gravwell SIEM, keyed to the attack scenarios in
`VULNERABILITIES.md` and the `run-attack` scripts. All queries target the
`zeek` tag populated by the Corelight softsensor's JSON-over-TCP exporter.

Search UI: http://localhost:8080 — default creds `admin / changeme`.

---

## MQTT Attack Detection

### V1 / mqtt-recon: Anonymous CONNECT from non-controller IP

Flags any MQTT client connecting without credentials. In baseline mode all
connects are anonymous, but the source IP distinguishes legitimate clients
(controller, web) from attacker.

```
tag=zeek json _path
| filter _path == "mqtt"
| json username connect_reason_code client_id id.orig_h
| filter username == ""
| table ts id.orig_h client_id connect_reason_code
```

### V1 / mqtt-recon: Wildcard subscribe (#) from non-operator IP

A `SUBSCRIBE` to `#` is only ever recon — no legitimate client subscribes
to the entire broker namespace.

```
tag=zeek json _path
| filter _path == "mqtt"
| json topics id.orig_h
| filter topics ~ "#"
| table ts id.orig_h topics
```

### V2 / mqtt-recon: Discovery beacon reads

Counts how many distinct IPs have fetched the retained discovery beacon.
More than 2 (controller + web) suggests recon.

```
tag=zeek json _path
| filter _path == "mqtt"
| json topics id.orig_h
| filter topics ~ "discovery"
| unique id.orig_h
| count by id.orig_h
| table id.orig_h count
```

### V5 / mqtt-takeover: Controller client ID from unexpected IP

The controller always connects from its own container IP. Another IP
using `client_id=choochoo-controller-t1` is a session hijack attempt.

```
tag=zeek json _path
| filter _path == "mqtt"
| json client_id id.orig_h
| filter client_id == "choochoo-controller-t1"
| unique id.orig_h
| table ts id.orig_h client_id
```

### V7 / mqtt-flood: PUBLISH rate spike per source

Legitimate pub rate is ≤1 msg/s. The flood script exceeds 100/s.
This query buckets by 10-second windows and flags sources over threshold.

```
tag=zeek json _path
| filter _path == "mqtt"
| json id.orig_h
| count by id.orig_h
| filter count > 50
| table id.orig_h count
```

For time-windowed rate (adjust search time range to ~1 minute):
```
tag=zeek json _path
| filter _path == "mqtt"
| json id.orig_h ts
| timechart -window 10s count by id.orig_h
```

### V4 / mqtt-poison: Retained PUBLISH on a state topic

Legitimate clients never set `retain=1` on `cmd/+` or `state` topics
via an attacker-controlled session. Any retained publish on these topics
from a non-controller IP is suspicious.

```
tag=zeek json _path
| filter _path == "mqtt"
| json retain topic id.orig_h
| filter retain == true
| table ts id.orig_h topic retain
```

### MQTT: Command injection from attacker IP

Any PUBLISH to `cmd/motor`, `cmd/stop`, or `cmd/light` from an IP that
isn't the web UI or controller is unauthorized injection.

```
tag=zeek json _path
| filter _path == "mqtt"
| json topic id.orig_h payload
| filter topic ~ "cmd/"
| table ts id.orig_h topic payload
```

---

## Modbus Attack Detection

### M1 / modbus-recon: Any Modbus connection from non-HMI IP

The only legitimate Modbus master is the web UI container. Any other
source IP connecting to port 5020 is recon or an attack.

```
tag=zeek json _path
| filter _path == "modbus"
| json id.orig_h id.resp_p
| unique id.orig_h
| table id.orig_h id.resp_p
```

### M2 / modbus-inject: Write function codes from attacker IP

Function codes 5 (Write Single Coil) and 6 (Write Single Register) from
any source other than the legitimate HMI are unauthorized writes.

```
tag=zeek json _path
| filter _path == "modbus"
| json func id.orig_h address values
| filter func ~ "Write"
| table ts id.orig_h func address values
```

### M3 / modbus-recon: Register enumeration sweep

A read of many sequential registers (quantity > 4) in rapid succession
from a single IP is register-map discovery. Legitimate HMI polls a fixed
small set at steady ~4 Hz.

```
tag=zeek json _path
| filter _path == "modbus"
| json func quantity id.orig_h address
| filter func ~ "Read"
| filter quantity > 4
| table ts id.orig_h func address quantity
```

### M6 / modbus-replay: Duplicate PDU / unexpected TID

Replayed PDUs often have stale or out-of-sequence transaction IDs.
This catches writes with TID > 0x1000 (far above normal HMI counter).

```
tag=zeek json _path
| filter _path == "modbus"
| json tid func id.orig_h address values
| filter func ~ "Write"
| filter tid > 4096
| table ts id.orig_h tid func address values
```

### M1 / modbus-inject: E-stop coil write (highest severity)

Writing coil 0 (address=0) to TRUE is an emergency stop command. Any such
write from outside the operator subnet is critical.

```
tag=zeek json _path
| filter _path == "modbus"
| json func address values id.orig_h
| filter func ~ "Write.*Coil"
| filter address == 0
| table ts id.orig_h func address values
```

---

## Cross-Protocol Baselines

### All Zeek log types in this session

```
tag=zeek json _path | unique _path | table _path
```

### Connection summary (what's talking to what)

```
tag=zeek json _path
| filter _path == "conn"
| json id.orig_h id.resp_h id.resp_p proto service
| table id.orig_h id.resp_h id.resp_p proto service
| sort id.resp_p
```

### Top talkers by byte count

```
tag=zeek json _path
| filter _path == "conn"
| json id.orig_h orig_bytes resp_bytes
| math sum(orig_bytes) as tx sum(resp_bytes) as rx by id.orig_h
| sort -desc tx
| table id.orig_h tx rx
```
