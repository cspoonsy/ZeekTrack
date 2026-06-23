# Corelight Microsensor

Optional `sensor` profile in `docker-compose.fake.yml`. Adds a Corelight
Microsensor container that runs Zeek (and optionally Suricata) against
traffic on its own interface, so trainees / defenders can see what the
attack actually looks like in `conn.log`, `mqtt.log`, `modbus.log`, etc.

## Prerequisites

Two things have to come from Corelight, neither of which is in the repo:

1. **Package-repo auth token.** Log in to <https://my.corelight.cloud/>
   → Downloads → Microsensor and copy the token. You pass it once at
   build time as `CORELIGHT_TOKEN`. The Dockerfile strips the apt auth
   file after install so the token does not ship in the final image.

2. **License file.** Get it from your Corelight account manager and drop
   it at `sensor/license/corelight-license.txt`. The file is
   `.gitignore`-d.

The Microsensor package is **Linux x86_64 only**. On Apple Silicon the
container runs under Docker Desktop's QEMU emulation — it works, just
slower. The compose service pins `platform: linux/amd64`.

## Build and run

```sh
# Build (one-time per token rotation):
docker build --platform linux/amd64 \
  --build-arg CORELIGHT_TOKEN=<your-token> \
  -t choochoo-sensor:dev sensor/

# Stack with whatever else you're running:
docker compose -f docker-compose.fake.yml \
  --profile mqtt --profile noise --profile sensor up -d

# Watch the Zeek logs:
docker exec -it choochoo-sensor bash
ls /var/corelight/logs/$(date +%Y-%m-%d)/
tail -f /var/corelight/logs/current/conn.log
```

## What the trainer should care about

- **`/var/corelight/logs/`** is the source of truth. Zeek writes hourly
  rotation files (`conn.20:00:00-21:00:00.log` etc.) plus a `current/`
  symlink dir. JSON or TSV depending on the build.
- **MQTT and Modbus analyzers are first-class** in modern Zeek; the
  Microsensor inherits them. So a `mosquitto_pub` flood or an `mbpoll`
  E-stop write shows up in `mqtt.log` / `modbus.log` with
  `id.orig_h`, function code, topic, retain flag, etc. — exactly the
  fields `VULNERABILITIES.md` references for detection hooks.
- **Streaming exporters are off by default** in our `corelight-softsensor.conf`.
  Edit the file (mounted read-only at run time — change it on the host
  and `docker compose restart sensor`) to enable JSON-over-TCP, Splunk
  HEC, Kafka, Syslog, or any of the other supported sinks.

## Caveats

- **Container sniffing != SPAN port.** On the default Docker bridge,
  `eth0` only sees broadcast + the sensor's own traffic, not the
  east-west chatter between siblings. For a complete defender view in a
  pure-virtual session, run the sensor with `network_mode: host` (then
  point it at the host bridge interface, e.g. `Corelight::sniff docker0~2`).
  In a real deployment the Microsensor would tap a switch SPAN.
- **Microsensor is a Limited Availability product** at the time of
  writing. If your account doesn't have access, ask your Corelight
  account manager — that's also how you get the license.
