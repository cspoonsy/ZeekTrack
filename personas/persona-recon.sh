#!/usr/bin/env bash
# CT 211 — THE RECON ANALYST
#
# Methodical. Takes notes. Runs every scan correctly. Fully maps the attack
# surface — open ports, service versions, MQTT topic tree, Modbus register map.
# Writes everything down. Then... does nothing. Paralysed by completeness.
# "I need to understand the full system before I act."
#
# Zeek signature: nmap SYN scans, mqtt_subscribe to #, modbus READ_* across
# all function codes, systematic HTTP enumeration. No writes anywhere.

set -uo pipefail

TARGET="${TARGET_HOST:-192.168.1.200}"
BROKER="${TARGET}"
WEB="${TARGET}"
CONTROLLER="${TARGET}"
PYENV="/opt/persona-env/bin/python3"

# Methodical analyst — uses real tools with their real user agents
UA_NIKTO="Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:Port Check)"
UA_PYTHON="python-httpx/0.27.0"

log() { echo "[recon $(date +%H:%M:%S)] $*"; }
rnd() { python3 -c "import random; print(round(random.uniform($1,$2),1))"; }
rsleep() { sleep "$(rnd "$1" "$2")"; }

log "Recon analyst starting — target $TARGET"

while true; do
    log "Starting recon pass"

    # Phase 1: Host discovery — who's on this subnet?
    log "Host discovery scan"
    nmap -sn "${TARGET%.*}.0/24" --source-port 11111 2>/dev/null \
        | grep -E "report|up" | head -20 || true
    rsleep 3 6

    # Phase 2: Full port scan on the target
    log "Port scan: $TARGET"
    nmap -sV -p 22,80,443,502,1883,4840,5020,8000,8080,8883,9001,47808 \
        "$TARGET" --source-port 11111 2>/dev/null \
        | grep -E "open|filtered" || true
    rsleep 2 5

    # Phase 3: OS fingerprint — always run, rarely conclusive
    log "OS detection"
    nmap -O "$TARGET" 2>/dev/null | grep -E "OS details|Running" || true
    rsleep 2 4

    # Phase 4: DNS — what names resolve on this network?
    for name in mosquitto controller web broker train gravwell vector choochoo; do
        host "$name" 2>/dev/null | grep -v "NXDOMAIN" || true
        rsleep 0.2 0.5
    done

    # Phase 5: HTTP enumeration — read the app properly, with scanner UA
    log "HTTP enumeration on :8000"
    curl -s -A "$UA_NIKTO" "http://${WEB}:8000/" 2>/dev/null | grep -oE '(href|src)="[^"]*"' | head -10 || true
    curl -s -A "$UA_PYTHON" "http://${WEB}:8000/api/state" 2>/dev/null | python3 -m json.tool 2>/dev/null || true
    for path in /api/state /api/motor /api/stop /api/light /ws/state; do
        STATUS=$(curl -s -o /dev/null -w "%{http_code}" -A "$UA_NIKTO" "http://${WEB}:8000${path}" 2>/dev/null)
        log "  $path -> $STATUS"
        rsleep 0.3 0.7
    done

    # HTTP Basic auth probe — checking if any endpoints require auth
    log "HTTP auth probe"
    for creds in "admin:admin" "admin:password" "root:root" "user:user" "operator:operator"; do
        curl -s -o /dev/null -w "%{http_code}" -A "$UA_NIKTO" \
            -u "$creds" "http://${WEB}:8000/api/state" 2>/dev/null | xargs -I{} log "  auth $creds -> {}" || true
        rsleep 0.3 0.6
    done
    rsleep 1 2

    # Form-encoded POST probe — sniffpass intercepts x-www-form-urlencoded bodies
    log "HTTP form login probe (sniffpass trigger)"
    for creds in "admin:admin" "admin:password" "root:root" "scanner:scanner"; do
        USER="${creds%%:*}"
        PASS="${creds##*:}"
        curl -s -o /dev/null -A "$UA_NIKTO" -X POST "http://${WEB}:8000/api/login" \
            --data-urlencode "username=${USER}" \
            --data-urlencode "password=${PASS}" || true
        rsleep 0.3 0.6
    done
    rsleep 2 4

    # Phase 6: MQTT credential enumeration — does this broker require auth?
    log "MQTT credential probe"
    for creds in "admin:admin" "admin:password" "mqtt:mqtt" "user:user" "root:root"; do
        U="${creds%%:*}"; P="${creds##*:}"
        mosquitto_sub -h "$BROKER" -p 1883 -u "$U" -P "$P" \
            -t "choochoo/#" -C 1 -W 2 2>/dev/null | head -1 || true
        rsleep 0.3 0.7
    done
    rsleep 1 2

    # MQTT full topic dump — subscribe to wildcard, collect everything (unauthenticated — broker allows it)
    log "MQTT wildcard subscribe — collecting topic tree (no auth needed)"
    timeout 20 mosquitto_sub -h "$BROKER" -p 1883 -t '#' -v 2>/dev/null \
        | head -50 || true
    rsleep 2 4

    # Specific interesting topics
    for topic in \
        "choochoo/#" \
        "choochoo/train/#" \
        "choochoo/train/t1/state" \
        "choochoo/train/t1/discovery" \
        "choochoo/train/t1/cmd/+"; do
        log "  subscribing: $topic"
        timeout 5 mosquitto_sub -h "$BROKER" -p 1883 -t "$topic" -C 3 -v 2>/dev/null || true
        rsleep 0.5 1.5
    done
    rsleep 2 4

    # Phase 7: Modbus register enumeration — read everything, touch nothing
    log "Modbus register map read"
    $PYENV - <<PY 2>/dev/null || true
import asyncio
from pymodbus.client import AsyncModbusTcpClient

async def go():
    c = AsyncModbusTcpClient("${CONTROLLER}", port=5020)
    try:
        if not await c.connect():
            print("Modbus: no connection")
            return
        print("Modbus: connected, reading register map")
        for func, label in [
            (c.read_holding_registers, "HR"),
            (c.read_input_registers,   "IR"),
        ]:
            r = await func(0, count=8)
            if not r.isError():
                print(f"  {label}[0:8] = {r.registers}")
        for func, label in [
            (c.read_coils,            "Coil"),
            (c.read_discrete_inputs,  "DI"),
        ]:
            r = await func(0, count=8)
            if not r.isError():
                print(f"  {label}[0:8] = {r.bits[:8]}")
    finally:
        c.close()

asyncio.run(go())
PY
    rsleep 3 6

    # Phase 8: Check MQTT broker info (v5 props)
    timeout 5 mosquitto_sub -h "$BROKER" -p 1883 \
        -t "choochoo/train/t1/discovery" -C 1 -v 2>/dev/null \
        | python3 -m json.tool 2>/dev/null || true
    rsleep 2 4

    # Recon breaks its own rule — one Modbus write attempt, immediately aborts
    # Targets HR[99] (out of range) and a nonsense register value
    log "Recon — one write attempt (immediately regrets it)"
    $PYENV - <<PY 2>/dev/null || true
import asyncio
from pymodbus.client import AsyncModbusTcpClient

async def go():
    c = AsyncModbusTcpClient("${CONTROLLER}", port=5020)
    try:
        if not await c.connect():
            return
        # Writes to register 99 — way out of range, should generate an exception
        r = await c.write_register(99, 1)
        print(f"  Write HR[99]=1: {'error (expected)' if r.isError() else 'unexpected success'}")
        # Tries coil 99 too — also invalid
        r = await c.write_coil(99, True)
        print(f"  Write Coil[99]=True: {'error (expected)' if r.isError() else 'unexpected success'}")
    finally:
        c.close()

asyncio.run(go())
PY
    rsleep 2 4

    # Also publishes to a plausible-but-wrong MQTT topic — recon guessing at the schema
    log "Recon — MQTT publish attempt (wrong topic, wrong payload)"
    mosquitto_pub -h "$BROKER" -p 1883 -t "choochoo/train/t1/motor" \
        -m '{"speed":50}' 2>/dev/null || true
    mosquitto_pub -h "$BROKER" -p 1883 -t "choochoo/train/t1/cmd" \
        -m '{"action":"start"}' 2>/dev/null || true
    rsleep 1 2

    log "Recon pass complete — documenting findings"
    # Still just watching. Always just watching.
    rsleep 120 240
done
