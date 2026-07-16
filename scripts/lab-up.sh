#!/usr/bin/env bash
# lab-up.sh — single command to bring up the full ChooChoo lab.
#
# Usage:
#   ./scripts/lab-up.sh mqtt      # IoT / MQTT control plane (default)
#   ./scripts/lab-up.sh modbus    # Enterprise / Modbus control plane
#   ./scripts/lab-up.sh down      # Tear everything down
#
# Always starts: attacker, sensor (Zeek + Vector), gravwell, simple-relay.
# Zeek is automatically pointed at the right container for the chosen mode.

set -euo pipefail

MODE="${1:-mqtt}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE="docker compose -f ${SCRIPT_DIR}/../docker-compose.fake.yml"
DASHBOARDS_DIR="${SCRIPT_DIR}/../gravwell/dashboards"

case "$MODE" in
  mqtt)
    echo "Starting MQTT (IoT) mode..."
    $COMPOSE --profile mqtt --profile attacker --profile gravwell up --build -d
    echo "Waiting for mosquitto to be ready..."
    until docker exec choochoo-mosquitto-fake mosquitto_sub -h localhost -t '#' -C 1 -W 1 &>/dev/null; do sleep 1; done
    ZEEK_TARGET_CONTAINER=choochoo-mosquitto-fake \
      $COMPOSE --profile mqtt --profile attacker --profile sensor --profile gravwell up -d
    ;;
  modbus)
    echo "Starting Modbus (Enterprise) mode..."
    $COMPOSE --profile modbus --profile attacker --profile gravwell up --build -d
    echo "Waiting for controller to be ready..."
    until docker exec choochoo-controller-modbus python3 -c \
      "import socket; s=socket.create_connection(('localhost',5020),timeout=1); s.close()" &>/dev/null; do sleep 1; done
    ZEEK_TARGET_CONTAINER=choochoo-controller-modbus \
      $COMPOSE --profile modbus --profile attacker --profile sensor --profile gravwell up -d
    ;;
  dual)
    echo "Starting dual mode (MQTT + Modbus simultaneously)..."
    MODBUS_WEB_PORT=8001 \
      $COMPOSE --profile dual --profile attacker --profile gravwell up --build -d
    echo "Waiting for mosquitto to be ready..."
    until docker exec choochoo-mosquitto-fake mosquitto_sub -h localhost -t '#' -C 1 -W 1 &>/dev/null; do sleep 1; done
    echo "Waiting for Modbus controller to be ready..."
    until docker exec choochoo-controller-modbus python3 -c \
      "import socket; s=socket.create_connection(('localhost',5020),timeout=1); s.close()" &>/dev/null; do sleep 1; done
    MODBUS_WEB_PORT=8001 \
      $COMPOSE --profile dual --profile attacker --profile gravwell up -d
    echo "Zeek instances: choochoo-zeek-mqtt (MQTT) + choochoo-zeek-modbus (Modbus)"
    ;;
  down)
    echo "Bringing down all profiles..."
    $COMPOSE --profile mqtt --profile modbus --profile dual --profile attacker --profile sensor --profile gravwell --profile noise down
    ;;
  *)
    echo "Usage: $0 [mqtt|modbus|dual|down]" >&2
    exit 1
    ;;
esac

echo ""
echo "Provisioning Gravwell dashboards..."
provision_dashboards() {
  local retries=30
  local jwt=""

  # Wait for Gravwell to accept logins
  until jwt=$(curl -s -X POST http://localhost:8080/api/login \
      -H 'Content-Type: application/json' \
      -d '{"User":"admin","Pass":"changeme"}' \
      | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['JWT'])" 2>/dev/null) \
      && [ -n "$jwt" ]; do
    retries=$((retries - 1))
    [ $retries -le 0 ] && echo "  Gravwell not ready after 30s — skipping dashboard import" && return
    sleep 1
  done

  local imported=0
  for f in "${DASHBOARDS_DIR}"/*.json; do
    name=$(python3 -c "import json; print(json.load(open('$f')).get('Name','?'))")
    result=$(curl -s -X POST \
      -H "Authorization: Bearer $jwt" \
      -H "Content-Type: application/json" \
      http://localhost:8080/api/dashboards \
      --data-binary "@$f")
    if python3 -c "import sys,json; r=json.load(sys.stdin); exit(0 if 'ID' in r else 1)" <<< "$result" 2>/dev/null; then
      echo "  ✓ $name"
      imported=$((imported + 1))
    else
      echo "  ✗ $name (already exists or error — skipping)"
    fi
  done
  echo "  $imported dashboard(s) imported."
}
provision_dashboards

echo ""
echo "Train UI (MQTT):   http://localhost:8000"
echo "Train UI (Modbus): http://localhost:8001  (dual mode only)"
echo "Gravwell:          http://localhost:8080  (admin / changeme)"
echo "Attacker:          docker exec -it choochoo-attacker bash"
echo "Attacks:           docker exec choochoo-attacker run-attack --list"
