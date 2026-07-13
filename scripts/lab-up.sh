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
COMPOSE="docker compose -f $(dirname "$0")/../docker-compose.fake.yml"

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
echo "Train UI (MQTT):   http://localhost:8000"
echo "Train UI (Modbus): http://localhost:8001  (dual mode only)"
echo "Gravwell:          http://localhost:8080  (admin / changeme)"
echo "Attacker:          docker exec -it choochoo-attacker bash"
echo "Attacks:           docker exec choochoo-attacker run-attack --list"
