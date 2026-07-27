#!/usr/bin/env bash
# lab-up.sh — single command to bring up the full ChooChoo lab.
#
# Usage:
#   ./scripts/lab-up.sh mqtt      # IoT / MQTT control plane (default)
#   ./scripts/lab-up.sh modbus    # Enterprise / Modbus control plane
#   ./scripts/lab-up.sh dual      # Both protocols simultaneously
#   ./scripts/lab-up.sh down      # Tear everything down
#
# Environment variables:
#   GRAVWELL_URL     URL of the Gravwell instance for dashboard provisioning.
#                    Defaults to http://localhost:8080 (local all-in-one).
#                    Set to http://<host> when Gravwell runs on a separate node.
#   ADMIN_PASSWORD   Password for the admin panel (default: choochoo-admin).
#                    CHANGE THIS before running at a public event.
#                    Admin panel: http://<host>:9999  (user: admin)
#
# When GRAVWELL_URL is set to a non-localhost address, the local Gravwell
# containers are not started — useful for split deployments where Gravwell
# lives on a dedicated host or LXC container.

set -euo pipefail

MODE="${1:-mqtt}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE="docker compose -f ${SCRIPT_DIR}/../docker-compose.fake.yml"
# If a host-local override exists (e.g. apparmor=unconfined on LXC hosts), merge it in.
OVERRIDE="${SCRIPT_DIR}/../docker-compose.override.yml"
[ -f "$OVERRIDE" ] && COMPOSE="$COMPOSE -f $OVERRIDE"
DASHBOARDS_DIR="${SCRIPT_DIR}/../gravwell/dashboards"
GRAVWELL_URL="${GRAVWELL_URL:-http://localhost:8080}"

# Include local Gravwell profile only when Gravwell runs on this host.
# Set GRAVWELL_URL to a non-localhost address to skip local Gravwell containers.
# The sensor profile (container Zeek) always runs — it watches the Docker bridge
# for MQTT/Modbus protocol visibility regardless of whether an external LAN sensor
# (e.g. CT 202) also exists.
if echo "$GRAVWELL_URL" | grep -qE "localhost|127\.0\.0\.1"; then
  GRAVWELL_PROFILE="--profile gravwell"
else
  GRAVWELL_PROFILE=""
fi
SENSOR_PROFILE="--profile sensor"
ADMIN_PROFILE="--profile admin"

case "$MODE" in
  mqtt)
    echo "Starting MQTT (IoT) mode..."
    $COMPOSE --profile mqtt --profile attacker $GRAVWELL_PROFILE $SENSOR_PROFILE $ADMIN_PROFILE up --build -d
    echo "Waiting for mosquitto to be ready..."
    until docker exec choochoo-mosquitto-fake mosquitto_sub -h localhost -t '#' -C 1 -W 1 &>/dev/null; do sleep 1; done
    ;;
  modbus)
    echo "Starting Modbus (Enterprise) mode..."
    $COMPOSE --profile modbus --profile attacker $GRAVWELL_PROFILE $SENSOR_PROFILE $ADMIN_PROFILE up --build -d
    echo "Waiting for controller to be ready..."
    until docker exec choochoo-controller-modbus python3 -c \
      "import socket; s=socket.create_connection(('localhost',5020),timeout=1); s.close()" &>/dev/null; do sleep 1; done
    ;;
  dual)
    echo "Starting dual mode (MQTT + Modbus simultaneously)..."
    MODBUS_WEB_PORT=8001 \
      $COMPOSE --profile dual --profile attacker $GRAVWELL_PROFILE $SENSOR_PROFILE $ADMIN_PROFILE up --build -d
    echo "Waiting for mosquitto to be ready..."
    until docker exec choochoo-mosquitto-fake mosquitto_sub -h localhost -t '#' -C 1 -W 1 &>/dev/null; do sleep 1; done
    echo "Waiting for Modbus controller to be ready..."
    until docker exec choochoo-controller-modbus python3 -c \
      "import socket; s=socket.create_connection(('localhost',5020),timeout=1); s.close()" &>/dev/null; do sleep 1; done
    ;;
  down)
    echo "Bringing down all profiles..."
    $COMPOSE --profile mqtt --profile modbus --profile dual --profile attacker --profile sensor --profile gravwell --profile noise --profile admin down
    ip route del 192.168.100.0/24 dev br-choochoo0 2>/dev/null || true
    exit 0
    ;;
  *)
    echo "Usage: $0 [mqtt|modbus|dual|down]" >&2
    exit 1
    ;;
esac

# Route 192.168.100.0/24 (simulated attendee IPs) through the Docker bridge
# so Zeek sees them as distinct source IPs instead of the Docker gateway NAT.
ip route replace 192.168.100.0/24 dev br-choochoo0 2>/dev/null || true

echo ""
echo "Provisioning Gravwell dashboards..."
provision_dashboards() {
  local retries=30
  local jwt=""

  until jwt=$(curl -s -X POST "${GRAVWELL_URL}/api/login" \
      -H 'Content-Type: application/json' \
      -d '{"User":"admin","Pass":"changeme"}' \
      | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['JWT'])" 2>/dev/null) \
      && [ -n "$jwt" ]; do
    retries=$((retries - 1))
    [ $retries -le 0 ] && echo "  Gravwell not ready after 30s — skipping dashboard import" && return
    sleep 1
  done

  # Fetch existing dashboards so we can delete by name before re-importing.
  local existing_json
  existing_json=$(mktemp)
  curl -s -H "Authorization: Bearer $jwt" "${GRAVWELL_URL}/api/dashboards" > "$existing_json"

  local imported=0
  for f in "${DASHBOARDS_DIR}"/*.json; do
    name=$(python3 -c "import json; print(json.load(open('$f')).get('Name','?'))")

    # Delete any existing dashboard with the same name (upsert behaviour).
    existing_id=$(python3 - "$existing_json" "$name" <<'PYEOF'
import sys, json
data = json.load(open(sys.argv[1]))
if not isinstance(data, list):
    sys.exit(0)
for d in data:
    if d.get('Name') == sys.argv[2]:
        print(d.get('ID', ''))
        sys.exit(0)
PYEOF
)
    if [ -n "$existing_id" ]; then
      curl -s -X DELETE \
        -H "Authorization: Bearer $jwt" \
        "${GRAVWELL_URL}/api/dashboards/${existing_id}" > /dev/null
    fi

    result=$(curl -s -X POST \
      -H "Authorization: Bearer $jwt" \
      -H "Content-Type: application/json" \
      "${GRAVWELL_URL}/api/dashboards" \
      --data-binary "@$f")
    # Gravwell returns a bare integer (new dashboard ID) on success
    if python3 -c "import sys,json; r=json.load(sys.stdin); exit(0 if isinstance(r, int) or 'ID' in r else 1)" <<< "$result" 2>/dev/null; then
      echo "  ✓ $name"
      imported=$((imported + 1))
    else
      echo "  ✗ $name (error: $result)"
    fi
  done
  rm -f "$existing_json"
  echo "  $imported dashboard(s) imported."
}
provision_dashboards

HOST_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")
echo ""
echo "Train UI (MQTT):   http://${HOST_IP}:8000"
echo "Train UI (Modbus): http://${HOST_IP}:8001  (dual mode only)"
echo "MQTT broker:       ${HOST_IP}:1883"
echo "Gravwell:          ${GRAVWELL_URL}  (admin / changeme)"
echo "Admin panel:       http://${HOST_IP}:9999  (admin / ${ADMIN_PASSWORD:-choochoo-admin})"
echo "Attacker:          docker exec -it choochoo-attacker bash"
echo "Attacks:           docker exec choochoo-attacker run-attack --list"
