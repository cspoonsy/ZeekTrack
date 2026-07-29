#!/usr/bin/env bash
# Import (or re-import) all ChooChoo dashboards into a Gravwell instance.
#
# Usage:
#   ./scripts/provision-dashboards.sh
#   GRAVWELL_URL=http://192.168.1.201:80 GRAVWELL_PASS=mypass ./scripts/provision-dashboards.sh
#
# Environment variables:
#   GRAVWELL_URL    URL of the Gravwell instance  (default: http://localhost:8080)
#   GRAVWELL_USER   Gravwell admin username        (default: admin)
#   GRAVWELL_PASS   Gravwell admin password        (default: changeme)
#
# Each dashboard is upserted: if a dashboard with the same name already
# exists it is deleted first, then the JSON file is POSTed fresh. Running
# this script multiple times is safe.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DASHBOARDS_DIR="${SCRIPT_DIR}/../gravwell/dashboards"
GRAVWELL_URL="${GRAVWELL_URL:-http://localhost:8080}"
GRAVWELL_USER="${GRAVWELL_USER:-admin}"
GRAVWELL_PASS="${GRAVWELL_PASS:-changeme}"

echo "Connecting to Gravwell at ${GRAVWELL_URL} ..."

JWT=$(curl -sf -X POST "${GRAVWELL_URL}/api/login" \
    -H 'Content-Type: application/json' \
    -d "{\"User\":\"${GRAVWELL_USER}\",\"Pass\":\"${GRAVWELL_PASS}\"}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['JWT'])" 2>/dev/null) || true

if [ -z "$JWT" ]; then
  echo "ERROR: Could not authenticate to Gravwell. Check GRAVWELL_URL, GRAVWELL_USER, GRAVWELL_PASS." >&2
  exit 1
fi

echo "Authenticated. Importing dashboards from ${DASHBOARDS_DIR} ..."

EXISTING_JSON=$(mktemp)
curl -sf -H "Authorization: Bearer $JWT" "${GRAVWELL_URL}/api/dashboards" > "$EXISTING_JSON"

IMPORTED=0
for f in "${DASHBOARDS_DIR}"/*.json; do
  NAME=$(python3 -c "import json; print(json.load(open('$f')).get('Name','?'))")

  EXISTING_ID=$(python3 - "$EXISTING_JSON" "$NAME" <<'PYEOF'
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
  if [ -n "$EXISTING_ID" ]; then
    curl -sf -X DELETE \
      -H "Authorization: Bearer $JWT" \
      "${GRAVWELL_URL}/api/dashboards/${EXISTING_ID}" > /dev/null
  fi

  RESULT=$(curl -sf -X POST \
    -H "Authorization: Bearer $JWT" \
    -H "Content-Type: application/json" \
    "${GRAVWELL_URL}/api/dashboards" \
    --data-binary "@$f")

  if python3 -c "import sys,json; r=json.load(sys.stdin); exit(0 if isinstance(r,int) or 'ID' in r else 1)" <<< "$RESULT" 2>/dev/null; then
    echo "  ✓ $NAME"
    IMPORTED=$((IMPORTED + 1))
  else
    echo "  ✗ $NAME (error: $RESULT)"
  fi
done

rm -f "$EXISTING_JSON"
echo "$IMPORTED dashboard(s) imported."
