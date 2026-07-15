#!/usr/bin/env bash
# Run a choochoo subcommand against the hardened broker.
#
#   ./scripts/run-hardened.sh controller
#   ./scripts/run-hardened.sh web --http-port 8765
#   ./scripts/run-hardened.sh send motor forward 30
#
# Each role gets its own credentials per the ACL.

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
AUTH="$ROOT/mosquitto/auth"
CA="$ROOT/mosquitto/certs/ca.crt"

if [[ ! -f "$AUTH/credentials.env" || ! -f "$CA" ]]; then
  echo "Missing credentials or CA. Run ./scripts/bootstrap-hardened.sh first." >&2
  exit 1
fi

# shellcheck disable=SC1091
. "$AUTH/credentials.env"

ROLE="${1:-}"
shift || true

export CHOOCHOO_BROKER="${CHOOCHOO_BROKER:-localhost}"
export CHOOCHOO_TLS_CA="$CA"

case "$ROLE" in
  controller)
    export CHOOCHOO_USER=controller
    export CHOOCHOO_PASSWORD="$CHOOCHOO_CONTROLLER_PW"
    exec uv run choochoo controller "$@"
    ;;
  web)
    export CHOOCHOO_USER=web
    export CHOOCHOO_PASSWORD="$CHOOCHOO_WEB_PW"
    exec uv run choochoo web "$@"
    ;;
  send)
    export CHOOCHOO_USER=operator
    export CHOOCHOO_PASSWORD="$CHOOCHOO_OPERATOR_PW"
    exec uv run choochoo send "$@"
    ;;
  *)
    echo "Usage: $0 {controller|web|send} [args...]" >&2
    exit 2
    ;;
esac
