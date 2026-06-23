#!/usr/bin/env bash
# Generate self-signed CA + server cert + hashed password file for the
# hardened broker profile. Idempotent — re-run safe; existing files are kept.
#
# Outputs (all gitignored):
#   mosquitto/certs/{ca.crt,ca.key,server.crt,server.key}
#   mosquitto/auth/{passwords,credentials.env}
#
# `credentials.env` is the per-role secrets file the run wrapper sources.

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
CERTS="$ROOT/mosquitto/certs"
AUTH="$ROOT/mosquitto/auth"
mkdir -p "$CERTS" "$AUTH"

# --- TLS material ----------------------------------------------------------
if [[ ! -f "$CERTS/ca.crt" ]]; then
  echo "==> generating self-signed CA"
  openssl genrsa -out "$CERTS/ca.key" 4096 2>/dev/null
  openssl req -x509 -new -nodes -key "$CERTS/ca.key" -sha256 -days 3650 \
    -subj "/CN=ChooChoo Training CA" -out "$CERTS/ca.crt"
fi

if [[ ! -f "$CERTS/server.crt" ]]; then
  echo "==> generating server certificate"
  openssl genrsa -out "$CERTS/server.key" 2048 2>/dev/null
  openssl req -new -key "$CERTS/server.key" \
    -subj "/CN=choochoo-mosquitto-hardened" \
    -out "$CERTS/server.csr"
  cat > "$CERTS/server.ext" <<EOF
subjectAltName = DNS:choochoo-mosquitto-hardened, DNS:localhost, IP:127.0.0.1
EOF
  openssl x509 -req -in "$CERTS/server.csr" \
    -CA "$CERTS/ca.crt" -CAkey "$CERTS/ca.key" -CAcreateserial \
    -out "$CERTS/server.crt" -days 825 -sha256 \
    -extfile "$CERTS/server.ext"
  rm -f "$CERTS/server.csr" "$CERTS/server.ext" "$CERTS/ca.srl"
fi

# Mosquitto runs as UID 1883 in the official image; needs read on these files.
chmod 644 "$CERTS"/*.crt "$CERTS"/*.key

# --- Passwords -------------------------------------------------------------
# Generate fresh creds only if the password file is missing. Trainer can
# wipe mosquitto/auth/ to rotate.
if [[ ! -f "$AUTH/passwords" ]]; then
  echo "==> generating user credentials"
  CONTROLLER_PW=$(openssl rand -hex 16)
  WEB_PW=$(openssl rand -hex 16)
  OPERATOR_PW=$(openssl rand -hex 16)

  # mosquitto_passwd lives in the same image; use it for proper hashing.
  : > "$AUTH/passwords"
  docker run --rm -v "$AUTH:/auth" eclipse-mosquitto:2 \
    sh -c "
      mosquitto_passwd -b /auth/passwords controller '$CONTROLLER_PW' &&
      mosquitto_passwd -b /auth/passwords web        '$WEB_PW' &&
      mosquitto_passwd -b /auth/passwords operator   '$OPERATOR_PW'
    "

  cat > "$AUTH/credentials.env" <<EOF
# Sourced by scripts/run-hardened.sh — do NOT commit.
CHOOCHOO_CONTROLLER_PW='$CONTROLLER_PW'
CHOOCHOO_WEB_PW='$WEB_PW'
CHOOCHOO_OPERATOR_PW='$OPERATOR_PW'
EOF
  chmod 600 "$AUTH/credentials.env"
fi

# Mosquitto requires the password file be 0700 / 0600 or it refuses to start.
chmod 600 "$AUTH/passwords"
chmod 644 "$AUTH/acl" 2>/dev/null || true

echo
echo "Hardened bootstrap complete."
echo "  certs:       $CERTS"
echo "  passwords:   $AUTH/passwords"
echo "  credentials: $AUTH/credentials.env"
echo
echo "Next:"
echo "  docker compose -f docker-compose.hardened.yml up -d"
echo "  ./scripts/run-hardened.sh controller"
