#!/usr/bin/env bash
# One-shot setup for a Raspberry Pi running the choochoo controller.
# Idempotent — re-run safe. Designed for Raspberry Pi OS / Debian.
#
# Assumptions:
#   - The repo is already cloned on the Pi.
#   - The current user owns the repo and will own the systemd service.
#   - BLE works (built-in on Pi 3+).

set -euo pipefail

HERE=$(cd "$(dirname "$0")/.." && pwd)

# Two systemd units get installed: the train controller (Modbus outstation
# / MQTT controller depending on env) and the track-switch controller
# (always MQTT). Both are BLE-owning bare-metal processes; the rest of
# the stack runs in docker-compose.real.yml alongside them.
TRAIN_SERVICE_NAME=choochoo-controller
TRAIN_SERVICE_TEMPLATE="$HERE/deploy/$TRAIN_SERVICE_NAME.service"
TRAIN_ENV_EXAMPLE="$HERE/deploy/controller.env.example"
TRAIN_ENV_DEST=/etc/choochoo/controller.env

SWITCH_SERVICE_NAME=choochoo-switch-controller
SWITCH_SERVICE_TEMPLATE="$HERE/deploy/$SWITCH_SERVICE_NAME.service"
SWITCH_ENV_EXAMPLE="$HERE/deploy/switch-controller.env.example"
SWITCH_ENV_DEST=/etc/choochoo/switch-controller.env

if [[ "$EUID" -eq 0 ]]; then
  echo "Run this script as the user that will run the controller, not root." >&2
  exit 1
fi

echo "==> Installing system packages"
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
    git curl ca-certificates \
    bluetooth bluez libglib2.0-0 \
    python3 python3-dev build-essential

echo "==> Ensuring $USER is in the bluetooth group"
if ! id -nG "$USER" | grep -qw bluetooth; then
  sudo usermod -a -G bluetooth "$USER"
  echo "  (added — you must log out and back in before BLE will work)"
fi

if ! command -v uv >/dev/null 2>&1 && [[ ! -x "$HOME/.local/bin/uv" ]]; then
  echo "==> Installing uv"
  curl -LsSf https://astral.sh/uv/install.sh | sh
fi

UV="$HOME/.local/bin/uv"
[[ -x "$UV" ]] || UV=$(command -v uv)

echo "==> Syncing Python dependencies (--extra pi)"
cd "$HERE"
"$UV" sync --extra pi

install_unit() {
  # $1 = service name, $2 = template path, $3 = env-example path, $4 = env dest
  local svc="$1" template="$2" env_example="$3" env_dest="$4"
  local tmp
  tmp=$(mktemp)
  sed -e "s|@USER@|$USER|g" \
      -e "s|@HOME@|$HOME|g" \
      -e "s|@REPO@|$HERE|g" \
      "$template" > "$tmp"
  sudo install -m 644 "$tmp" "/etc/systemd/system/$svc.service"
  rm -f "$tmp"

  if [[ ! -f "$env_dest" ]]; then
    sudo install -m 644 "$env_example" "$env_dest"
    echo "  (created $env_dest from example)"
  else
    echo "  (kept existing $env_dest)"
  fi
}

sudo install -d /etc/choochoo

echo "==> Installing systemd unit: $TRAIN_SERVICE_NAME"
install_unit "$TRAIN_SERVICE_NAME" "$TRAIN_SERVICE_TEMPLATE" \
    "$TRAIN_ENV_EXAMPLE" "$TRAIN_ENV_DEST"

echo "==> Installing systemd unit: $SWITCH_SERVICE_NAME"
install_unit "$SWITCH_SERVICE_NAME" "$SWITCH_SERVICE_TEMPLATE" \
    "$SWITCH_ENV_EXAMPLE" "$SWITCH_ENV_DEST"

sudo systemctl daemon-reload

cat <<EOF

==> Setup complete.

Two BLE-owning services are installed. Both run bare-metal (BLE can't be
containerized without --privileged + host networking).

Next steps:

  1. Edit the train-controller config (Modbus outstation or MQTT bridge):
       sudo \$EDITOR $TRAIN_ENV_DEST

  2. Edit the track-switch controller config:
       sudo \$EDITOR $SWITCH_ENV_DEST

  3. Enable and start both services:
       sudo systemctl enable --now $TRAIN_SERVICE_NAME $SWITCH_SERVICE_NAME

  4. Watch the logs:
       sudo journalctl -u $TRAIN_SERVICE_NAME -u $SWITCH_SERVICE_NAME -f

  5. Bring up the containerized stack (web UI, broker, attacker, sensor,
     …) alongside them:
       docker compose -f docker-compose.real.yml --profile modbus --profile mqtt up -d

If you just got added to the bluetooth group, log out and back in first.
EOF
