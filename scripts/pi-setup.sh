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
SERVICE_NAME=choochoo-controller
SERVICE_TEMPLATE="$HERE/deploy/$SERVICE_NAME.service"
ENV_EXAMPLE="$HERE/deploy/controller.env.example"
ENV_DEST=/etc/choochoo/controller.env

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

echo "==> Installing systemd unit"
TMP=$(mktemp)
sed -e "s|@USER@|$USER|g" \
    -e "s|@HOME@|$HOME|g" \
    -e "s|@REPO@|$HERE|g" \
    "$SERVICE_TEMPLATE" > "$TMP"
sudo install -m 644 "$TMP" "/etc/systemd/system/$SERVICE_NAME.service"
rm -f "$TMP"

sudo install -d /etc/choochoo
if [[ ! -f "$ENV_DEST" ]]; then
  sudo install -m 644 "$ENV_EXAMPLE" "$ENV_DEST"
  echo "  (created $ENV_DEST from example)"
else
  echo "  (kept existing $ENV_DEST)"
fi

sudo systemctl daemon-reload

cat <<EOF

==> Setup complete.

Next steps:

  1. Edit the controller config:
       sudo \$EDITOR $ENV_DEST

  2. Enable and start the service:
       sudo systemctl enable --now $SERVICE_NAME

  3. Watch the logs:
       sudo journalctl -u $SERVICE_NAME -f

If you just got added to the bluetooth group, log out and back in first.
EOF
