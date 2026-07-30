#!/usr/bin/env bash
# persona-setup.sh — Create 4 LXC persona containers on Proxmox.
#
# Each container is a distinct simulated DefCon attendee with its own
# 192.168.1.x IP, skill level, and behavior loop running as a systemd service.
#
# CTs created:
#   210  tourist       — confused normie, browses the web UI, gives up
#   211  recon         — methodical analyst, maps everything, never acts
#   212  wrong-path    — capable but wrong assumptions at every turn
#   213  the-one       — reads the beacon, sends valid commands, wins
#
# Usage (run as root on the Proxmox host):
#   bash persona-setup.sh
#
# Prerequisites:
#   - debian-13-standard template already downloaded to local storage
#   - This script in the same directory as persona-*.sh
#
# To tear down:
#   for id in 210 211 212 213; do pct stop $id; pct destroy $id; done

set -euo pipefail

TEMPLATE="local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst"
STORAGE="local-lvm"
BRIDGE="vmbr0"
GW="192.168.1.1"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

TARGET_HOST="${TARGET_HOST:-192.168.1.200}"
GRAVWELL_URL="${GRAVWELL_URL:-http://192.168.1.201:80}"

declare -A PERSONAS=(
    [210]="tourist"
    [211]="recon"
    [214]="wrong-path"
    [213]="the-one"
)

declare -A IPS=(
    [210]="192.168.1.210"
    [211]="192.168.1.211"
    [214]="192.168.1.214"
    [213]="192.168.1.213"
)

for VMID in "${!PERSONAS[@]}"; do
    NAME="${PERSONAS[$VMID]}"
    IP="${IPS[$VMID]}"
    SCRIPT="${SCRIPT_DIR}/persona-${NAME}.sh"

    if ! [ -f "$SCRIPT" ]; then
        echo "ERROR: missing $SCRIPT" >&2
        exit 1
    fi

    if pct status "$VMID" &>/dev/null; then
        echo "CT $VMID already exists — skipping creation"
    else
        echo "Creating CT $VMID ($NAME) at $IP..."
        pct create "$VMID" "$TEMPLATE" \
            --hostname "choochoo-${NAME}" \
            --storage "$STORAGE" \
            --rootfs "${STORAGE}:4" \
            --memory 256 \
            --cores 1 \
            --net0 "name=eth0,bridge=${BRIDGE},ip=${IP}/24,gw=${GW},type=veth" \
            --unprivileged 1 \
            --features "nesting=1" \
            --password "choochoo" \
            --start 0
    fi

    echo "Provisioning CT $VMID ($NAME)..."
    pct start "$VMID" 2>/dev/null || true
    sleep 3

    # Copy persona script in
    pct push "$VMID" "$SCRIPT" /usr/local/bin/persona
    pct exec "$VMID" -- chmod +x /usr/local/bin/persona

    # Bootstrap: install tools, write systemd service, enable
    pct exec "$VMID" -- bash -c "
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
    nmap dnsutils netcat-openbsd tcpdump iproute2 curl wget \
    mosquitto-clients \
    mbpoll \
    python3 python3-pip python3-venv \
    smbclient \
    iputils-ping \
    2>/dev/null

python3 -m venv /opt/persona-env
/opt/persona-env/bin/pip install --no-cache-dir paho-mqtt pymodbus 2>/dev/null

# Write systemd unit with the resolved TARGET_HOST value
cat > /etc/systemd/system/persona.service << EOF
[Unit]
Description=ChooChoo Persona Behaviour Loop
After=network-online.target
Wants=network-online.target

[Service]
Environment=TARGET_HOST=${TARGET_HOST}
ExecStart=/usr/local/bin/persona
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable persona
systemctl start persona
"

    echo "  CT $VMID ($NAME) — up at $IP"
done

echo ""
echo "All persona containers running:"
for VMID in 210 211 213 214; do
    NAME="${PERSONAS[$VMID]}"
    IP="${IPS[$VMID]}"
    echo "  CT $VMID  ${IP}  ${NAME}  $(pct status $VMID 2>/dev/null | awk '{print $2}')"
done
echo ""
echo "Logs:  pct exec <VMID> -- journalctl -u persona -f"
echo "Stop:  pct stop <VMID>"
echo "Start: pct start <VMID>"
