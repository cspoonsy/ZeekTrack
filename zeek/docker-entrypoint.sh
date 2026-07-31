#!/bin/sh
# Generates a deployment.zeek with site-specific authorized IP redefs from
# environment variables, then execs Zeek. This makes the image reusable
# across both the Docker single-host setup (where services have Docker bridge
# IPs) and physical multi-Pi deployments (where they have real LAN IPs)
# without rebuilding.
#
# Environment variables:
#   ZEEK_IFACE          NIC to sniff. Default: br-choochoo0 (Docker bridge).
#                       Override to eth0 (or the SPAN NIC name) on physical Pis.
#   MODBUS_MASTER_IP    IP of the legitimate Modbus master (web-modbus service).
#                       Writes from any other IP get authorized=F in Zeek logs.
#   MQTT_PUBLISHER_IP   IP of the legitimate MQTT publisher (web-mqtt service).
#                       Publishes from any other IP fire UnauthorizedPublish.

set -e

ZEEK_IFACE="${ZEEK_IFACE:-br-choochoo0}"
MODBUS_MASTER_IP="${MODBUS_MASTER_IP:-}"
MQTT_PUBLISHER_IP="${MQTT_PUBLISHER_IP:-}"

SITE="/usr/local/zeek/share/zeek/site"

# Write deployment-specific redefs. local.zeek loads this file at the end.
# Always write the file (even if empty) so the @load never fails.
{
    printf "# Generated at container start — do not edit by hand.\n"
    printf "# Source of truth: MODBUS_MASTER_IP / MQTT_PUBLISHER_IP env vars.\n"

    if [ -n "$MODBUS_MASTER_IP" ]; then
        printf "redef modbus_detect::authorized_masters += { %s };\n" "$MODBUS_MASTER_IP"
    fi

    if [ -n "$MQTT_PUBLISHER_IP" ]; then
        # The pattern allows any choochoo train topic; adjust if topic schema changes.
        printf "redef mqtt_detect::authorized_publishers += { [%s] = /choochoo\\/train\\/.*/ };\n" \
            "$MQTT_PUBLISHER_IP"
    fi
} > "$SITE/deployment.zeek"

exec /usr/local/zeek/bin/zeek -i "$ZEEK_IFACE" -C local
