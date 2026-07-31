# FOSS Zeek for ChooChoo.
#
# Runs the official `zeek/zeek` image against the container's eth0 with a
# minimal site policy that enables JSON logs + the MQTT and Modbus
# analyzers (the two protocols we actually care about for this exercise).
# Logs land in /logs, which the compose file mounts as a named volume so
# the Vector sidecar can tail them and ship them to Gravwell.
#
# No license, no auth token — same detection surface (conn / dns / http /
# ssl / mqtt / modbus / files) as the Corelight softsensor for the
# training exercise.

FROM zeek/zeek:latest

COPY local.zeek /usr/local/zeek/share/zeek/site/local.zeek

# ChooChoo OT detection packages (loaded directly, no zkg required).
COPY cluster_relay_lib  /usr/local/zeek/share/zeek/site/cluster_relay_lib
COPY modbus-detections  /usr/local/zeek/share/zeek/site/modbus-detections
COPY mqtt-detections    /usr/local/zeek/share/zeek/site/mqtt-detections

# Entrypoint generates a deployment.zeek with site-specific IP redefs from
# env vars (MODBUS_MASTER_IP, MQTT_PUBLISHER_IP, ZEEK_IFACE), then execs
# Zeek. This makes the image usable on both Docker single-host (bridge IPs)
# and physical multi-Pi deployments (real LAN IPs) without rebuilding.
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# WORKDIR creates /logs if absent — no RUN step needed (avoids AppArmor
# issues inside unprivileged LXC).
WORKDIR /logs

# ZEEK_IFACE defaults to br-choochoo0 (Docker bridge, single-host mode).
# Override to eth0 or the SPAN NIC name for physical multi-Pi deployments.
ENV ZEEK_IFACE=br-choochoo0

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
