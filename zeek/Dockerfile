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

# WORKDIR creates /logs if absent — no RUN step needed (avoids AppArmor
# issues inside unprivileged LXC).
WORKDIR /logs

# -i br-choochoo0  sniff the named Docker bridge (network_mode: host).
# -C               skip bad-checksum warnings (common under Docker / QEMU).
# local            load /usr/local/zeek/share/zeek/site/local.zeek (our policy).
CMD ["/usr/local/zeek/bin/zeek", "-i", "br-choochoo0", "-C", "local"]
