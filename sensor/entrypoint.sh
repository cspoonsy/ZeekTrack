#!/bin/sh
# Microsensor container entrypoint. Container-friendly substitute for
# the systemd unit the package would normally install.

set -eu

LICENSE_PATH=/etc/corelight-license.txt
CONF_PATH=/etc/corelight-softsensor.conf

if [ ! -s "$LICENSE_PATH" ]; then
    cat >&2 <<EOF
ERROR: $LICENSE_PATH is missing or empty.

Mount the file Corelight provided you (it is *not* in the image, on
purpose). Example in docker-compose.fake.yml:

    volumes:
      - ./sensor/license/corelight-license.txt:/etc/corelight-license.txt:ro
EOF
    exit 1
fi

if [ ! -f "$CONF_PATH" ]; then
    # The package installs a default + a .example. Fall back to the example.
    if [ -f "${CONF_PATH}.example" ]; then
        cp "${CONF_PATH}.example" "$CONF_PATH"
    else
        echo "ERROR: $CONF_PATH does not exist and no example was found." >&2
        exit 1
    fi
fi

# Show what's about to start so debugging is one `docker logs` away.
echo "Starting corelight-softsensor"
echo "  binary:   $(command -v corelight-softsensor || echo 'not found')"
echo "  license:  $LICENSE_PATH ($(wc -c < $LICENSE_PATH) bytes)"
echo "  config:   $CONF_PATH"
echo "  iface:    $(ip -br link show | awk '$1 != "lo" {print $1}' | tr '\n' ' ')"

# `start` runs in the foreground, suitable for containers / `tini` PID 1.
exec corelight-softsensor start
