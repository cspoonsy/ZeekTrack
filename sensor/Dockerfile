# Corelight Microsensor container.
#
# Builds an x86_64 Debian image with the official corelight-softsensor
# package (1.25.0+) installed from Corelight's stable repo. Two things
# the user has to provide:
#
#   1. A package-repo auth token at build time (build-arg
#      CORELIGHT_TOKEN). Get it from my.corelight.cloud -> Downloads ->
#      Microsensor.
#   2. A license file at run time, mounted at /etc/corelight-license.txt.
#      Get it from your Corelight account manager.
#
# Build (from repo root):
#   docker build --platform linux/amd64 \
#     --build-arg CORELIGHT_TOKEN=<your-token> \
#     -t choochoo-sensor:dev sensor/
#
# The image is amd64-only because the package is only published for
# x86_64. Apple Silicon hosts will run it under QEMU emulation via Docker
# Desktop — it works but it is slow.

FROM --platform=linux/amd64 debian:bookworm-slim

ARG CORELIGHT_TOKEN

RUN test -n "$CORELIGHT_TOKEN" || \
    (echo "ERROR: set CORELIGHT_TOKEN build-arg" >&2 && exit 2)

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl gnupg ca-certificates apt-transport-https \
        tini iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Install the Corelight repo signing key + package source. Token only
# lives in build-time apt config; it is *not* baked into the final layer.
RUN install -d /etc/apt/keyrings /etc/apt/auth.conf.d /etc/apt/sources.list.d && \
    curl -fsSL "https://${CORELIGHT_TOKEN}:@pkgrepos.corelight.cloud/corelight/microsensor-stable/gpgkey" \
        | gpg --dearmor > /etc/apt/keyrings/corelight_microsensor-stable-archive-keyring.gpg && \
    echo "deb [signed-by=/etc/apt/keyrings/corelight_microsensor-stable-archive-keyring.gpg] https://pkgrepos.corelight.cloud/corelight/microsensor-stable/any/ any main" \
        > /etc/apt/sources.list.d/corelight_microsensor-stable.list && \
    printf 'machine pkgrepos.corelight.cloud/corelight/microsensor-stable/ login %s password irrelevant\n' \
        "$CORELIGHT_TOKEN" > /etc/apt/auth.conf.d/corelight_microsensor-stable.conf && \
    apt-get update && \
    apt-get install -y --no-install-recommends corelight-softsensor && \
    # Strip the auth file so the token doesn't ship in the image layers.
    rm -f /etc/apt/auth.conf.d/corelight_microsensor-stable.conf && \
    rm -rf /var/lib/apt/lists/*

# Wrapper that fails loudly if the license file isn't mounted, then runs
# the sensor in the foreground (containers want PID 1, not systemd).
COPY entrypoint.sh /usr/local/bin/choochoo-sensor-entry
RUN chmod +x /usr/local/bin/choochoo-sensor-entry

# Persistent state. Mount a volume here to keep logs across restarts.
VOLUME ["/var/corelight"]

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/choochoo-sensor-entry"]
