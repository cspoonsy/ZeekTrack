# Workstation traffic simulator.
#
# Walks a weighted random schedule of HTTP / SMB / DNS / dashboard actions
# at human-ish pacing so Zeek sees a realistic baseline. The attacker's
# probes have to stand out against this.

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 \
        smbclient \
        ca-certificates \
        iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY simulate.py /app/simulate.py

CMD ["python3", "-u", "/app/simulate.py"]
