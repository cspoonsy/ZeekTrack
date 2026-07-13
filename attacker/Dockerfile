# Kali-based attacker container for the ChooChoo training exercise.
#
# Designed for virtual events where attendees can't bring their own LAN box.
# Trainee shells into this container with `docker exec -it choochoo-attacker
# bash` and runs the same recon / exploit tools they'd run from a physical
# Kali machine on a real LAN.
#
# Build:
#   docker build -t choochoo-attacker:dev attacker/
#
# Use via docker-compose.fake.yml --profile attacker.

FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

# Install the toolset the trainer's playbook actually uses. Kali ships with
# most of these in metapackages, but the rolling base is minimal — we name
# them explicitly so an audit trail of "what's in the box" is visible.
#
# Roughly grouped:
#   recon:        nmap, dnsutils, netcat, tcpdump
#   mqtt:         mosquitto-clients (mosquitto_pub/sub)
#   modbus:       mbpoll (industrial Modbus client)
#   http/curl:    curl, jq, wget
#   scripting:    python3 + pip + pymodbus, paho-mqtt for ad-hoc scripts
#   convenience:  vim-tiny, less, iproute2 for "where am I on the network"
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap dnsutils ncat tcpdump iproute2 \
        mosquitto-clients \
        mbpoll \
        smbclient \
        curl jq wget \
        python3 python3-pip python3-venv \
        vim-tiny less ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Python attack libs into a venv so we don't fight Kali's PEP 668.
RUN python3 -m venv /opt/attack && \
    /opt/attack/bin/pip install --no-cache-dir paho-mqtt pymodbus

ENV PATH="/opt/attack/bin:${PATH}"

# Cheat sheet baked into the image — `cat /opt/cheatsheet.md` from inside
# the container. Mirrors the suggested attacker progression in
# VULNERABILITIES.md so the trainer doesn't have to dictate URLs.
COPY cheatsheet.md /opt/cheatsheet.md

# Named attack scenarios — callable as `run-attack <name>` from inside the
# container, or `docker exec choochoo-attacker run-attack <name>` from the host.
COPY attacks/ /opt/attacks/
RUN chmod +x /opt/attacks/* && \
    ln -s /opt/attacks/run-attack /usr/local/bin/run-attack

# Drop the user into /work so any artifacts they create end up in a known
# place. The compose file mounts the project read-only at /project.
WORKDIR /work

# Long-running idle command so the container stays up; trainee execs in.
# Plain `bash -c` (not `-l`) so the venv on $PATH set above sticks.
CMD ["bash", "-c", "echo 'ChooChoo attacker container ready. run-attack --list to see scenarios.'; /opt/attacks/noise-attendee > /tmp/noise-attendee.log 2>&1 & exec sleep infinity"]
