#!/usr/bin/env bash
# CT 210 — THE TOURIST
#
# Showed up to DefCon, heard there was a hacking challenge, opened a laptop.
# Browses the web UI, clicks around, gets confused, tries a few random paths.
# Never touches MQTT or Modbus — has no idea those exist.
# Gives up and comes back 20-40 minutes later to try again.
#
# Zeek signature: HTTP to :8000, lots of 404s, periodic conn resets

set -uo pipefail

TARGET="${TARGET_HOST:-192.168.1.200}"
BROKER="${TARGET}"
WEB="${TARGET}"
CONTROLLER="${TARGET}"

# Realistic browser UA — person on a MacBook at a conference
UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

log() { echo "[tourist $(date +%H:%M:%S)] $*"; }
rnd() { python3 -c "import random; print(round(random.uniform($1,$2),1))"; }
rsleep() { sleep "$(rnd "$1" "$2")"; }

log "Tourist starting — target $TARGET"

while true; do
    log "New round — opening laptop"

    # Ping the host — "is anything even there?"
    ping -c 3 -W 2 "$TARGET" &>/dev/null && log "Host is up" || log "No ping response"
    rsleep 2 5

    # Stumbles onto the web UI — probably found the IP by asking someone
    curl -s -o /dev/null -w "%{http_code}" -A "$UA" "http://${WEB}:8000/" | while read -r code; do log "GET / -> $code"; done
    rsleep 1 3

    # Tries a bunch of paths that make no sense for a train controller
    for path in /dashboard /login /index.html /app /home /control /train \
                /api/v1 /api/v2 /swagger /docs /graphql /metrics /actuator \
                /health /admin /status /robots.txt /sitemap.xml /favicon.ico; do
        curl -s -o /dev/null -A "$UA" "http://${WEB}:8000${path}" || true
        rsleep 0.2 0.8
    done

    # Tries to curl the MQTT port as if it were HTTP — gets confused by the response
    curl -s -o /dev/null -A "$UA" --max-time 3 "http://${BROKER}:1883/" 2>/dev/null || true
    rsleep 1 2

    # Someone mentioned "MQTT" — tries mosquitto_pub with no idea what they're doing
    log "Trying MQTT (heard it's a thing)"
    mosquitto_pub -h "$BROKER" -p 1883 -t "train" -m "go fast" 2>/dev/null || true
    mosquitto_pub -h "$BROKER" -p 1883 -t "train/control" -m "speed=100" 2>/dev/null || true
    mosquitto_pub -h "$BROKER" -p 1883 -t "/train/t1" -m "on" 2>/dev/null || true
    rsleep 1 3

    # Pings a few other IPs on the subnet — "maybe there's more?"
    for host in "${TARGET%.*}.1" "${TARGET%.*}.5" "${TARGET%.*}.100" "${TARGET%.*}.254"; do
        ping -c 1 -W 1 "$host" &>/dev/null || true
    done
    rsleep 1 3

    # Tries the API endpoint — someone told them there's an API
    curl -s -A "$UA" "http://${WEB}:8000/api/state" 2>/dev/null | head -c 200 || true
    rsleep 2 4

    # Tries logging in with default creds — heard there might be a login page
    # Form-encoded so sniffpass fires HTTP_POST_Password_Seen notices
    for creds in "admin:admin" "admin:password" "user:password" "admin:123456"; do
        USER="${creds%%:*}"
        PASS="${creds##*:}"
        curl -s -o /dev/null -A "$UA" -X POST "http://${WEB}:8000/api/login" \
            --data-urlencode "username=${USER}" \
            --data-urlencode "password=${PASS}" || true
        rsleep 0.5 1.5
    done

    # Does the same thing again with slight variation (refreshing the page)
    for path in / /api/state /; do
        curl -s -o /dev/null -A "$UA" "http://${WEB}:8000${path}" || true
        rsleep 0.5 2
    done

    log "Giving up for now"
    rsleep 300 600
done
