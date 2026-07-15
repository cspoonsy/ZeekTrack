"""Simulated end-user workstation traffic.

Walks a weighted random schedule of HTTP fetches, SMB list/reads, DNS
lookups, and the occasional legitimate ChooChoo dashboard view. Cycles
between "active" bursts and idle periods so the wire pattern looks like
a real workstation rather than a synthetic torrent.

All targets are read from env vars, defaulting to the docker-compose
hostnames. Logs each action to stdout (visible via `docker logs`).
"""

from __future__ import annotations

import os
import random
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

INTRANET = os.environ.get("CHOOCHOO_INTRANET", "http://intranet")
DASHBOARD = os.environ.get("CHOOCHOO_DASHBOARD", "http://web-mqtt:8000")
FILESHARE_HOST = os.environ.get("CHOOCHOO_FILESHARE_HOST", "fileshare")
FILESHARE_NAME = os.environ.get("CHOOCHOO_FILESHARE_NAME", "section7")

INTRANET_PATHS = [
    "/", "/", "/",                  # weighted: portal hit is most common
    "/status",
    "/reports/", "/reports/2026-05-14.txt", "/reports/2026-05-15.txt",
    "/files/", "/files/track-layout.txt", "/files/safety-policy.txt",
]

DNS_LOOKUPS = [
    "intranet", "fileshare",
    "web-mqtt", "web-modbus",       # whichever exists
    "controller", "mosquitto",
]


def log(msg: str) -> None:
    print(msg, flush=True)


def http_get(url: str, timeout: float = 5.0) -> None:
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AcmeRailWorkstation/1.0"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp.read()
            log(f"HTTP {resp.status} {url}")
    except (urllib.error.URLError, TimeoutError) as e:
        log(f"HTTP fail {url}: {e}")


def dns_lookup(name: str) -> None:
    try:
        ip = socket.gethostbyname(name)
        log(f"DNS {name} -> {ip}")
    except socket.gaierror as e:
        log(f"DNS fail {name}: {e}")


def smb_list_share() -> None:
    """Anonymously list the SMB share's root."""
    try:
        out = subprocess.run(
            ["smbclient", "-N", "-L", f"//{FILESHARE_HOST}/", "--option=client min protocol=NT1"],
            capture_output=True, text=True, timeout=8.0,
        )
        log(f"SMB list //{FILESHARE_HOST}/ exit={out.returncode}")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        log(f"SMB list fail: {e}")


def smb_read_file() -> None:
    """Pick a file in the share and read it."""
    candidates = ["welcome.txt", "contacts.txt", "maintenance-2026Q2.csv"]
    target = random.choice(candidates)
    try:
        out = subprocess.run(
            [
                "smbclient", "-N", f"//{FILESHARE_HOST}/{FILESHARE_NAME}",
                "--option=client min protocol=NT1",
                "-c", f"get {target} /tmp/last-fetch",
            ],
            capture_output=True, text=True, timeout=8.0,
        )
        log(f"SMB read {target} exit={out.returncode}")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        log(f"SMB read fail: {e}")


def dashboard_view() -> None:
    # An ops user occasionally checks the train dashboard. A read of /api/state
    # mirrors what the legitimate operator's browser does on a refresh.
    http_get(f"{DASHBOARD}/api/state")


# Weighted action table — closer to a real ops user's day. Tweak freely.
ACTIONS = [
    (5, lambda: http_get(INTRANET + random.choice(INTRANET_PATHS))),
    (2, lambda: dns_lookup(random.choice(DNS_LOOKUPS))),
    (2, smb_list_share),
    (2, smb_read_file),
    (1, dashboard_view),
]


def pick_action():
    weights = [w for w, _ in ACTIONS]
    fns = [f for _, f in ACTIONS]
    return random.choices(fns, weights=weights, k=1)[0]


def main() -> int:
    log(f"user simulator starting; intranet={INTRANET} dashboard={DASHBOARD} smb=//{FILESHARE_HOST}/{FILESHARE_NAME}")
    # Stagger start so multiple user containers don't all fire at the same moment.
    time.sleep(random.uniform(2, 6))
    while True:
        # Active burst: 6-15 actions, ~0.5-3s apart.
        burst_size = random.randint(6, 15)
        for _ in range(burst_size):
            try:
                pick_action()()
            except Exception as e:  # noqa: BLE001
                log(f"action error: {e}")
            time.sleep(random.uniform(0.5, 3.0))
        # Idle period: 30-90s, like a user reading or away from desk.
        idle = random.uniform(30, 90)
        log(f"idle {idle:.0f}s")
        time.sleep(idle)


if __name__ == "__main__":
    sys.exit(main())
