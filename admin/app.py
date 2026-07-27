"""ChooChoo Admin Panel.

Password-protected panel for event operators. Provides:
  - Per-container restart / hard rebuild
  - Full stack teardown and rebuild
  - IP blacklisting via iptables DOCKER-USER chain (blocks before any container sees traffic)
  - Live system health stats (CPU, RAM, disk, network throughput)

Requires:
  - /var/run/docker.sock mounted (container control)
  - NET_ADMIN + network_mode: host (iptables, /proc stats)
  - ADMIN_PASSWORD env var (set in docker-compose — change before events)
"""

from __future__ import annotations

import os
import subprocess
import time
from typing import Annotated

import docker
import psutil
from fastapi import Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates
import secrets

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "choochoo-admin")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
COMPOSE_FILE = os.environ.get("COMPOSE_FILE", "/compose/docker-compose.fake.yml")
COMPOSE_PROFILES = os.environ.get("COMPOSE_PROFILES", "mqtt,sensor,gravwell").split(",")

RESTARTABLE_CONTAINERS = [
    "choochoo-mosquitto-fake",
    "choochoo-switch-controller-mqtt",
    "choochoo-web-mqtt",
    "choochoo-controller-modbus",
    "choochoo-web-modbus",
    "choochoo-zeek",
    "choochoo-vector",
]

# Warm up psutil CPU measurement — first call with interval=None always returns 0.0
try:
    psutil.cpu_percent(interval=None)
except Exception:
    pass

# Previous network snapshot for rate calculation: {iface: {ts, rx, tx}}
_net_snapshot: dict = {}

security = HTTPBasic()
templates = Jinja2Templates(directory="templates")
app = FastAPI(title="ChooChoo Admin", docs_url=None, redoc_url=None)

try:
    docker_client = docker.from_env()
except Exception:
    docker_client = None


def require_auth(credentials: Annotated[HTTPBasicCredentials, Depends(security)]) -> str:
    ok = (
        secrets.compare_digest(credentials.username.encode(), ADMIN_USER.encode())
        and secrets.compare_digest(credentials.password.encode(), ADMIN_PASSWORD.encode())
    )
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


def _blocked_ips() -> list[str]:
    """Return currently blocked IPs from the DOCKER-USER chain."""
    try:
        out = subprocess.check_output(
            ["iptables", "-L", "DOCKER-USER", "-n", "--line-numbers"],
            stderr=subprocess.DEVNULL,
            text=True,
        )
        ips = []
        for line in out.splitlines():
            # Lines look like: 1  DROP  all  --  1.2.3.4  0.0.0.0/0 ...
            parts = line.split()
            if len(parts) >= 5 and parts[1] == "DROP" and parts[4] not in ("0.0.0.0/0", "source"):
                ips.append(parts[4])
        return ips
    except Exception:
        return []


def _running_containers() -> list[dict]:
    if docker_client is None:
        return []
    result = []
    for name in RESTARTABLE_CONTAINERS:
        try:
            c = docker_client.containers.get(name)
            result.append({"name": name, "status": c.status, "image": c.image.tags[0] if c.image.tags else "?"})
        except docker.errors.NotFound:
            result.append({"name": name, "status": "absent", "image": "—"})
    return result


def _net_rate(iface: str = "br-choochoo0") -> dict | None:
    """Return RX/TX rates in bytes/sec for iface since the last call."""
    global _net_snapshot
    try:
        counters = psutil.net_io_counters(pernic=True)
        br = counters.get(iface)
        if br is None:
            return None
        now = time.monotonic()
        prev = _net_snapshot.get(iface)
        _net_snapshot[iface] = {"ts": now, "rx": br.bytes_recv, "tx": br.bytes_sent}
        if prev is None:
            return {"rx_bps": 0, "tx_bps": 0}
        dt = now - prev["ts"]
        if dt <= 0:
            return {"rx_bps": 0, "tx_bps": 0}
        return {
            "rx_bps": max(0, int((br.bytes_recv - prev["rx"]) / dt)),
            "tx_bps": max(0, int((br.bytes_sent - prev["tx"]) / dt)),
        }
    except Exception:
        return None


@app.get("/api/stats")
def api_stats(_user: str = Depends(require_auth)):
    try:
        cpu_pct = round(psutil.cpu_percent(interval=None), 1)
    except Exception:
        cpu_pct = None

    try:
        mem = psutil.virtual_memory()
        mem_data = {
            "used_gb": round(mem.used / 1024 ** 3, 2),
            "total_gb": round(mem.total / 1024 ** 3, 2),
            "pct": round(mem.percent, 1),
        }
    except Exception:
        mem_data = None

    try:
        disk = psutil.disk_usage("/")
        disk_data = {
            "used_gb": round(disk.used / 1024 ** 3, 1),
            "total_gb": round(disk.total / 1024 ** 3, 1),
            "pct": round(disk.percent, 1),
        }
    except Exception:
        disk_data = None

    return {
        "cpu_pct": cpu_pct,
        "mem": mem_data,
        "disk": disk_data,
        "net": _net_rate("br-choochoo0"),
    }


@app.get("/", response_class=HTMLResponse)
def index(request: Request, _user: str = Depends(require_auth)):
    return templates.TemplateResponse(request, "index.html", {
        "containers": _running_containers(),
        "blocked_ips": _blocked_ips(),
    })


@app.post("/restart/{container_name}")
def restart_container(container_name: str, _user: str = Depends(require_auth)):
    if container_name not in RESTARTABLE_CONTAINERS:
        raise HTTPException(400, "Unknown container")
    if docker_client is None:
        raise HTTPException(500, "Docker socket not available")
    try:
        c = docker_client.containers.get(container_name)
        c.restart(timeout=10)
    except docker.errors.NotFound:
        raise HTTPException(404, f"{container_name} not found")
    return RedirectResponse("/", status_code=303)


@app.post("/rebuild/{container_name}")
def rebuild_container(container_name: str, _user: str = Depends(require_auth)):
    """Stop the container, pull/rebuild its image, and start it fresh."""
    if container_name not in RESTARTABLE_CONTAINERS:
        raise HTTPException(400, "Unknown container")
    if docker_client is None:
        raise HTTPException(500, "Docker socket not available")
    try:
        c = docker_client.containers.get(container_name)
        c.stop(timeout=10)
        c.remove()
    except docker.errors.NotFound:
        pass
    except Exception as e:
        raise HTTPException(500, str(e))
    profile_flags = []
    for p in COMPOSE_PROFILES:
        profile_flags += ["--profile", p.strip()]
    service_name = container_name.replace("choochoo-", "").replace("-fake", "")
    subprocess.Popen(
        ["docker", "compose", "-f", COMPOSE_FILE] + profile_flags + ["up", "-d", "--no-deps", service_name]
    )
    return RedirectResponse("/", status_code=303)


@app.post("/stack/restart")
def stack_restart(_user: str = Depends(require_auth)):
    """Restart all containers in the stack without rebuilding images."""
    profile_flags = []
    for p in COMPOSE_PROFILES:
        profile_flags += ["--profile", p.strip()]
    subprocess.Popen(
        ["docker", "compose", "-f", COMPOSE_FILE] + profile_flags + ["restart"]
    )
    return RedirectResponse("/", status_code=303)


@app.post("/stack/rebuild")
def stack_rebuild(_user: str = Depends(require_auth)):
    """Tear down, rebuild images, and bring the full stack back up."""
    profile_flags = []
    for p in COMPOSE_PROFILES:
        profile_flags += ["--profile", p.strip()]
    subprocess.Popen([
        "bash", "-c",
        f"docker compose -f {COMPOSE_FILE} {' '.join(profile_flags)} down --remove-orphans && "
        f"docker compose -f {COMPOSE_FILE} {' '.join(profile_flags)} up -d --build"
    ])
    return RedirectResponse("/", status_code=303)


@app.post("/block")
def block_ip(ip: Annotated[str, Form()], _user: str = Depends(require_auth)):
    """Insert a DROP rule in DOCKER-USER before any RETURN rules."""
    if not ip or "/" in ip:
        raise HTTPException(400, "Provide a single host IP (no CIDR)")
    subprocess.run(
        ["iptables", "-I", "DOCKER-USER", "1", "-s", ip, "-j", "DROP"],
        check=True,
    )
    return RedirectResponse("/", status_code=303)


@app.post("/unblock")
def unblock_ip(ip: Annotated[str, Form()], _user: str = Depends(require_auth)):
    """Remove all DROP rules for this IP from DOCKER-USER."""
    blocked = _blocked_ips()
    if ip not in blocked:
        raise HTTPException(404, "IP not in blocklist")
    while ip in _blocked_ips():
        subprocess.run(
            ["iptables", "-D", "DOCKER-USER", "-s", ip, "-j", "DROP"],
            check=False,
        )
    return RedirectResponse("/", status_code=303)
