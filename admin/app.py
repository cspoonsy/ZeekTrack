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

import asyncio
import ipaddress
import os
import queue
import subprocess
import threading
import time
from contextlib import asynccontextmanager
from typing import Annotated

import docker
import httpx
import psutil
from fastapi import Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates
import secrets

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "choochoo-admin")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
COMPOSE_FILE = os.environ.get("COMPOSE_FILE", "/compose/docker-compose.fake.yml")
COMPOSE_PROFILES = os.environ.get("COMPOSE_PROFILES", "modbus,admin").split(",")
TRAIN_API_URL = os.environ.get("TRAIN_API_URL", "http://localhost:8001")
SWITCH_API_URL = os.environ.get("SWITCH_API_URL", "http://localhost:8000")
# Network interface for throughput stats. On the admin Pi (multi-Pi deployment)
# there is no br-choochoo0 bridge — use eth0. Override via STATS_IFACE env var.
STATS_IFACE = os.environ.get("STATS_IFACE", "eth0")

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


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    await _train_client.aclose()
    await _switch_client.aclose()


app = FastAPI(title="ChooChoo Admin", docs_url=None, redoc_url=None, lifespan=lifespan)

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


def _net_rate(iface: str = STATS_IFACE) -> dict | None:
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
        "net": _net_rate(),
    }


@app.get("/api/containers")
def api_containers(_user: str = Depends(require_auth)):
    return _running_containers()


@app.get("/", response_class=HTMLResponse)
def index(request: Request, _user: str = Depends(require_auth)):
    return templates.TemplateResponse(request, "index.html", {
        "containers": _running_containers(),
        "blocked_ips": _blocked_ips(),
        "profiles": COMPOSE_PROFILES,
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
    # Explicit mapping avoids fragile string replacement silently producing wrong service names.
    _container_to_service = {
        "choochoo-mosquitto-fake":          "mosquitto",
        "choochoo-switch-controller-mqtt":  "switch-controller-mqtt",
        "choochoo-web-mqtt":                "web-mqtt",
        "choochoo-controller-modbus":       "controller-modbus",
        "choochoo-web-modbus":              "web-modbus",
        "choochoo-zeek":                    "zeek",
        "choochoo-vector":                  "vector",
    }
    service_name = _container_to_service[container_name]
    # Intentionally fire-and-forget: the compose up can take several seconds to pull/start
    # the image; we redirect immediately so the browser isn't left waiting.
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
    base = ["docker", "compose", "-f", COMPOSE_FILE] + profile_flags
    down = subprocess.run(base + ["down", "--remove-orphans"])
    if down.returncode == 0:
        subprocess.Popen(base + ["up", "-d", "--build"])
    return RedirectResponse("/", status_code=303)


@app.post("/block")
def block_ip(ip: Annotated[str, Form()], _user: str = Depends(require_auth)):
    """Insert a DROP rule in DOCKER-USER before any RETURN rules."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(400, "Provide a valid host IP address (no CIDR)")
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


# ── Train control proxy ───────────────────────────────────────────────────────
# Train (motor/stop/state) proxies to TRAIN_API_URL — web-modbus on :8001.
# Switch (throw/state) proxies to SWITCH_API_URL — web-mqtt on :8000, which
# has the SwitchBridge regardless of the train protocol.
# host network mode means container names don't resolve; use localhost + port.

_train_client = httpx.AsyncClient(base_url=TRAIN_API_URL, timeout=5.0)
_switch_client = httpx.AsyncClient(base_url=SWITCH_API_URL, timeout=5.0)


@app.get("/api/train/state")
async def api_train_state(_user: str = Depends(require_auth)):
    try:
        r = await _train_client.get("/api/state")
        return r.json()
    except Exception:
        return {"error": "train unavailable"}


@app.post("/api/train/motor")
async def api_train_motor(request: Request, _user: str = Depends(require_auth)):
    body = await request.json()
    try:
        r = await _train_client.post("/api/motor", json=body)
        return r.json()
    except Exception:
        raise HTTPException(502, "train unavailable")


@app.post("/api/train/stop")
async def api_train_stop(_user: str = Depends(require_auth)):
    try:
        r = await _train_client.post("/api/stop")
        return r.json()
    except Exception:
        raise HTTPException(502, "train unavailable")


@app.get("/api/train/switch/state")
async def api_switch_state(_user: str = Depends(require_auth)):
    try:
        r = await _switch_client.get("/api/switch/state")
        return r.json()
    except Exception:
        return {"error": "switch unavailable"}


@app.post("/api/train/switch/throw")
async def api_switch_throw(request: Request, _user: str = Depends(require_auth)):
    body = await request.json()
    try:
        r = await _switch_client.post("/api/switch/throw", json=body)
        return r.json()
    except Exception:
        raise HTTPException(502, "switch unavailable")


# ── Live log streaming ────────────────────────────────────────────────────────
# Streams Docker container logs as newline-delimited text via chunked HTTP.
# The browser reads it with fetch + ReadableStream — no WebSocket needed.

LOG_SOURCES = {
    "modbus": "choochoo-controller-modbus",
    "mqtt":   "choochoo-mosquitto-fake",
    "web":    "choochoo-web-modbus",
    "zeek":   "choochoo-zeek",
}


@app.get("/api/logs/{source}")
async def stream_logs(source: str, _user: str = Depends(require_auth)):
    container_name = LOG_SOURCES.get(source)
    if not container_name:
        raise HTTPException(400, f"Unknown log source '{source}'. Valid: {list(LOG_SOURCES)}")
    if docker_client is None:
        raise HTTPException(500, "Docker socket not available")
    try:
        container = docker_client.containers.get(container_name)
    except docker.errors.NotFound:
        raise HTTPException(404, f"{container_name} not running")

    # Zeek writes to log files, not stdout — tail notice.log inside the container.
    # Everything else streams Docker container stdout/stderr as normal.
    use_exec = (source == "zeek")

    async def generate():
        q: asyncio.Queue = asyncio.Queue()
        stop = threading.Event()
        loop = asyncio.get_running_loop()

        def _reader():
            try:
                if use_exec:
                    _, stream = container.exec_run(
                        ["tail", "-n", "100", "-f", "/logs/notice.log"],
                        stream=True, demux=False,
                    )
                    for chunk in stream:
                        if stop.is_set():
                            break
                        if chunk:
                            loop.call_soon_threadsafe(q.put_nowait, chunk)
                else:
                    for chunk in container.logs(stream=True, follow=True, tail=100, timestamps=True):
                        if stop.is_set():
                            break
                        data = chunk if isinstance(chunk, bytes) else chunk.encode()
                        loop.call_soon_threadsafe(q.put_nowait, data)
            except Exception:
                pass
            finally:
                loop.call_soon_threadsafe(q.put_nowait, None)

        threading.Thread(target=_reader, daemon=True).start()

        try:
            while True:
                item = await q.get()
                if item is None:
                    break
                yield item
        finally:
            stop.set()

    return StreamingResponse(generate(), media_type="text/plain; charset=utf-8")
