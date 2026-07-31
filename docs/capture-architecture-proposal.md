# ChooChoo Capture Architecture — Options for Discussion

**Context:** When ChooChoo services run as Docker containers on a single host, inter-container Modbus and MQTT traffic is invisible to Zeek. This document lays out four architectural paths to solve it, ordered from least to most invasive. It also covers the specific case of containers spread across multiple Pis, since that topology changes the problem significantly.

---

## The Problem

When two containers on the same Docker bridge talk to each other (e.g. web-modbus → controller-modbus on port 5020), the kernel forwards those frames at L2 inside the bridge without going through a normal capture tap. Zeek sniffs the bridge interface but on most ARM/Raspbian kernels it sees nothing — the frames never hit the hook Zeek depends on.

The result: Zeek logs are empty or sparse for the protocols that are the whole point of the demo. Gravwell dashboards show nothing. The detection story falls flat.

**Critical point for multi-Pi deployments:** this problem only exists when two services that talk to each other run on the same Pi. Traffic between Pis crosses physical Ethernet and is visible to a SPAN port regardless of whether the services are in containers. So the capture problem can be eliminated entirely by keeping communicating service pairs on separate Pis — no kernel module changes, no macvlan tricks, no bare-metal migration required.

---

## Service Communication Map

Before discussing topology, here is the actual communication graph — which services talk to which:

| From | To | Protocol | Notes |
|------|----|----------|-------|
| web-mqtt | mosquitto | MQTT :1883 | Publishes train commands, subscribes to state |
| web-modbus | controller-modbus | Modbus TCP :5020 | Primary train control path |
| web-modbus | mosquitto | MQTT :1883 | Switch control (dual mode) |
| switch-controller-mqtt | mosquitto | MQTT :1883 | Switch throw/state |
| controller-modbus | mosquitto | MQTT :1883 | Switch mediation (dual mode) |
| attacker container | mosquitto | MQTT :1883 | MQTT attack scripts |
| attacker container | controller-modbus | Modbus TCP :5020 | Modbus attack scripts |
| Zeek | (all services) | pcap/SPAN | Passive capture only |
| Vector | Gravwell | TCP :7777 | Log forwarding |

**The pairs that matter most for capture:** `web-modbus ↔ controller-modbus` (Modbus TCP) and `web-mqtt ↔ mosquitto` (MQTT). If either of those pairs is co-located on the same Pi, their traffic is invisible to Zeek.

---

## Option A — Kernel Module Fix (No Topology Change)

**What:** Force the kernel to route bridged frames through the netfilter hook by loading `br_netfilter`. This makes inter-container traffic visible to Zeek's libpcap tap without changing anything else.

**Test first — run this with traffic active:**
```bash
tcpdump -i br-choochoo0 -c 5 tcp port 5020
```
If it returns 0 packets, the module is missing or ineffective. If it returns packets, capture is already working and there is no problem to solve.

**If the test fails, load and persist the module:**
```bash
modprobe br_netfilter
sysctl -w net.bridge.bridge-nf-call-iptables=1
echo br_netfilter >> /etc/modules-load.d/br_netfilter.conf
echo "net.bridge.bridge-nf-call-iptables=1" >> /etc/sysctl.d/99-bridge.conf
```
Then restart Zeek and re-run the test.

**Pros:**
- No hardware or topology changes
- 15-minute fix if it works
- Everything else stays the same

**Cons:**
- Raspbian and Pi OS kernels often ship without `br_netfilter` as a loadable module — it may simply not be available
- Even if loaded, reliability under traffic load on ARM is uncertain
- Still a single-host dependency, no physical network realism for the demo

**Try this first.** 15 minutes to know.

---

## Option B — Macvlan Networking (Containers Stay on One Host, Real Wire)

**What:** Give each critical container its own MAC address and IP on the physical network. Inter-container traffic flows over the physical NIC and switch instead of the Docker bridge. Zeek sniffs the physical NIC and sees everything.

**What changes:**
- Containers use `network_mode: macvlan` instead of the shared Docker bridge
- Each service gets a static IP in a dedicated lab subnet (e.g. `192.168.2.x`)
- Zeek sniffs `eth0` instead of `br-choochoo0`
- `CHOOCHOO_BROKER`, `CHOOCHOO_MODBUS_PORT` etc. point to real IPs instead of container hostnames

**Pros:**
- Reliable capture — pcap on a physical NIC always works, no kernel module dependency
- All containers stay on one Pi — no new hardware
- Real Ethernet frames, real IPs in Zeek logs

**Cons:**
- macvlan prevents containers from reaching the host's own IP on the same interface — admin panel access needs a workaround (second NIC or macvlan shim)
- Still a single physical host — one Pi failure takes everything down
- No physical topology realism

**Complexity:** Medium. Config changes only, no new hardware. Estimated 2–4 hours.

---

## Option C — Containers Spread Across Multiple Pis

**What:** Keep Docker and docker-compose as the deployment model but split services across Pis so communicating pairs are always on separate hosts. Inter-service traffic becomes physical-wire by definition. A managed switch with SPAN gives Zeek complete visibility.

### Why co-location matters

If `web-modbus` and `controller-modbus` are on the same Pi, all Modbus TCP traffic stays on the Docker bridge and is invisible to SPAN — same as the single-host problem. The fix is not a kernel module or macvlan trick. It is simply: **don't put them on the same box.**

### Service assignment for capture-safe multi-Pi deployment

The rule: services that communicate directly must be on different Pis.

| Pi | Services | Notes |
|----|----------|-------|
| Pi-1 | mosquitto broker | MQTT bus — all other services connect to this |
| Pi-2 | web-mqtt, switch-controller-mqtt | Both connect outbound to Pi-1 only |
| Pi-3 | controller-modbus | Modbus outstation — accepts connections from Pi-4 and attacker |
| Pi-4 | web-modbus | Connects to Pi-3 (Modbus) and Pi-1 (MQTT switch). Cross-Pi on both paths. |
| Pi-5 | Zeek + Vector | Passive SPAN tap — no connections to any service Pi |
| Pi-6 (optional) | Attacker tooling | Kali, attack scripts — connects to Pi-1 and Pi-3 |
| Existing Gravwell host | Gravwell SIEM | Receives Vector logs from Pi-5, no change |

With this layout every communication path in the service map crosses a physical cable. Zeek on Pi-5 sees all of it via SPAN. There are no co-located communicating pairs.

### What to avoid

These co-location combinations put traffic back on a bridge and out of Zeek's sight:

| Bad co-location | Invisible traffic |
|-----------------|-------------------|
| web-mqtt + mosquitto on same Pi | All MQTT train commands and state |
| web-modbus + controller-modbus on same Pi | All Modbus TCP (the most important path) |
| switch-controller-mqtt + mosquitto on same Pi | Switch throw/state |
| attacker + mosquitto on same Pi | MQTT attack traffic |
| attacker + controller-modbus on same Pi | Modbus attack traffic |

If Pi count is constrained (e.g. only 4 Pis), the non-negotiable separations are:
1. `web-modbus` and `controller-modbus` must be on different Pis
2. `web-mqtt` and `mosquitto` must be on different Pis

Everything else can be co-located without affecting the primary capture paths.

### Switch configuration

- Managed switch between all Pis (TP-Link TL-SG108E is ~$30 and supports SPAN)
- One SPAN port configured to mirror all switch traffic to Pi-5's NIC
- Zeek on Pi-5: `zeek -i eth0 local`

### What changes in the codebase

- `CHOOCHOO_BROKER` env vars point to Pi-1's real IP instead of `mosquitto` (container hostname)
- `CHOOCHOO_MODBUS_PORT` on web-modbus points to Pi-3's real IP instead of `controller`
- Each Pi runs `docker compose` with only its assigned service profiles
- `lab-up.sh` becomes a short SSH orchestration script that starts each Pi's compose stack
- No code changes — only env vars and compose profile splits

**Pros:**
- Reliable capture with no kernel changes and no macvlan complexity
- Docker and compose stay as-is — same images, same deployment model, easy to iterate
- Physically realistic multi-node ICS topology — separate engineering and OT nodes
- Failure isolation — Pi-3 going down doesn't affect MQTT
- The detection story is strong: "passive out-of-band SPAN tap on the OT segment"

**Cons:**
- Requires 4–6 Pis and a managed switch
- More physical hardware to transport and cable at DefCon
- Services that previously used Docker hostname resolution now need explicit IP configuration
- Pi count constrains flexibility — can't easily move a service without rechecking co-location rules

**Complexity:** Medium. Mostly env var changes and compose profile splits. No code changes. Estimated 1 day to build and test, 1–2 hours to set up at an event.

---

## Option D — Full Bare Metal (No Docker)

**What:** Each service runs as a systemd unit directly on its Pi. Same multi-Pi topology as Option C but Docker is removed entirely.

**Same node layout as Option C applies.** The co-location rules are identical — services that talk to each other still need to be on separate Pis.

**What changes beyond Option C:**
- `mosquitto`, `pymodbus` controller, and FastAPI web services all run under systemd
- Zeek and Vector run as systemd services
- `lab-up.sh` uses `systemctl start` over SSH instead of `docker compose up`
- Python virtualenvs per Pi instead of container images

**Pros:**
- Maximum realism and simplicity at runtime — no container networking layer, direct process-to-NIC
- Easier to reason about what's running and why
- No Docker daemon overhead on Pi hardware

**Cons:**
- Most invasive option — requires rewriting deployment tooling
- Harder to reproduce a clean state (`docker compose down && up` becomes manual service teardown)
- Longer initial setup, harder to iterate during development

**Complexity:** High. Better as a post-DefCon migration than a pre-event sprint.

---

## Comparison Summary

| | Option A | Option B | Option C | Option D |
|--|--|--|--|--|
| **Hardware changes** | None | None | 4–6 Pis + managed switch | 4–6 Pis + managed switch |
| **Docker retained** | Yes | Yes | Yes | No |
| **Config changes** | Kernel module + sysctl | docker-compose networking | Env vars + compose splits | systemd unit files |
| **Capture reliability** | Uncertain (kernel-dependent) | High (physical NIC) | High (SPAN, no co-located pairs) | High (SPAN, no co-located pairs) |
| **Demo realism** | Low (single host) | Medium (real IPs, one host) | High (multi-node OT topology) | High (multi-node OT topology) |
| **Failure isolation** | None | None | Yes (per-Pi) | Yes (per-Pi) |
| **Time to implement** | 15 min–2 hours | 2–4 hours | 1 day | 2 days |
| **Recommended for DefCon** | Only if it works | Fallback, no new hardware | Best balance | Post-event migration |

---

## Recommendation

**Start with Option A** — tcpdump test takes 5 minutes. If the module loads and capture works on Raspbian, nothing else needs to change.

**If A fails and Pis are available: Option C.** It keeps Docker as the deployment model (fast iteration, easy rollback), eliminates the capture problem purely through topology, and gives you a demo layout that's genuinely defensible as a realistic ICS network. The co-location rules above are the main thing to get right.

**If A fails and Pis aren't available: Option B** as a stopgap — no new hardware, reliable capture, ships for DefCon. Migrate to C afterward.

**Option D** is the right long-term architecture for a mature kit but is too invasive to rush before an event.

**Questions to align on:**
1. How many Pis do we have or can we get? (Option C needs 4 minimum, 6 is comfortable)
2. Do we have or want to buy a managed switch for SPAN? (TP-Link TL-SG108E, ~$30)
3. What is the timeline before DefCon?
4. Is the multi-node topology story worth the setup cost for this audience?
5. If we go Option C, are we comfortable with the IP-based service config (no Docker hostname resolution)?
