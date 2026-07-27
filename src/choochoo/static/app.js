const $ = (id) => document.getElementById(id);
const logEl = $("log");
const log = (msg) => {
  logEl.textContent = `${new Date().toISOString()} ${msg}\n` + logEl.textContent;
};

const powerInput = $("power-input");
const powerLabel = $("power-label");
powerInput.addEventListener("input", () => (powerLabel.textContent = powerInput.value));

const lightInput = $("light-input");
const lightLabel = $("light-label");
lightInput.addEventListener("input", () => {
  lightLabel.textContent = lightInput.value;
  send("/api/light", { brightness: Number(lightInput.value) });
});

$("btn-forward").onclick = () =>
  send("/api/motor", { direction: "forward", power: Number(powerInput.value) });
$("btn-reverse").onclick = () =>
  send("/api/motor", { direction: "reverse", power: Number(powerInput.value) });
$("btn-stop").onclick = () => send("/api/stop", {});

async function send(path, body) {
  // Animate the command flowing across the network panel. MQTT goes via
  // the broker; Modbus is point-to-point so we skip the broker hop.
  // Packets launch optimistically before the POST returns; if the call
  // fails the visual is still informative because the packet *was* sent.
  const fwd = PROTOCOL === "modbus"
    ? ["browser", "controller", "train"]
    : ["browser", "broker", "controller", "train"];
  packetChain(fwd, "#3fb950", 220);
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  log(`POST ${path} ${JSON.stringify(body)} -> ${res.status}`);
}

const trainState = { direction: null, power: 0 };

function applyState(s) {
  $("train-id").textContent = s.train_id ?? "?";
  $("connected").textContent = s.connected ? "yes" : "no";
  $("direction").textContent = s.direction ?? "—";
  $("power").textContent = s.power ?? 0;
  $("power-bar").value = s.power ?? 0;
  trainState.direction = s.direction ?? null;
  trainState.power = s.power ?? 0;
  renderLinkStatus(s.connected === true ? "up" : s.connected === false ? "down" : "unknown");
}

// BLE link status: pill in the header + live styling of the topology's
// controller-to-train segment. `connected` is authoritative — it comes from
// the controller's TrainClient.state().connected (BuWizzTrain flips it to
// true only after a successful GATT connect).
const LINK_STATES = {
  up:      { cls: "link-pill--up",      text: "BLE • Connected",    line: "#3fb950", label: "BLE (connected)",    trainOpacity: "1"   },
  down:    { cls: "link-pill--down",    text: "BLE • Disconnected", line: "#f85149", label: "BLE (disconnected)", trainOpacity: "0.3" },
  unknown: { cls: "link-pill--unknown", text: "BLE • …",            line: "#30363d", label: "BLE",                trainOpacity: "0.6" },
};
let linkState = "unknown";

function renderLinkStatus(next) {
  if (next === linkState) return;
  linkState = next;
  const cfg = LINK_STATES[next];
  const pill = $("link-pill");
  pill.classList.remove("link-pill--up", "link-pill--down", "link-pill--unknown");
  pill.classList.add(cfg.cls);
  $("link-pill-text").textContent = cfg.text;
  const line = $("link-controller-train");
  if (line) line.setAttribute("stroke", cfg.line);
  const label3 = $("label-link3");
  if (label3) label3.textContent = cfg.label;
  const trainRect = $("node-train-rect");
  if (trainRect) trainRect.setAttribute("opacity", cfg.trainOpacity);
}

// --- Visualization ---------------------------------------------------------
// Integrate power over time to move a sprite along the SVG track path.
// Power is unitless (0-100); we pick a scale factor that feels right for
// the Powered Up train at max throttle.
const trackPath = $("track-path");
const trackLen = trackPath.getTotalLength();
// Backend caps power at MAX_POWER (injected via meta tag); rescale the
// animation so that running at the cap looks like a healthy speed rather
// than 50%-of-imagined-max.
const MAX_POWER = Number(
  document.querySelector('meta[name="choochoo-max-power"]')?.content ?? 100
);
const PROTOCOL = (
  document.querySelector('meta[name="choochoo-protocol"]')?.content ?? "mqtt"
).toLowerCase();

// Adjust the topology panel to match the active protocol. Modbus is
// point-to-point — there's no broker — so we hide that node and relabel
// the link between the browser and controller.
(function applyProtocolUi() {
  const pill = document.getElementById("mode-pill");
  if (PROTOCOL === "modbus") {
    pill.textContent = "ENTERPRISE / MODBUS";
    pill.classList.add("modbus");
    document.getElementById("label-link1").textContent = "HTTP";
    document.getElementById("label-link2").textContent = "Modbus/TCP 5020";
    document.getElementById("node-broker-label").textContent = "—";
    document.getElementById("node-broker-rect").setAttribute("opacity", "0.3");
  } else {
    pill.textContent = "IOT / MQTT";
    pill.classList.add("mqtt");
    document.getElementById("label-link1").textContent = "MQTT/WS";
    document.getElementById("label-link2").textContent = "MQTT 1883";
    document.getElementById("node-broker-label").textContent = "Broker";
  }
})();
const PX_PER_SEC_AT_MAX_POWER = 140;

// Each car (locomotive + tenders) gets positioned at lead-position minus
// its data-offset. Picked up from the DOM so adding cars is markup-only.
const cars = Array.from(document.querySelectorAll("#consist > g")).map((el) => ({
  el,
  offset: Number(el.dataset.offset ?? 0),
}));

const signals = Array.from(document.querySelectorAll(".signal")).map((el) => ({
  el,
  pos: Number(el.dataset.stationPos ?? 0),
}));

const stations = Array.from(document.querySelectorAll(".station")).map((el) => ({
  el,
  pos: Number(el.dataset.station ?? 0),
  flashing: false,
}));

let position = 0;
let lastTs = null;

function placeAt(el, distance) {
  const d = ((distance % trackLen) + trackLen) % trackLen;
  const here = trackPath.getPointAtLength(d);
  const ahead = trackPath.getPointAtLength((d + 1) % trackLen);
  const angle = (Math.atan2(ahead.y - here.y, ahead.x - here.x) * 180) / Math.PI;
  el.setAttribute("transform", `translate(${here.x} ${here.y}) rotate(${angle})`);
}

function pathDistance(a, b) {
  // Shortest signed distance from a to b around the loop. Negative means
  // b is "behind" a along the direction of travel.
  let d = b - a;
  if (d > trackLen / 2) d -= trackLen;
  if (d < -trackLen / 2) d += trackLen;
  return d;
}

function updateSignals() {
  // Green = clear; yellow = train approaching from <=80px ahead;
  // red = train within 25px or already at the platform.
  for (const s of signals) {
    const ahead = pathDistance(position, s.pos);
    let color = "#3fb950";
    if (Math.abs(ahead) < 25) color = "#f85149";
    else if (ahead > 0 && ahead < 80) color = "#f7e97a";
    s.el.setAttribute("fill", color);
  }
}

function checkStationPass(prev, next) {
  // Detect when the train crossed a station's path-distance this frame.
  // We compare prev/next positions modulo trackLen.
  for (const s of stations) {
    const wrapped = ((s.pos - prev) % trackLen + trackLen) % trackLen;
    const stepped = ((next - prev) % trackLen + trackLen) % trackLen;
    // Train moved forward through a station this frame if `wrapped <= stepped`
    // and stepped is small (we didn't lap the whole track).
    if (stepped > 0 && stepped < trackLen / 2 && wrapped <= stepped && !s.flashing) {
      flashStation(s);
    }
  }
}

function flashStation(s) {
  s.flashing = true;
  s.el.classList.add("flash");
  setTimeout(() => {
    s.el.classList.remove("flash");
    s.flashing = false;
  }, 250);
}

function tick(ts) {
  if (lastTs == null) lastTs = ts;
  const dt = (ts - lastTs) / 1000;
  lastTs = ts;

  const signed =
    trainState.direction === "forward" ? 1 :
    trainState.direction === "reverse" ? -1 : 0;
  const velocity = (trainState.power / MAX_POWER) * PX_PER_SEC_AT_MAX_POWER * signed;

  const prevPosition = position;
  position = (position + velocity * dt) % trackLen;
  if (position < 0) position += trackLen;

  if (signed > 0) checkStationPass(prevPosition, position);

  for (const car of cars) placeAt(car.el, position - car.offset);
  updateSignals();

  // Cone widens with current power; the steady headlight bulb still tracks
  // the light slider only.
  const cone = $("headlight-cone");
  if (cone) {
    const conePower = trainState.power / MAX_POWER;
    cone.setAttribute("opacity", String(Math.min(0.7, conePower * 0.7 * coneLightFactor)));
  }

  requestAnimationFrame(tick);
}
requestAnimationFrame(tick);

// Headlight reflects the light command; the cone visibility is gated on it
// so dark = no cone even if you're at full throttle.
let coneLightFactor = 0;
function setHeadlight(brightness) {
  $("train-headlight").setAttribute("opacity", String(Math.min(1, brightness / 10)));
  coneLightFactor = Math.min(1, brightness / 10);
}
lightInput.addEventListener("input", () => setHeadlight(Number(lightInput.value)));

// --- Derailment detector ---------------------------------------------------
// A throttle-stuck attacker drives state churn far above what a human or
// the legit UI produces. We watch the rolling rate of state messages and
// flash a derailment warning when it spikes past a threshold.
const stateTimes = [];
const STATE_RATE_WINDOW_MS = 1000;
const STATE_RATE_THRESHOLD = 6;  // > N msgs/s within window = anomaly
let derailUntil = 0;

function recordStateMessage() {
  const now = performance.now();
  stateTimes.push(now);
  while (stateTimes.length && stateTimes[0] < now - STATE_RATE_WINDOW_MS) {
    stateTimes.shift();
  }
  // Reverse chain. Drawn in a different color to keep command vs. state
  // visually distinct. Modbus skips the broker hop here too.
  const rev = PROTOCOL === "modbus"
    ? ["train", "controller", "browser"]
    : ["train", "controller", "broker", "browser"];
  packetChain(rev, "#f0883e", 220);
  if (stateTimes.length > STATE_RATE_THRESHOLD) {
    triggerDerail();
  } else if (now > derailUntil) {
    clearDerail();
  }
}

function triggerDerail() {
  derailUntil = performance.now() + 1500;
  document.getElementById("track-svg").classList.add("derailed");
  const banner = document.getElementById("alert-banner");
  banner.textContent = "ANOMALY: rapid state churn — possible MQTT flood";
  banner.classList.remove("hidden");
}

function clearDerail() {
  document.getElementById("track-svg").classList.remove("derailed");
  document.getElementById("alert-banner").classList.add("hidden");
}

// Auto-clear the alert when the message rate has been quiet for a beat,
// even if no new messages arrive to trigger recordStateMessage.
setInterval(() => {
  if (derailUntil && performance.now() > derailUntil) {
    derailUntil = 0;
    clearDerail();
  }
}, 250);

// --- Network panel packet animation ---------------------------------------
// Each call animates a single dot from one node to the next. `packetChain`
// strings these together so a command/state crosses every hop in turn.
const SVG_NS = "http://www.w3.org/2000/svg";
const networkNodes = {
  browser:    document.getElementById("node-browser"),
  broker:     document.getElementById("node-broker"),
  controller: document.getElementById("node-controller"),
  train:      document.getElementById("node-train"),
};
const packetsLayer = document.getElementById("packets");

function nodeXY(name) {
  const el = networkNodes[name];
  return [Number(el.dataset.x), Number(el.dataset.y)];
}

function packetHop(from, to, color, durationMs) {
  return new Promise((resolve) => {
    const [x1, y1] = nodeXY(from);
    const [x2, y2] = nodeXY(to);
    const dot = document.createElementNS(SVG_NS, "circle");
    dot.setAttribute("r", "3");
    dot.setAttribute("fill", color);
    dot.setAttribute("cx", String(x1));
    dot.setAttribute("cy", String(y1));
    packetsLayer.appendChild(dot);
    const start = performance.now();
    function step(now) {
      const t = Math.min(1, (now - start) / durationMs);
      dot.setAttribute("cx", String(x1 + (x2 - x1) * t));
      dot.setAttribute("cy", String(y1 + (y2 - y1) * t));
      if (t < 1) {
        requestAnimationFrame(step);
      } else {
        dot.remove();
        resolve();
      }
    }
    requestAnimationFrame(step);
  });
}

async function packetChain(nodes, color, totalMs) {
  const perHop = totalMs / (nodes.length - 1);
  for (let i = 0; i < nodes.length - 1; i++) {
    await packetHop(nodes[i], nodes[i + 1], color, perHop);
  }
}

fetch("/api/state").then((r) => r.json()).then(applyState).catch(() => {});

function connectWs() {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  const ws = new WebSocket(`${proto}//${location.host}/ws/state`);
  ws.onmessage = (ev) => {
    try {
      const s = JSON.parse(ev.data);
      applyState(s);
      recordStateMessage();
      log(`state: ${ev.data}`);
    } catch (e) {
      log(`parse error: ${e}`);
    }
  };
  ws.onclose = () => {
    log("ws closed, reconnecting in 2s");
    renderLinkStatus("unknown");
    setTimeout(connectWs, 2000);
  };
  ws.onerror = () => ws.close();
}
connectWs();
