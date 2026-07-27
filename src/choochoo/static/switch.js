// Track-switch panel. Subscribes to /ws/switch/state, renders position +
// connection + cooldown, and POSTs to /api/switch/throw on button clicks.
//
// Wrapped in an IIFE so its top-level `const $` and helpers don't collide
// with app.js's identically-named globals — plain <script> tags share
// one global scope.
(() => {

// Wire <-> visual direction mapping. The physical switch has three gears
// between the motor and the rack, which inverts rotation direction.
// Every planned switch in this range uses the same 3-gear mechanism, so
// this mapping is a fixed system invariant, not a per-switch parameter.
const UI_STRAIGHT_WIRE_DIRECTION = "forward";
const UI_CURVE_WIRE_DIRECTION    = "reverse";

// Must match SWITCH_COOLDOWN_S in switch_protocol.py (2.0 s = 2000 ms).
// If that constant changes, update here too — the cooldown progress bar's
// max needs to match the controller's actual cooldown window.
const COOLDOWN_MS = 2000;

const $ = (id) => document.getElementById(id);
const positionPill = $("switch-position-pill");
const connPill     = $("switch-conn-pill");
const connText     = $("switch-conn-text");
const cooldownBar  = $("switch-cooldown-bar");
const cooldownText = $("switch-cooldown-remaining");
const lastEvent    = $("switch-last-event");
const btnStraight  = $("btn-throw-straight");
const btnCurve     = $("btn-throw-curve");

let latestCooldownUntilMs = 0;

function labelForPosition(wirePosition) {
  if (wirePosition === UI_STRAIGHT_WIRE_DIRECTION) {
    return { label: "Straight", cls: "switch-pill--straight" };
  }
  if (wirePosition === UI_CURVE_WIRE_DIRECTION) {
    return { label: "Curve", cls: "switch-pill--curve" };
  }
  return { label: "Unknown", cls: "switch-pill--unknown" };
}

function renderState(state) {
  const { label, cls } = labelForPosition(state.position);
  positionPill.textContent = label;
  positionPill.className = `switch-pill ${cls}`;

  connPill.classList.remove("link-pill--up", "link-pill--down", "link-pill--unknown");
  if (state.connected === true) {
    connPill.classList.add("link-pill--up");
    connText.textContent = "Switch · Connected";
  } else if (state.connected === false) {
    connPill.classList.add("link-pill--down");
    connText.textContent = "Switch · Disconnected";
  } else {
    connPill.classList.add("link-pill--unknown");
    connText.textContent = "Switch · …";
  }

  // cooldown_until_ts is seconds-since-epoch from the controller. Store
  // it in ms for cheap comparison against Date.now().
  latestCooldownUntilMs = (state.cooldown_until_ts || 0) * 1000;
}

// Cooldown ticker. Runs regardless of state pushes so the bar shrinks
// smoothly. Disables buttons while > 0.
//
// Caveat: this uses the browser's clock, so if the browser and controller
// clocks drift by more than a second the button-disable will feel wrong.
// Fine on a LAN where both machines sync from the same source.
setInterval(() => {
  const remainingMs = Math.max(0, latestCooldownUntilMs - Date.now());
  cooldownBar.value = remainingMs;
  cooldownBar.max = COOLDOWN_MS;
  cooldownText.textContent = remainingMs > 0
    ? `${(remainingMs / 1000).toFixed(1)}s`
    : "ready";
  const inCooldown = remainingMs > 0;
  btnStraight.disabled = inCooldown;
  btnCurve.disabled = inCooldown;
}, 100);

async function throwSwitch(uiPosition) {
  const direction = uiPosition === "straight"
    ? UI_STRAIGHT_WIRE_DIRECTION
    : UI_CURVE_WIRE_DIRECTION;
  lastEvent.classList.remove("error");
  try {
    const resp = await fetch("/api/switch/throw", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ action: "throw", direction }),
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    lastEvent.textContent = `→ throw ${uiPosition} (${direction})`;
  } catch (e) {
    lastEvent.textContent = `throw failed: ${e.message}`;
    lastEvent.classList.add("error");
  }
}

btnStraight.addEventListener("click", () => throwSwitch("straight"));
btnCurve.addEventListener("click", () => throwSwitch("curve"));

function connect() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws/switch/state`);
  ws.onmessage = (e) => {
    try { renderState(JSON.parse(e.data)); }
    catch (err) { console.warn("bad switch state payload", err); }
  };
  ws.onclose = () => setTimeout(connect, 1500);
  ws.onerror = () => ws.close();
}
connect();

})();
