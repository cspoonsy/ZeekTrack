##! ChooChoo Zeek site policy.
##!
##! Minimal on purpose — we load the two analyzers the exercise cares about
##! (MQTT for IoT mode, Modbus for enterprise mode) and enable JSON output
##! so the Vector sidecar can ship each line to Gravwell verbatim. Base
##! analyzers (conn / dns / http / ssl / ssh / files) are auto-loaded by
##! `zeek -i ... local` via the default script bundle.

@load base/protocols/mqtt
@load base/protocols/modbus

# The ChooChoo Modbus controller listens on 5020 (non-standard to avoid conflicts
# in the lab). Tell Zeek's DPD to parse this port as Modbus TCP.
redef Modbus::ports += { 5020/tcp };

# Emit JSON instead of TSV — one JSON document per line per log stream,
# which is exactly the format Gravwell's simple_relay `line` reader wants.
redef LogAscii::use_json = T;

# Add a `_path` field to every JSON record so downstream (Gravwell, Splunk,
# Elastic) can tell `conn.log` events from `mqtt.log` events without
# needing to know which file they came from. `_write_ts` is the wall-clock
# time Zeek serialized the record — handy when filtering by receipt time
# vs. Zeek's own event timestamps.
#
# Log::default_ext_func's return-record fields get prefixed with `_`
# (Log::default_ext_prefix), so returning {path=..., write_ts=...}
# yields `_path` and `_write_ts` in each JSON document.
type ChooChooLogExt: record {
    path: string &log;
    write_ts: time &log;
};

function log_ext_choochoo(path: string): ChooChooLogExt
{
    return ChooChooLogExt($path=path, $write_ts=current_time());
}

redef Log::default_ext_func = log_ext_choochoo;

# OT security detections.
@load ./mqtt-detections
@load ./modbus-detections

# Modbus authorized masters — web-modbus container (172.19.0.4) is the only
# legitimate source of Modbus writes. Anything else gets authorized=F in
# modbus_writes.log, which fires the UnauthorizedWrite notice.
redef modbus_detect::authorized_masters += { 172.19.0.4 };

# Demo-tuned thresholds — make detections fire in a live lab session.
redef modbus_detect::unexpected_unit_write_grace = 0sec;
redef modbus_detect::read_sweep_threshold = 20;
redef modbus_detect::write_escalation_grace = 5min;
redef modbus_detect::request_flood_threshold = 50;

##! DET-010 (MultiSlaveSweep) is intentionally NOT redef'd here.
##! The lab uses a single-controller topology: one Modbus master (web-modbus,
##! 172.19.0.4) talking to exactly one slave (controller-modbus, 172.19.0.3).
##! MultiSlaveSweep fires when a single master fans out to multiple slave unit
##! IDs in a short window — that pattern never occurs in this topology, so the
##! detection will not fire during normal lab operation and there is nothing to
##! tune. If a future exercise adds a second outstation, revisit this comment.

# MQTT: only web-mqtt (172.19.0.5) is an authorized publisher to train cmd topics.
redef mqtt_detect::authorized_publishers += { [172.19.0.5] = /choochoo\/train\/.*/ };

# Local nets — anything outside these ranges is treated as external.
# Covers the Docker bridge default (172.16/12) plus common LAN ranges so
# real-hardware sessions work out of the box.
redef Site::local_nets += { 172.16.0.0/12, 10.0.0.0/8, 192.168.0.0/16 };
