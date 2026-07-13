##! ChooChoo Zeek site policy.
##!
##! Minimal on purpose — we load the two analyzers the exercise cares about
##! (MQTT for IoT mode, Modbus for enterprise mode) and enable JSON output
##! so the Vector sidecar can ship each line to Gravwell verbatim. Base
##! analyzers (conn / dns / http / ssl / ssh / files) are auto-loaded by
##! `zeek -i ... local` via the default script bundle.

@load base/protocols/mqtt
@load base/protocols/modbus

# ChooChoo runs Modbus on 5020 (non-standard to avoid port conflicts).
# Tell Zeek's Modbus analyzer to also watch 5020/tcp.
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

# Local nets — anything outside these ranges is treated as external.
# Covers the Docker bridge default (172.16/12) plus common LAN ranges so
# real-hardware sessions work out of the box.
redef Site::local_nets += { 172.16.0.0/12, 10.0.0.0/8, 192.168.0.0/16 };
