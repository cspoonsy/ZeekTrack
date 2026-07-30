# scripts/mqtt_protocol_violations.zeek — Detect protocol-level anomalies on
# MQTT connections by observing Zeek's conn_weird stream.
#
# Frame stacking — attacker injects extra SYNs into an established MQTT session.
# Zeek reports each as active_connection_reuse on port-1883 connections.
# Premature reuse — TCP session torn down mid-flight (premature_connection_reuse).
#
# Both weird names are absent from benign MQTT traffic.
# Identical pattern to modbus_protocol_violations.zeek; only the port differs.
#
# Notice: MQTT::ProtocolViolation — >protocol_violation_threshold of the above weirds.

@load base/frameworks/notice
@load base/protocols/mqtt
@load ./mqtt_detect

module MQTT;

redef record connection += {
	mqtt_violation_count: count &default=0;
};

const _mqtt_violation_weirds: set[string] = {
	"active_connection_reuse",
	"premature_connection_reuse",
} &redef;

event conn_weird(name: string, c: connection, addl: string, source: string)
	{
	if ( c$id$resp_p != 1883/tcp && c$id$orig_p != 1883/tcp )
		return;
	if ( name !in _mqtt_violation_weirds )
		return;

	++c$mqtt_violation_count;

	if ( c$mqtt_violation_count == mqtt_detect::protocol_violation_threshold )
		{
		NOTICE([$note=MQTT::ProtocolViolation, $msg=fmt("%s → %s: %d frame-level protocol violations (weird: %s) — possible frame stacking attack",
		    c$id$orig_h, c$id$resp_h, c$mqtt_violation_count, name),
		    $conn=c, $identifier=cat(c$id$orig_h, c$id$resp_h),
		    $suppress_for=5min]);
		}
	}
