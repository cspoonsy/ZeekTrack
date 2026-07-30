# modbus_protocol_violations.zeek — Detect protocol-level anomalies on Modbus
# connections by observing Zeek's conn_weird stream.
#
# Covers two attack classes visible in the CIC Modbus Dataset 2023:
#
#   Frame Stacking  — attacker injects extra PDUs into an existing TCP stream
#                     so the responder processes them as if they were from the
#                     legitimate master.  Zeek reports each surplus PDU as
#                     active_connection_reuse on the Modbus connection.
#
#   Premature Reuse — TCP session torn down mid-flight; subsequent data reuses
#                     the 4-tuple before the connection is fully closed.
#                     Zeek reports these as premature_connection_reuse.
#
# Both weird names are absent from benign Modbus traffic (0 occurrences across
# 62 benign pcaps in the CIC dataset) but appear in high volume during attacks
# (44K active_connection_reuse, 1.7K premature_connection_reuse).
#
# Notice fired:
#   Modbus::ProtocolViolation — >protocol_violation_threshold of the above
#                                weirds per connection.

@load base/frameworks/notice
@load base/protocols/modbus
@load ./modbus_detect

module Modbus;

# Per-connection counter — accumulated between conn_weird callbacks.
redef record connection += {
	modbus_violation_count: count &default=0;
};

# Set of conn_weird names that indicate Modbus frame-level abuse.
# &redef so operators can extend for vendor-specific weirdness.
const _modbus_violation_weirds: set[string] = {
	"active_connection_reuse",
	"premature_connection_reuse",
} &redef;

event conn_weird(name: string, c: connection, addl: string, source: string)
	{
	# Only care about Modbus connections and relevant weird names.
	if ( c$id$resp_p !in Modbus::ports && c$id$orig_p !in Modbus::ports )
		return;
	if ( name !in _modbus_violation_weirds )
		return;

	++c$modbus_violation_count;

	if ( c$modbus_violation_count == modbus_detect::protocol_violation_threshold )
		{
		NOTICE([$note=Modbus::ProtocolViolation, $msg=fmt("%s → %s: %d frame-level protocol violations (weird: %s) — possible frame stacking attack",
		    c$id$orig_h, c$id$resp_h, c$modbus_violation_count, name),
		    $conn=c, $identifier=cat(c$id$orig_h, c$id$resp_h),
		    $suppress_for=5min]);
		}
	}
