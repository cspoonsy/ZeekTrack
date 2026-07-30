# modbus_detect/__load__.zeek — Shared option constants and notice types for the
# Modbus security detection suite.
#
# All tunable thresholds are declared here as `option` constants so operators
# have one place to redef without editing individual detection scripts:
#
#   redef modbus_detect::authorized_masters += { 192.168.10.10 };
#   redef modbus_detect::exception_flood_threshold = 30;
#
# If authorized_masters is empty (default), all writes are logged with
# authorized=T and a one-time Reporter::warning is emitted.  Populate the
# set from at least one week of modbus_masters.log baseline data before
# expecting UnauthorizedWrite notices.

module modbus_detect;

@load base/frameworks/input

export {
	# -------------------------------------------------------------------------
	# Notice types
	# -------------------------------------------------------------------------

	redef enum Notice::Type += {
		## DET-001: Write from a source IP not in authorized_masters.
		Modbus::UnauthorizedWrite,
		## DET-004: Write to unit ID 0 (Modbus broadcast address).
		Modbus::BroadcastWrite,
		## DET-009: First-ever Modbus PDU from a source not in authorized_masters
		## or known_modbus.log.
		Modbus::RogueMaster,
		## DET-005: More than exception_flood_threshold exceptions in
		## exception_flood_interval from the same master/slave pair.
		Modbus::ExceptionFlood,
		## DET-007: Any SLAVE_DEVICE_FAILURE exception response.
		Modbus::SlaveDeviceFailure,
		## DET-006: More than illegal_function_scan_threshold ILLEGAL_FUNCTION
		## exceptions in one TCP connection (function code enumeration).
		Modbus::IllegalFunctionScan,
		## DET-008: More than unit_scan_threshold distinct unit IDs in one TCP
		## connection (unit ID scan).
		Modbus::UnitScan,
		## DET-003: Firmware or vendor write function code used (FIRMWARE_REPLACEMENT,
		## WRITE_FILE_RECORD, PROGRAM_* family).
		Modbus::FirmwareFunction,
		## DET-013: More than request_flood_threshold requests in
		## request_flood_interval from the same master to the same slave.
		Modbus::RequestFlood,
		## DET-014: MASK_WRITE_REGISTER (FC22) used from a source not in
		## mask_write_allowed.
		Modbus::MaskWriteRegister,
		## DET-015: Diagnostic function code used (FC7, FC8, FC11, FC12, FC17).
		Modbus::DiagnosticFunctionCode,
		## DET-016: More than register_scan_threshold ILLEGAL_DATA_ADDRESS
		## exceptions in register_scan_interval from the same master/slave/unit.
		Modbus::RegisterAddressScan,
		## DET-017: Authorized master that has a read-only history begins writing.
		Modbus::AuthorizedMasterWriteEscalation,
		## DET-010: Master contacts >multi_slave_sweep_threshold distinct slave IPs
		## in multi_slave_sweep_interval.
		Modbus::MultiSlaveSweep,
		## DET-002: Write to a unit ID never seen in read traffic from this master.
		Modbus::UnexpectedUnitWrite,
		## DET-011: Request with a function code Zeek does not recognize.
		Modbus::UnknownFunctionCode,
		## DET-012: Exception response whose TID does not match any pending request.
		Modbus::MalformedPDU,
		## DET-018: More than protocol_violation_threshold conn_weird events of
		## frame-stacking or premature-reuse type on a Modbus connection.
		Modbus::ProtocolViolation,
		## DET-019: Unauthorized source issues reads across >read_sweep_threshold
		## distinct (function_code, start_address) combinations in
		## read_sweep_interval (successful register enumeration without exceptions).
		Modbus::ReadSweep,
		## DET-020: A write to a holding register falls outside the min/max range
		## observed in prior read traffic by more than register_value_alert_pct.
		## Only fires when register_value_alert_enabled = T.
		Modbus::RegisterValueAnomaly,
		## DET-021: A master reads a holding or input register and then writes a
		## different value to the same register on the same connection.
		Modbus::ReadModifyWrite,
	};

	# -------------------------------------------------------------------------
	# Allow-lists
	# -------------------------------------------------------------------------

	## IPs permitted to issue write commands.  Empty by default — UnauthorizedWrite
	## notices are suppressed until this set is populated.  Populate from at least
	## one week of modbus_masters.log:
	##   zeek-cut master < modbus_masters.log | sort -u > authorized_masters.tsv
	option authorized_masters: set[addr] = {};

	## TSV file (columns: ip  description) loaded into authorized_masters at
	## startup.  Reload without restart by sending Zeek SIGHUP.
	## Reporter::warning written to reporter.log if the file is absent.
	option authorized_masters_file: string = "";

	## IPs permitted to use MASK_WRITE_REGISTER (FC22).  Any source not in this
	## set fires Modbus::MaskWriteRegister.  Empty = every FC22 fires the notice.
	option mask_write_allowed: set[addr] = {};

	# -------------------------------------------------------------------------
	# DET-005 ExceptionFlood
	# -------------------------------------------------------------------------

	## Exceptions per epoch from the same master/slave pair that triggers
	## Modbus::ExceptionFlood.
	option exception_flood_threshold: count = 20;

	## Counting window for ExceptionFlood.
	option exception_flood_interval: interval = 60sec;

	# -------------------------------------------------------------------------
	# DET-006 IllegalFunctionScan
	# -------------------------------------------------------------------------

	## Distinct function codes receiving ILLEGAL_FUNCTION in one TCP connection
	## that triggers Modbus::IllegalFunctionScan.
	option illegal_function_scan_threshold: count = 3;

	# -------------------------------------------------------------------------
	# DET-008 UnitScan
	# -------------------------------------------------------------------------

	## Distinct unit IDs in one TCP connection that triggers Modbus::UnitScan.
	option unit_scan_threshold: count = 5;

	# -------------------------------------------------------------------------
	# DET-010 MultiSlaveSweep (defined in modbus_masters.zeek, Phase 2)
	# -------------------------------------------------------------------------

	## Distinct slave IPs per master in multi_slave_sweep_interval that triggers
	## Modbus::MultiSlaveSweep.
	option multi_slave_sweep_threshold: count = 8;

	## Counting window for MultiSlaveSweep.
	option multi_slave_sweep_interval: interval = 60sec;

	# -------------------------------------------------------------------------
	# DET-013 RequestFlood
	# -------------------------------------------------------------------------

	## Requests per epoch from the same master/slave pair that triggers
	## Modbus::RequestFlood.  Separate 5-second SumStats epoch.
	##
	## NOTE: This threshold is environment-specific and should be tuned to
	## your deployment's polling rate.  Legitimate SCADA HMIs may burst
	## hundreds of READ requests during periodic full-register-read cycles.
	## Test against benign baseline traffic before lowering this value.
	option request_flood_threshold: count = 500;

	## Counting window for RequestFlood.  Must be kept short (5 sec) to detect
	## bursts that would overwhelm a PLC TCP stack.
	option request_flood_interval: interval = 5sec;

	# -------------------------------------------------------------------------
	# DET-015 DiagnosticFunctionCode
	# -------------------------------------------------------------------------

	## Function code strings whose use triggers Modbus::DiagnosticFunctionCode.
	## FC7/FC8/FC11/FC12/FC17 — none have a role in production SCADA polling.
	## Remove REPORT_SLAVE_ID if the environment uses it for device inventory.
	option diagnostic_function_codes: set[string] = {
		"READ_EXCEPTION_STATUS", # FC7
		"DIAGNOSTICS", # FC8
		"GET_COMM_EVENT_COUNTER", # FC11
		"GET_COMM_EVENT_LOG", # FC12
		"REPORT_SLAVE_ID", # FC17
	};

	# -------------------------------------------------------------------------
	# DET-018 ProtocolViolation
	# -------------------------------------------------------------------------

	## Number of frame-stacking / premature-reuse conn_weird events on a single
	## Modbus TCP connection that triggers Modbus::ProtocolViolation.
	## A legitimate Modbus session should never produce these.
	option protocol_violation_threshold: count = 5;

	# -------------------------------------------------------------------------
	# DET-019 ReadSweep
	# -------------------------------------------------------------------------

	## Distinct (function_code, start_address) pairs from an unauthorized source
	## in read_sweep_interval that triggers Modbus::ReadSweep.
	## Requires authorized_masters to be configured; suppressed otherwise.
	option read_sweep_threshold: count = 100;

	## Counting window for ReadSweep.
	option read_sweep_interval: interval = 60sec;

	# -------------------------------------------------------------------------
	# DET-016 RegisterAddressScan
	# -------------------------------------------------------------------------

	## ILLEGAL_DATA_ADDRESS exceptions per epoch from the same master/slave/unit
	## that triggers Modbus::RegisterAddressScan.
	option register_scan_threshold: count = 10;

	## Counting window for RegisterAddressScan.
	option register_scan_interval: interval = 60sec;

	# -------------------------------------------------------------------------
	# Writes log
	# -------------------------------------------------------------------------

	## Maximum number of register or coil values hex-logged per write row in
	## modbus_writes.log.  Values beyond this cap are summarised as "[+N more]".
	option max_logged_values: count = 16;

	## SumStats epoch for modbus_summary.log.  Default 1 hour; reduce for
	## testing (e.g. redef modbus_detect::summary_epoch = 10sec in a btest).
	option summary_epoch: interval = 1hr;

	## How often workers flush accumulated master state and func-code observations
	## to the manager in cluster mode.  Lower values reduce detection latency;
	## higher values reduce Broker message volume.  5 seconds is appropriate for
	## almost all ICS deployments — Modbus polling cycles are 100ms–2s.
	option master_state_flush_interval: interval = 5sec;

	# -------------------------------------------------------------------------
	# DET-002 UnexpectedUnitWrite (Phase 3 implementation)
	# -------------------------------------------------------------------------

	## Grace period on fresh deployment (no baseline file present) before the
	## UnexpectedUnitWrite notice can fire.
	option unexpected_unit_write_grace: interval = 24hr;

	# -------------------------------------------------------------------------
	# DET-017 AuthorizedMasterWriteEscalation
	# -------------------------------------------------------------------------

	## Minimum observation period before a master's write history is considered
	## a confirmed read-only baseline.  Masters seen for less than this interval
	## do not trigger AuthorizedMasterWriteEscalation on their first write.
	option write_escalation_grace: interval = 168hr; # one week

	# -------------------------------------------------------------------------
	# DET-011 UnknownFunctionCode
	# -------------------------------------------------------------------------

	## Function code strings to ignore for UnknownFunctionCode detection.
	## Add known vendor-specific codes here to suppress false positives.
	option unknown_func_allowed: set[string] = {};

	# -------------------------------------------------------------------------
	# DET-020 RegisterValueAnomaly
	# -------------------------------------------------------------------------

	## Enable RegisterValueAnomaly notices.  Off by default — requires a
	## register value baseline to be established before enabling to avoid
	## false positives on deployment.
	option register_value_alert_enabled: bool = F;

	## Margin as a percentage of the observed min/max range.  Default 50 means
	## a value more than 50% of (max - min) beyond the observed range fires
	## the notice.  When min == max, the margin is computed as pct of max.
	option register_value_alert_pct: double = 50.0;

	## Minimum observed max_value a register must have before the anomaly
	## check applies.  Prevents noise from boolean-like registers (0/1).
	option register_value_alert_min: count = 4;

	# -------------------------------------------------------------------------
	# DET-021 ReadModifyWrite
	# -------------------------------------------------------------------------

	## Source IPs permitted to perform read-modify-write sequences.
	## Deliberately separate from authorized_masters — an authorized master
	## that reads and then writes different values is still worth logging.
	## Populate this set only for masters whose control logic is confirmed
	## to perform legitimate read-modify-write sequences.
	option read_modify_write_allowed: set[addr] = {};

	# -------------------------------------------------------------------------
	# Baseline file paths (loading deferred to Phase 4)
	# -------------------------------------------------------------------------

	## TSV file of known (master, unit) pairs for UnexpectedUnitWrite baseline.
	option unexpected_unit_write_baseline_file: string = "";

	## TSV file of known write-capable masters for WriteEscalation baseline.
	option write_escalation_baseline_file: string = "";

	# -------------------------------------------------------------------------
	# Internal helpers
	# -------------------------------------------------------------------------

	## Set of function code strings that constitute write operations.  Used by
	## modbus_summary.zeek to classify PDUs into read_count vs write_count.
	## Not an option — modifying this would produce misleading summary data.
	const write_function_codes: set[string] = {
		"WRITE_SINGLE_COIL",
		"WRITE_SINGLE_REGISTER",
		"WRITE_MULTIPLE_COILS",
		"WRITE_MULTIPLE_REGISTERS",
		"WRITE_FILE_RECORD",
		"MASK_WRITE_REGISTER",
		"READ_WRITE_MULTIPLE_REGISTERS",
		"FIRMWARE_REPLACEMENT",
		"PROGRAM_484",
		"PROGRAM_584_984",
		"PROGRAM_584_984_2",
		"PROGRAM_884_U84",
		"PROGRAM_CONCEPT",
		"PROGRAM_UNITY",
		"PROGRAM_2000",
	} &redef;

	## Set of function code strings whose use should log to modbus_writes.log.
	## Includes all write_function_codes plus firmware/vendor codes that modify
	## device state but may not have a dedicated Zeek write event.
	const firmware_function_codes: set[string] = {
		"FIRMWARE_REPLACEMENT",
		"WRITE_FILE_RECORD",
		"PROGRAM_484",
		"PROGRAM_584_984",
		"PROGRAM_584_984_2",
		"PROGRAM_2000",
		"PROGRAM_884_U84",
		"PROGRAM_CONCEPT",
		"PROGRAM_UNITY",
	} &redef;

	## Returns T if the authorized_masters set (or file-loaded table) is
	## populated.  When F, authorized writes are not enforced and all writes
	## receive authorized=T.
	global masters_configured: function(): bool;

	## Returns T if ip is in the authorized_masters set or the file-loaded
	## table.  Always returns T when masters are not configured.
	global is_authorized_master: function(ip: addr): bool;

	## File-loaded allow-list table (addr → description string).
	## Populated from authorized_masters_file via Input framework.
	## Read-only for callers outside this module; use is_authorized_master()
	## for enforcement logic.  Exposed for RogueMaster logic in
	## modbus_masters.zeek which needs direct set membership without the
	## "return T when empty" semantics of is_authorized_master().
	global _authorized_masters_tbl: table[addr] of string = {};
}

# Emit the "empty allow-list" warning at most once per Zeek session.
global _masters_warned: bool = F;

# Input framework record type — TSV columns: ip  description
type _AuthMasterRec: record {
	ip: addr;
	description: string &optional;
};

# Input framework destination table (addr → description); synced from TSV file.
global _auth_masters_input_tbl: table[addr] of string = {} &redef;

# -------------------------------------------------------------------------
# Function implementations
# -------------------------------------------------------------------------

function masters_configured(): bool
	{
	return |authorized_masters| > 0 || |_authorized_masters_tbl| > 0;
	}

function is_authorized_master(ip: addr): bool
	{
	if ( ! masters_configured() )
		{
		if ( ! _masters_warned )
			{
			Reporter::warning("modbus_detect: authorized_masters is empty; all writes logged with authorized=T; populate authorized_masters to enable UnauthorizedWrite detection");
			_masters_warned = T;
			}
		return T;
		}
	return ip in authorized_masters || ip in _authorized_masters_tbl;
	}

# -------------------------------------------------------------------------
# zeek_init: load allow-list file if configured
# -------------------------------------------------------------------------

event zeek_init() &priority=3
	{
	if ( authorized_masters_file == "" )
		return;

	Input::add_table([$source=authorized_masters_file,
	    $name="modbus_authorized_masters", $idx=_AuthMasterRec,
	    $destination=_auth_masters_input_tbl, $mode=Input::REREAD, ]);
	}

# Sync Input table → internal lookup table on each reload.
event Input::end_of_data(name: string, source: string)
	{
	if ( name != "modbus_authorized_masters" )
		return;
	clear_table(_authorized_masters_tbl);
	for ( ip in _auth_masters_input_tbl )
		_authorized_masters_tbl[ip] = _auth_masters_input_tbl[ip];
	}

# Extend Zeek's built-in function_codes table with PROGRAM_2000 (Modicon 0x41).
redef Modbus::function_codes += {[0x41] = "PROGRAM_2000"};
