# modbus_writes.zeek — Log every Modbus write function code with full context.
#
# Produces modbus_writes.log: one row per write PDU regardless of whether
# modbus.log is enabled.  Write operations are rare in healthy OT environments;
# every row warrants review.
#
# Zero-config notices fired unconditionally (no allow-list required):
#   Modbus::FirmwareFunction   — FIRMWARE_REPLACEMENT, WRITE_FILE_RECORD, PROGRAM_* family
#   Modbus::BroadcastWrite     — unit ID = 0 (mass-control broadcast)
#   Modbus::MaskWriteRegister  — FC22, unless source is in mask_write_allowed
#   Modbus::DiagnosticFunctionCode — FC7/FC8/FC11/FC12/FC17
#
# Allow-list notice (requires authorized_masters to be populated):
#   Modbus::UnauthorizedWrite  — write from source not in authorized_masters

@load base/frameworks/notice
@load base/protocols/modbus
@load ./modbus_detect

module Modbus;

export {
	redef enum Log::ID += { LOG_WRITES };

	type WritesInfo: record {
		## Timestamp of the write request.
		ts: time &log;
		## Connection UID.
		uid: string &log;
		## Connection 4-tuple.
		id: conn_id &log;
		## Modbus unit ID (slave address); 0 = broadcast.
		unit: count &log;
		## Decoded function code string (e.g. WRITE_MULTIPLE_REGISTERS).
		func: string &log;
		## Starting register or coil address (0 if not applicable).
		register_start: count &log &optional;
		## Number of registers or coils targeted (0 if not applicable).
		register_count: count &log &optional;
		## Hex-encoded written values; first max_logged_values entries;
		## excess shown as "[+N more]".
		values: string &log &optional;
		## T if source IP is in authorized_masters (or set is empty); F otherwise.
		authorized: bool &log;
	};

	global log_modbus_writes: event(rec: WritesInfo);
}

# ---------------------------------------------------------------------------
# Log stream
# ---------------------------------------------------------------------------

event zeek_init() &priority=5
	{
	Log::create_stream(Modbus::LOG_WRITES, [$columns=WritesInfo,
	    $ev=log_modbus_writes, $path="modbus_writes", ]);
	}

# ---------------------------------------------------------------------------
# DET-002 UnexpectedUnitWrite — worker-local state
# Cluster limitation: _master_read_units is worker-local; connections are
# sticky to workers so read/write pairs on the same connection are correct,
# but a master that reads on one worker and writes on another may produce
# false positives.  Same pattern as func_codes_seen in modbus_summary.zeek.
# ---------------------------------------------------------------------------

# (master, unit) pairs observed in read traffic.
global _master_read_units: set[addr, count] &create_expire=7day;

# Set to T when a baseline file is loaded (Phase 4).
global _read_units_baseline_loaded: bool = F;

# Timestamp of first read observation; used for grace period.
global _det002_start_time: time = double_to_time(0.0);

function _det002_in_grace(): bool
	{
	if ( _read_units_baseline_loaded )
		return F;
	if ( modbus_detect::unexpected_unit_write_grace == 0sec )
		return F;
	if ( _det002_start_time == double_to_time(0.0) )
		return T;
	return network_time() - _det002_start_time <
	    modbus_detect::unexpected_unit_write_grace;
	}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function _format_registers(regs: ModbusRegisters): string
	{
	local vals: vector of string = vector();
	local max_n = modbus_detect::max_logged_values;
	local n = |regs|;
	local limit = n < max_n ? n : max_n;
	# Zeek vector iteration yields the index, not the value.
	for ( idx in regs )
		{
		if ( idx >= limit )
			break;
		vals += fmt("0x%04x", regs[idx]);
		}
	if ( n > max_n )
		vals += fmt("[+%d more]", n - max_n);
	local s = join_string_vec(vals, ",");
	return s;
	}

function _format_coils(coils: ModbusCoils): string
	{
	local vals: vector of string = vector();
	local max_n = modbus_detect::max_logged_values;
	local n = |coils|;
	local limit = n < max_n ? n : max_n;
	for ( idx in coils )
		{
		if ( idx >= limit )
			break;
		vals += coils[idx] ? "1" : "0";
		}
	local s = join_string_vec(vals, ",");
	if ( n > max_n )
		s += fmt("[+%d more]", n - max_n);
	return s;
	}

function _authorized(c: connection): bool
	{
	# is_authorized_master handles the empty-set case (returns T + warns once).
	return modbus_detect::is_authorized_master(c$id$orig_h);
	}

function _write_notices(c: connection, rec: WritesInfo)
	{
	# DET-001 UnauthorizedWrite — only when allow-list is configured
	if ( modbus_detect::masters_configured() && ! rec$authorized )
		{
		NOTICE([$note=Modbus::UnauthorizedWrite, $msg=fmt(
		    "%s issued %s to slave %s unit=%d (not in authorized_masters)",
		    c$id$orig_h, rec$func, c$id$resp_h, rec$unit), $conn=c,
		    $identifier=cat(c$id$orig_h, c$id$resp_h, rec$func),
		    $suppress_for=5min]);
		}

	# DET-003 FirmwareFunction — firmware/vendor write codes (highest severity;
	# subsumes BroadcastWrite and UnexpectedUnitWrite for the same PDU).
	if ( rec$func in modbus_detect::firmware_function_codes )
		{
		local bcast_note = rec$unit == 0 ? " to broadcast (unit=0)" : "";
		NOTICE([$note=Modbus::FirmwareFunction, $msg=fmt(
		    "%s sent %s%s to slave %s (critical — firmware/file write)",
		    c$id$orig_h, rec$func, bcast_note, c$id$resp_h), $conn=c,
		    $identifier=cat(c$id$orig_h, c$id$resp_h), $suppress_for=1hr]);
		return;
		}

	# DET-004 BroadcastWrite — unit 0 is protocol-defined broadcast.
	# Also subsumes UnexpectedUnitWrite: unit=0 is never in read traffic by
	# definition, so that notice would add no information.
	if ( rec$unit == 0 )
		{
		NOTICE([$note=Modbus::BroadcastWrite, $msg=fmt(
		    "%s sent %s to broadcast (unit=0) on slave %s", c$id$orig_h,
		    rec$func, c$id$resp_h), $conn=c, $identifier=cat(
		    c$id$orig_h, c$id$resp_h, rec$func), $suppress_for=5min]);
		return;
		}

	# DET-014 MaskWriteRegister — FC22 bit-level manipulation
	if ( rec$func == "MASK_WRITE_REGISTER"
	    && c$id$orig_h !in modbus_detect::mask_write_allowed )
		{
		NOTICE([$note=Modbus::MaskWriteRegister, $msg=fmt("%s sent MASK_WRITE_REGISTER to slave %s unit=%d register=%s (bit-level write)",
		    c$id$orig_h, c$id$resp_h, rec$unit, rec?$register_start ?
		    fmt("%d", rec$register_start) : "?"), $conn=c,
		    $identifier=cat(c$id$orig_h, c$id$resp_h), $suppress_for=5min]);
		}

	# DET-002 UnexpectedUnitWrite — write to a unit never seen in read traffic
	if ( ! _det002_in_grace() && [c$id$orig_h, rec$unit] !in _master_read_units )
		{
		NOTICE([$note=Modbus::UnexpectedUnitWrite, $msg=fmt("%s wrote to unit=%d on slave %s — unit never seen in read traffic from this master",
		    c$id$orig_h, rec$unit, c$id$resp_h), $conn=c,
		    $identifier=cat(c$id$orig_h, rec$unit), $suppress_for=5min]);
		}
	}

# ---------------------------------------------------------------------------
# Write event handlers
# ---------------------------------------------------------------------------

event modbus_write_single_coil_request(c: connection, headers: ModbusHeaders,
    address: count, value: bool)
	{
	local rec: WritesInfo = [$ts=network_time(), $uid=c$uid, $id=c$id,
	    $unit=headers$uid, $func="WRITE_SINGLE_COIL",
	    $register_start=address, $register_count=1,
	    $values=value ? "0xff00" : "0x0000", $authorized=_authorized(c), ];
	_write_notices(c, rec);
	Log::write(LOG_WRITES, rec);
	}

event modbus_write_single_register_request(c: connection,
    headers: ModbusHeaders, address: count, value: count)
	{
	local rec: WritesInfo = [$ts=network_time(), $uid=c$uid, $id=c$id,
	    $unit=headers$uid, $func="WRITE_SINGLE_REGISTER",
	    $register_start=address, $register_count=1, $values=fmt("0x%04x",
	    value), $authorized=_authorized(c), ];
	_write_notices(c, rec);
	Log::write(LOG_WRITES, rec);
	}

event modbus_write_multiple_coils_request(c: connection, headers: ModbusHeaders,
    start_address: count, coils: ModbusCoils)
	{
	local rec: WritesInfo = [$ts=network_time(), $uid=c$uid, $id=c$id,
	    $unit=headers$uid, $func="WRITE_MULTIPLE_COILS",
	    $register_start=start_address, $register_count=|coils|,
	    $values=_format_coils(coils), $authorized=_authorized(c), ];
	_write_notices(c, rec);
	Log::write(LOG_WRITES, rec);
	}

event modbus_write_multiple_registers_request(c: connection,
    headers: ModbusHeaders, start_address: count, registers: ModbusRegisters)
	{
	local rec: WritesInfo = [$ts=network_time(), $uid=c$uid, $id=c$id,
	    $unit=headers$uid, $func="WRITE_MULTIPLE_REGISTERS",
	    $register_start=start_address, $register_count=|registers|,
	    $values=_format_registers(registers), $authorized=_authorized(c), ];
	_write_notices(c, rec);
	Log::write(LOG_WRITES, rec);
	}

event modbus_mask_write_register_request(c: connection, headers: ModbusHeaders,
    address: count, and_mask: count, or_mask: count)
	{
	local rec: WritesInfo = [$ts=network_time(), $uid=c$uid, $id=c$id,
	    $unit=headers$uid, $func="MASK_WRITE_REGISTER",
	    $register_start=address, $register_count=1, $values=fmt(
	    "and=0x%04x,or=0x%04x", and_mask, or_mask), $authorized=_authorized(c), ];
	_write_notices(c, rec);
	Log::write(LOG_WRITES, rec);
	}

event modbus_read_write_multiple_registers_request(c: connection,
    headers: ModbusHeaders, read_start_address: count, read_quantity: count,
    write_start_address: count, write_registers: ModbusRegisters)
	{
	local rec: WritesInfo = [$ts=network_time(), $uid=c$uid, $id=c$id,
	    $unit=headers$uid, $func="READ_WRITE_MULTIPLE_REGISTERS",
	    $register_start=write_start_address,
	    $register_count=|write_registers|, $values=_format_registers(
	    write_registers), $authorized=_authorized(c), ];
	_write_notices(c, rec);
	Log::write(LOG_WRITES, rec);
	}

event modbus_write_file_record_request(c: connection, headers: ModbusHeaders,
    byte_count: count, refs: ModbusFileReferences)
	{
	local rec: WritesInfo = [$ts=network_time(), $uid=c$uid, $id=c$id,
	    $unit=headers$uid, $func="WRITE_FILE_RECORD",
	    $register_count=byte_count, $authorized=_authorized(c), ];
	_write_notices(c, rec);
	Log::write(LOG_WRITES, rec);
	}

# ---------------------------------------------------------------------------
# modbus_message: firmware/vendor codes (no dedicated write event in Zeek)
# and diagnostic function codes.
# Runs at priority 3 — after main.zeek priority-5 sets c$modbus$func.
# ---------------------------------------------------------------------------

event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool)
    &priority=3
	{
	if ( ! is_orig )
		return;
	if ( ! c?$modbus || ! c$modbus?$func )
		return;

	local func = c$modbus$func;

	# Firmware/vendor write codes without a dedicated Zeek event.
	# WRITE_FILE_RECORD has its own event above; skip it here.
	if ( func in modbus_detect::firmware_function_codes
	    && func != "WRITE_FILE_RECORD" )
		{
		local wrec: WritesInfo = [$ts=network_time(), $uid=c$uid, $id=c$id,
		    $unit=headers$uid, $func=func, $authorized=_authorized(c), ];
		_write_notices(c, wrec);
		Log::write(LOG_WRITES, wrec);
		}

	# DET-015 DiagnosticFunctionCode — no log entry (not a write), notice only.
	if ( func in modbus_detect::diagnostic_function_codes )
		{
		NOTICE([$note=Modbus::DiagnosticFunctionCode, $msg=fmt(
		    "%s sent %s to slave %s unit=%d — diagnostic function code",
		    c$id$orig_h, func, c$id$resp_h, headers$uid), $conn=c,
		    $identifier=cat(c$id$orig_h, c$id$resp_h, func),
		    $suppress_for=1hr]);
		}

	# DET-003 extension: READ_FILE_RECORD — firmware/ladder logic exfiltration.
	# Notice only; not logged to modbus_writes.log (it's a read operation).
	if ( func == "READ_FILE_RECORD" )
		{
		NOTICE([$note=Modbus::FirmwareFunction, $msg=fmt(
		    "%s sent READ_FILE_RECORD to slave %s unit=%d (critical — firmware/file read exfiltration)",
		    c$id$orig_h, c$id$resp_h, headers$uid), $conn=c,
		    $identifier=cat(c$id$orig_h, c$id$resp_h, func),
		    $suppress_for=1hr]);
		}

	# DET-011 UnknownFunctionCode — Zeek labels unrecognized FCs as "unknown-NNN".
	if ( "unknown" in func && func !in modbus_detect::unknown_func_allowed )
		{
		NOTICE([$note=Modbus::UnknownFunctionCode, $msg=fmt(
		    "%s sent unknown function code %s to slave %s unit=%d",
		    c$id$orig_h, func, c$id$resp_h, headers$uid), $conn=c,
		    $identifier=cat(c$id$orig_h, c$id$resp_h, func),
		    $suppress_for=5min]);
		}
	}

# ---------------------------------------------------------------------------
# DET-002: Track (master, unit) pairs seen in read traffic.
# Runs at priority -1 so c$modbus$func is available.
# ---------------------------------------------------------------------------

event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool)
    &priority=-1
	{
	if ( ! is_orig )
		return;
	if ( ! c?$modbus || ! c$modbus?$func )
		return;

	local func = c$modbus$func;
	if ( func in modbus_detect::write_function_codes )
		return;

	# Track the first read observation for grace period calculation.
	if ( _det002_start_time == double_to_time(0.0) )
		_det002_start_time = network_time();

	add _master_read_units[c$id$orig_h, headers$uid];
	}
