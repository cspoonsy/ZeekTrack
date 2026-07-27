# modbus_exceptions.zeek — Log every Modbus exception response with full context.
#
# Produces modbus_exceptions.log: one row per exception PDU.
# In healthy OT environments exceptions are rare; any sustained rate indicates
# scanning, misconfiguration, or deliberate fault injection.
#
# Zero-config notices:
#   Modbus::ExceptionFlood     — >exception_flood_threshold exceptions / interval
#                                 per master/slave pair (SumStats)
#   Modbus::SlaveDeviceFailure — any SLAVE_DEVICE_FAILURE exception (per-PDU)
#   Modbus::RegisterAddressScan — >register_scan_threshold ILLEGAL_DATA_ADDRESS
#                                  exceptions / interval per master/slave/unit (SumStats)

@load base/frameworks/notice
@load base/frameworks/sumstats
@load base/protocols/modbus
@load ./modbus_detect

# DET-012 MalformedPDU: per-connection pending TID set for request/response matching.
redef record connection += {
	modbus_pending_tids: set[count] &optional;
};

module Modbus;

export {
	redef enum Log::ID += { LOG_EXCEPTIONS };

	type ExceptionsInfo: record {
		## Timestamp of the exception response.
		ts: time &log;
		## Connection UID.
		uid: string &log;
		## Connection 4-tuple.
		id: conn_id &log;
		## Unit ID that returned the exception.
		unit: count &log;
		## Base function code that triggered the exception (high bit stripped).
		func: string &log;
		## Exception code string (e.g. ILLEGAL_FUNCTION, SLAVE_DEVICE_FAILURE).
		exception: string &log;
	};

	global log_modbus_exceptions: event(rec: ExceptionsInfo);
}

# ---------------------------------------------------------------------------
# Log stream
# ---------------------------------------------------------------------------

event zeek_init() &priority=5
	{
	Log::create_stream(Modbus::LOG_EXCEPTIONS, [$columns=ExceptionsInfo,
	    $ev=log_modbus_exceptions, $path="modbus_exceptions", ]);
	}

# ---------------------------------------------------------------------------
# SumStats for ExceptionFlood
# ---------------------------------------------------------------------------

global _exception_flood_threshold_val: function(key: SumStats::Key,
    result: SumStats::Result): double;
global _exception_flood_threshold_crossed: function(key: SumStats::Key,
    result: SumStats::Result);
global _register_scan_threshold_val: function(key: SumStats::Key,
    result: SumStats::Result): double;
global _register_scan_threshold_crossed: function(key: SumStats::Key,
    result: SumStats::Result);

event zeek_init() &priority=4
	{
	_exception_flood_threshold_val = function(key: SumStats::Key,
	    result: SumStats::Result): double
		{
		if ( "modbus.exceptions.flood" !in result )
			return 0.0;
		return result["modbus.exceptions.flood"]$sum;
		};

	_exception_flood_threshold_crossed = function(key: SumStats::Key,
	    result: SumStats::Result)
		{
		if ( "modbus.exceptions.flood" !in result )
			return;
		local parts = split_string(key$str, /\//);
		if ( |parts| < 2 )
			return;
		local master = to_addr(parts[0]);
		local slave = to_addr(parts[1]);
		local cnt = double_to_count(result["modbus.exceptions.flood"]$sum);
		NOTICE([$note=Modbus::ExceptionFlood, $msg=fmt("%s received %d exceptions from slave %s in %s (threshold: %d)",
		    master, cnt, slave, modbus_detect::exception_flood_interval,
		    modbus_detect::exception_flood_threshold), $src=master,
		    $dst=slave, $identifier=cat(master, slave), $suppress_for=5min]);
		};

	_register_scan_threshold_val = function(key: SumStats::Key,
	    result: SumStats::Result): double
		{
		if ( "modbus.exceptions.scan" !in result )
			return 0.0;
		return result["modbus.exceptions.scan"]$sum;
		};

	_register_scan_threshold_crossed = function(key: SumStats::Key,
	    result: SumStats::Result)
		{
		if ( "modbus.exceptions.scan" !in result )
			return;
		local parts = split_string(key$str, /\//);
		if ( |parts| < 3 )
			return;
		local master = to_addr(parts[0]);
		local slave = to_addr(parts[1]);
		local unit = to_count(parts[2]);
		local cnt = double_to_count(result["modbus.exceptions.scan"]$sum);
		NOTICE([$note=Modbus::RegisterAddressScan, $msg=fmt("%s received %d ILLEGAL_DATA_ADDRESS exceptions from slave %s unit=%d in %s (register scan)",
		    master, cnt, slave, unit,
		    modbus_detect::register_scan_interval), $src=master,
		    $dst=slave, $identifier=cat(master, slave, unit),
		    $suppress_for=5min]);
		};
	}

event zeek_init() &priority=3
	{
	# --- DET-005 ExceptionFlood -------------------------------------------
	SumStats::create([$name="modbus.exceptions.flood",
	    $epoch=modbus_detect::exception_flood_interval, $reducers=set(
	    SumStats::Reducer($stream="modbus.exceptions.flood", $apply=set(
	    SumStats::SUM), )), $threshold_val=_exception_flood_threshold_val,
	    $threshold=modbus_detect::exception_flood_threshold + 0.0,
	    $threshold_crossed=_exception_flood_threshold_crossed, ]);

	# --- DET-016 RegisterAddressScan ---------------------------------------
	SumStats::create([$name="modbus.exceptions.scan",
	    $epoch=modbus_detect::register_scan_interval, $reducers=set(
	    SumStats::Reducer($stream="modbus.exceptions.scan", $apply=set(
	    SumStats::SUM), )), $threshold_val=_register_scan_threshold_val,
	    $threshold=modbus_detect::register_scan_threshold + 0.0,
	    $threshold_crossed=_register_scan_threshold_crossed, ]);
	}

# ---------------------------------------------------------------------------
# Exception event handler
# ---------------------------------------------------------------------------

event modbus_exception(c: connection, headers: ModbusHeaders, code: count)
	{
	# DET-012 MalformedPDU — exception TID does not match any pending request TID.
	if ( c?$modbus_pending_tids && headers$tid !in c$modbus_pending_tids )
		{
		NOTICE([$note=Modbus::MalformedPDU, $msg=fmt("slave %s returned exception with TID=%d not matching any pending request from %s (malformed PDU)",
		    c$id$resp_h, headers$tid, c$id$orig_h), $conn=c,
		    $identifier=cat(c$id$orig_h, c$id$resp_h, headers$tid),
		    $suppress_for=5min]);
		}

	local exception_str = Modbus::exception_codes[code];
	# Strip the exception high bit to get the base function code.
	local base_fc = headers$function_code & ~0x80;
	local func_str = Modbus::function_codes[base_fc];

	local rec: ExceptionsInfo = [$ts=network_time(), $uid=c$uid, $id=c$id,
	    $unit=headers$uid, $func=func_str, $exception=exception_str, ];
	Log::write(LOG_EXCEPTIONS, rec);

	local master = c$id$orig_h;
	local slave = c$id$resp_h;
	local unit = headers$uid;

	# DET-005 ExceptionFlood — observe every exception
	SumStats::observe("modbus.exceptions.flood", SumStats::Key($str=cat(master,
	    "/", slave)), SumStats::Observation($num=1));

	# DET-007 SlaveDeviceFailure — per-PDU, no threshold
	if ( exception_str == "SLAVE_DEVICE_FAILURE" )
		{
		NOTICE([$note=Modbus::SlaveDeviceFailure, $msg=fmt("slave %s unit=%d returned SLAVE_DEVICE_FAILURE to %s (hardware fault or firmware stress)",
		    slave, unit, master), $conn=c, $identifier=cat(slave, unit),
		    $suppress_for=10min]);
		}

	# DET-016 RegisterAddressScan — count only ILLEGAL_DATA_ADDRESS
	if ( exception_str == "ILLEGAL_DATA_ADDRESS" )
		{
		SumStats::observe("modbus.exceptions.scan", SumStats::Key($str=cat(master,
		    "/", slave, "/", unit)), SumStats::Observation($num=1));
		}
	}

# ---------------------------------------------------------------------------
# DET-012: Track pending request TIDs per connection
# ---------------------------------------------------------------------------

# Record request TIDs for matching against exception responses.
event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool)
	{
	if ( ! is_orig )
		return;

	if ( ! c?$modbus_pending_tids )
		c$modbus_pending_tids = set();

	add c$modbus_pending_tids[headers$tid];

	# Safety valve: reset if set grows unreasonably large.
	if ( |c$modbus_pending_tids| >= 256 )
		{
		Reporter::conn_weird("modbus_tid_overflow", c);
		c$modbus_pending_tids = set();
		}
	}

# Clean up TIDs on normal responses (priority -10 runs after other handlers).
event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool)
    &priority=-10
	{
	if ( is_orig )
		return;

	if ( c?$modbus_pending_tids )
		delete c$modbus_pending_tids[headers$tid];
	}
