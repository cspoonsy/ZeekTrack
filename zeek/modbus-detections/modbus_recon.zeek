# modbus_recon.zeek — Per-connection enumeration and scan detection.
#
# Produces modbus_recon.log: one row per connection at close, only when at
# least one recon indicator is non-zero.  All decision-making is per-connection
# so this script is cluster-safe without Broker.
#
# Zero-config notices (fire from the first packet, no allow-list needed):
#   Modbus::IllegalFunctionScan — >illegal_function_scan_threshold distinct
#       function codes received ILLEGAL_FUNCTION in one connection
#   Modbus::UnitScan            — >unit_scan_threshold distinct unit IDs in
#       one connection

@load base/frameworks/notice
@load base/frameworks/sumstats
@load base/protocols/modbus
@load ./modbus_detect

module Modbus;

export {
	redef enum Log::ID += { LOG_RECON };

	type ReconInfo: record {
		## Timestamp at connection close.
		ts: time &log;
		## Connection UID.
		uid: string &log;
		## Connection 4-tuple.
		id: conn_id &log;
		## Set of distinct unit IDs addressed in this connection.
		unit_ids_seen: set[count] &log;
		## Set of distinct function codes attempted.
		func_codes_tried: set[string] &log;
		## Total exception responses received.
		exception_count: count &log;
		## Write operations in this connection.
		write_count: count &log;
		## Total requests sent.
		request_count: count &log;
		## Total responses received.
		response_count: count &log;
	};

	global log_modbus_recon: event(rec: ReconInfo);
}

# ---------------------------------------------------------------------------
# Per-connection state
# ---------------------------------------------------------------------------

type ReconState: record {
	unit_ids_seen: set[count] &default=set();
	func_codes_tried: set[string] &default=set();
	illegal_funcs: set[string] &default=set(); # for IllegalFunctionScan
	exception_count: count &default=0;
	write_count: count &default=0;
	request_count: count &default=0;
	response_count: count &default=0;
};

redef record connection += {
	modbus_recon: ReconState &optional;
};

function _recon_state(c: connection): ReconState
	{
	if ( ! c?$modbus_recon )
		c$modbus_recon = ReconState();
	return c$modbus_recon;
	}

# ---------------------------------------------------------------------------
# Log stream
# ---------------------------------------------------------------------------

event zeek_init() &priority=5
	{
	Log::create_stream(Modbus::LOG_RECON, [$columns=ReconInfo,
	    $ev=log_modbus_recon, $path="modbus_recon", ]);
	}

# ---------------------------------------------------------------------------
# DET-019 ReadSweep — SumStats for unauthorized register enumeration
# ---------------------------------------------------------------------------

function _read_sweep_threshold_val(key: SumStats::Key, result: SumStats::Result)
    : double
	{
	if ( "modbus.recon.read_sweep" !in result )
		return 0.0;
	return result["modbus.recon.read_sweep"]$unique + 0.0;
	}

function _read_sweep_threshold_crossed(key: SumStats::Key,
    result: SumStats::Result)
	{
	if ( "modbus.recon.read_sweep" !in result )
		return;
	local master = to_addr(key$str);
	local cnt = result["modbus.recon.read_sweep"]$unique;
	NOTICE([$note=Modbus::ReadSweep, $msg=fmt("%s read %d distinct (function, address) combinations in %s — unauthorized register enumeration",
	    master, cnt, modbus_detect::read_sweep_interval), $src=master,
	    $identifier=cat(master), $suppress_for=10min]);
	}

event zeek_init() &priority=3
	{
	SumStats::create([$name="modbus.recon.read_sweep",
	    $epoch=modbus_detect::read_sweep_interval, $reducers=set(
	    SumStats::Reducer($stream="modbus.recon.read_sweep", $apply=set(
	    SumStats::UNIQUE)), ), $threshold_val=_read_sweep_threshold_val,
	    $threshold=modbus_detect::read_sweep_threshold + 0.0,
	    $threshold_crossed=_read_sweep_threshold_crossed, ]);
	}

function _observe_read_sweep(c: connection, func: string, start_address: count)
	{
	# Suppress when authorized_masters is not configured (no baseline = no signal).
	if ( modbus_detect::is_authorized_master(c$id$orig_h) )
		return;
	SumStats::observe("modbus.recon.read_sweep", SumStats::Key($str=cat(
	    c$id$orig_h)), SumStats::Observation($str=fmt("%s,%d", func,
	    start_address)));
	}

event modbus_read_coils_request(c: connection, headers: ModbusHeaders,
    start_address: count, quantity: count)
	{
	_observe_read_sweep(c, "READ_COILS", start_address);
	}

event modbus_read_discrete_inputs_request(c: connection, headers: ModbusHeaders,
    start_address: count, quantity: count)
	{
	_observe_read_sweep(c, "READ_DISCRETE_INPUTS", start_address);
	}

event modbus_read_holding_registers_request(c: connection,
    headers: ModbusHeaders, start_address: count, quantity: count)
	{
	_observe_read_sweep(c, "READ_HOLDING_REGISTERS", start_address);
	}

event modbus_read_input_registers_request(c: connection, headers: ModbusHeaders,
    start_address: count, quantity: count)
	{
	_observe_read_sweep(c, "READ_INPUT_REGISTERS", start_address);
	}

# ---------------------------------------------------------------------------
# Event handlers
# ---------------------------------------------------------------------------

event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool)
	{
	if ( ! c?$modbus || ! c$modbus?$func )
		return;

	local st = _recon_state(c);
	add st$unit_ids_seen[headers$uid];
	add st$func_codes_tried[c$modbus$func];

	if ( is_orig )
		++st$request_count;
	else
		++st$response_count;

	if ( is_orig && c$modbus$func in modbus_detect::write_function_codes )
		++st$write_count;
	}

event modbus_exception(c: connection, headers: ModbusHeaders, code: count)
	{
	local exception_str = Modbus::exception_codes[code];
	local base_fc = headers$function_code & ~0x80;
	local func_str = Modbus::function_codes[base_fc];

	local st = _recon_state(c);
	++st$exception_count;

	# DET-006: track distinct func codes that got ILLEGAL_FUNCTION
	if ( exception_str == "ILLEGAL_FUNCTION" )
		add st$illegal_funcs[func_str];
	}

event connection_state_remove(c: connection)
	{
	if ( ! c?$modbus_recon )
		return;

	local st = c$modbus_recon;

	# Only log when anomalous activity was observed.  unit_ids_seen and
	# func_codes_tried are always non-empty for any valid Modbus connection
	# so testing them for non-zero would log every polling connection.
	#
	# Write-only connections (write_count > 0 but no other indicators) are
	# NOT logged here — the write is fully captured in modbus_writes.log.
	# write_count is retained as a context field for connections that also
	# show scan activity (multiple unit IDs, exceptions, or illegal functions).
	if ( |st$unit_ids_seen| <= 1
	    && |st$illegal_funcs| == 0
	    && st$exception_count == 0 )
		return;

	local rec: ReconInfo = [$ts=network_time(), $uid=c$uid, $id=c$id,
	    $unit_ids_seen=st$unit_ids_seen,
	    $func_codes_tried=st$func_codes_tried,
	    $exception_count=st$exception_count, $write_count=st$write_count,
	    $request_count=st$request_count, $response_count=st$response_count, ];
	Log::write(LOG_RECON, rec);

	# DET-008 UnitScan
	if ( |st$unit_ids_seen| > modbus_detect::unit_scan_threshold )
		{
		NOTICE([$note=Modbus::UnitScan, $msg=fmt("%s addressed %d distinct unit IDs in one connection to %s (unit scan)",
		    c$id$orig_h, |st$unit_ids_seen|, c$id$resp_h), $conn=c,
		    $identifier=cat(c$id$orig_h, c$id$resp_h), $suppress_for=10min]);
		}

	# DET-006 IllegalFunctionScan
	if ( |st$illegal_funcs| > modbus_detect::illegal_function_scan_threshold )
		{
		NOTICE([$note=Modbus::IllegalFunctionScan, $msg=fmt("%s tried %d distinct function codes that returned ILLEGAL_FUNCTION to %s (function code enumeration)",
		    c$id$orig_h, |st$illegal_funcs|, c$id$resp_h), $conn=c,
		    $identifier=cat(c$id$orig_h, c$id$resp_h), $suppress_for=10min]);
		}
	}
