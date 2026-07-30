# modbus_register_values.zeek — DET-020: Register value range summary and
# anomalous-write detection.
#
# Produces modbus_register_values.log: one row per (master, slave, unit,
# register) per summary_epoch, recording the min/max value range observed
# in read traffic during that epoch.
#
# Optional notice (off by default — set register_value_alert_enabled = T):
#   Modbus::RegisterValueAnomaly — a write value falls outside the observed
#       min/max range by more than register_value_alert_pct (default 50%).
#       Only fires for registers where max_observed >= register_value_alert_min
#       (default 4) to prevent noise from boolean-like registers.
#
# Depends on modbus_register_tracking.zeek for request→response correlation.
#
# Cluster notes: SumStats MIN/MAX reducers are cluster-aware.  The anomaly
# notice uses worker-local last-read state from modbus_register_tracking.zeek;
# because connections are sticky to workers in a Zeek cluster, the read that
# precedes a write on the same connection will always be on the same worker.

@load base/frameworks/notice
@load base/frameworks/sumstats
@load base/protocols/modbus
@load ./modbus_detect
@load ./modbus_register_tracking

module Modbus;

export {
	redef enum Log::ID += { LOG_REGISTER_VALUES };

	type RegisterValueInfo: record {
		## Epoch boundary timestamp.
		ts: time &log;
		## Modbus master IP.
		master: addr &log;
		## Modbus slave IP.
		slave: addr &log;
		## Unit ID on this slave.
		unit: count &log;
		## Register address (0-based).
		register: count &log;
		## Minimum value observed in read traffic during this epoch.
		min_val: count &log;
		## Maximum value observed in read traffic during this epoch.
		max_val: count &log;
		## Number of read observations during this epoch.
		obs_count: count &log;
	};

	global log_modbus_register_values: event(rec: RegisterValueInfo);
}

# ---------------------------------------------------------------------------
# Log stream
# ---------------------------------------------------------------------------

event zeek_init() &priority=5
	{
	Log::create_stream(Modbus::LOG_REGISTER_VALUES, [$columns=RegisterValueInfo,
	    $ev=log_modbus_register_values, $path="modbus_register_values", ]);
	}

# ---------------------------------------------------------------------------
# SumStats: MIN and MAX per (master/slave/unit/register) per epoch
# ---------------------------------------------------------------------------

function _rv_epoch_result(ts: time, key: SumStats::Key,
    result: SumStats::Result)
	{
	local parts = split_string(key$str, /\//);
	if ( |parts| < 4 )
		return;
	local master = to_addr(parts[0]);
	local slave = to_addr(parts[1]);
	local unit = to_count(parts[2]);
	local register = to_count(parts[3]);

	if ( "modbus.regval.min" !in result || "modbus.regval.max" !in result )
		return;

	local min_v = double_to_count(result["modbus.regval.min"]$min);
	local max_v = double_to_count(result["modbus.regval.max"]$max);
	local cnt = "modbus.regval.obs" in result ? double_to_count(
	    result["modbus.regval.obs"]$num) : 0;

	local rec: RegisterValueInfo = [$ts=ts, $master=master, $slave=slave,
	    $unit=unit, $register=register, $min_val=min_v, $max_val=max_v,
	    $obs_count=cnt, ];
	Log::write(LOG_REGISTER_VALUES, rec);
	}

event zeek_init() &priority=3
	{
	SumStats::create([$name="modbus.regval", $epoch=modbus_detect::summary_epoch,
	    $reducers=set(SumStats::Reducer($stream="modbus.regval.min",
	    $apply=set(SumStats::MIN)), SumStats::Reducer(
	    $stream="modbus.regval.max", $apply=set(SumStats::MAX)),
	    SumStats::Reducer($stream="modbus.regval.obs", $apply=set(
	    SumStats::SUM)), ), $epoch_result=_rv_epoch_result, ]);
	}

# ---------------------------------------------------------------------------
# DET-020: Accumulated min/max range per (slave, unit, register).
# Defined here so _update_reg_range is available to the read-response handlers.
# ---------------------------------------------------------------------------

# key = "slave/unit/register"
type RegRange: record {
	min_val: count;
	max_val: count;
	obs_count: count;
};

global _reg_ranges: table[string] of RegRange &create_expire=7day;

# Diagnostic counter — prints _reg_ranges size every 10000 new insertions.
global _reg_ranges_add_count: count = 0;

# Called from read response handlers to update the accumulated range.
function _update_reg_range(slave: addr, unit: count, address: count,
    value: count)
	{
	local k = cat(slave, "/", unit, "/", address);
	if ( k !in _reg_ranges )
		{
		_reg_ranges[k] = RegRange($min_val=value, $max_val=value,
		    $obs_count=1);
		++_reg_ranges_add_count;
		if ( _reg_ranges_add_count % 10000 == 0 )
			Reporter::info(fmt("[modbus diag] _reg_ranges size=%d after %d inserts (network_time=%s)",
			    |_reg_ranges|, _reg_ranges_add_count, network_time()));
		return;
		}
	local r = _reg_ranges[k];
	if ( value < r$min_val )
		r$min_val = value;
	if ( value > r$max_val )
		r$max_val = value;
	++r$obs_count;
	}

# ---------------------------------------------------------------------------
# Observe read values via the tracking module's last-read events
# ---------------------------------------------------------------------------

event modbus_read_holding_registers_response(c: connection,
    headers: ModbusHeaders, registers: ModbusRegisters)
	{
	if ( ! c?$modbus_pending_reads )
		return;
	if ( headers$tid !in c$modbus_pending_reads )
		return;

	local req = c$modbus_pending_reads[headers$tid];
	local master = c$id$orig_h;
	local slave = c$id$resp_h;

	for ( idx in registers )
		{
		local reg_addr = req$start_address + idx;
		local reg_val = registers[idx];
		local k = SumStats::Key($str=cat(master, "/", slave, "/", req$unit, "/",
		    reg_addr));
		SumStats::observe("modbus.regval.min", k, SumStats::Observation(
		    $num=reg_val));
		SumStats::observe("modbus.regval.max", k, SumStats::Observation(
		    $num=reg_val));
		SumStats::observe("modbus.regval.obs", k, SumStats::Observation($num=1));
		# DET-020: update accumulated range for anomaly detection.
		_update_reg_range(slave, req$unit, reg_addr, reg_val);
		}
	}

event modbus_read_input_registers_response(c: connection,
    headers: ModbusHeaders, registers: ModbusRegisters)
	{
	if ( ! c?$modbus_pending_reads )
		return;
	if ( headers$tid !in c$modbus_pending_reads )
		return;

	local req = c$modbus_pending_reads[headers$tid];
	local master = c$id$orig_h;
	local slave = c$id$resp_h;

	for ( idx in registers )
		{
		local reg_addr = req$start_address + idx;
		local reg_val = registers[idx];
		local k = SumStats::Key($str=cat(master, "/", slave, "/", req$unit, "/",
		    reg_addr));
		SumStats::observe("modbus.regval.min", k, SumStats::Observation(
		    $num=reg_val));
		SumStats::observe("modbus.regval.max", k, SumStats::Observation(
		    $num=reg_val));
		SumStats::observe("modbus.regval.obs", k, SumStats::Observation($num=1));
		# DET-020: update accumulated range for anomaly detection.
		_update_reg_range(slave, req$unit, reg_addr, reg_val);
		}
	}

# ---------------------------------------------------------------------------
# DET-020 RegisterValueAnomaly — check write values against observed min/max
# range accumulated across all read traffic for this register.
# ---------------------------------------------------------------------------

function _check_write_anomaly(c: connection, unit: count, address: count,
    value: count)
	{
	if ( ! modbus_detect::register_value_alert_enabled )
		return;

	local k = cat(c$id$resp_h, "/", unit, "/", address);
	if ( k !in _reg_ranges )
		return;

	local r = _reg_ranges[k];

	# Only alert for registers with meaningful range.
	if ( r$max_val < modbus_detect::register_value_alert_min )
		return;

	# Need enough observations to establish a baseline.
	if ( r$obs_count < modbus_detect::register_value_alert_min )
		return;

	local pct: double = modbus_detect::register_value_alert_pct / 100.0;
	local range_size: double = r$max_val - r$min_val;
	local margin: double;
	if ( range_size > 0.0 )
		margin = range_size * pct;
	else
		margin = r$max_val * pct;

	local written: double = value;
	local threshold_high: double = r$max_val + margin;
	local threshold_low: double;
	if ( margin <= r$min_val )
		threshold_low = r$min_val - margin;
	else
		threshold_low = 0.0;

	if ( written <= threshold_high && written >= threshold_low )
		return;

	NOTICE([$note=Modbus::RegisterValueAnomaly, $msg=fmt("%s wrote 0x%04x to slave %s unit=%d register=%d; observed range [0x%04x, 0x%04x] over %d reads (outside +/-%.0f%% of range)",
	    c$id$orig_h, value, c$id$resp_h, unit, address, r$min_val,
	    r$max_val, r$obs_count,
	    modbus_detect::register_value_alert_pct), $conn=c, $identifier=cat(
	    c$id$orig_h, c$id$resp_h, unit, address), $suppress_for=5min]);
	}

event modbus_write_single_register_request(c: connection,
    headers: ModbusHeaders, address: count, value: count)
	{
	_check_write_anomaly(c, headers$uid, address, value);
	}

event modbus_write_multiple_registers_request(c: connection,
    headers: ModbusHeaders, start_address: count, registers: ModbusRegisters)
	{
	for ( idx in registers )
		_check_write_anomaly(c, headers$uid, start_address + idx, registers[idx]);
	}

event modbus_read_write_multiple_registers_request(c: connection,
    headers: ModbusHeaders, read_start_address: count, read_quantity: count,
    write_start_address: count, write_registers: ModbusRegisters)
	{
	for ( idx in write_registers )
		_check_write_anomaly(c, headers$uid, write_start_address + idx,
		    write_registers[idx]);
	}
