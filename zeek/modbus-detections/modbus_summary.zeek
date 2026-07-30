# modbus_summary.zeek — Hourly per-master/slave/unit aggregate counts.
#
# Produces modbus_summary.log: one row per (master, slave, unit) per hour.
# A deployment generating 1.4M raw modbus.log rows/day from 2 masters to 16
# slaves produces ~16 summary rows per hour — >99% volume reduction.
#
# Also implements DET-013 RequestFlood via a separate 5-second SumStats epoch.
#
# Zero-config notice:
#   Modbus::RequestFlood — >request_flood_threshold requests in
#                           request_flood_interval per master/slave pair.
#
# SumStats is cluster-aware via Broker; all count fields are accurate in
# clustered deployments.  Workers accumulate func_codes_seen locally and flush
# to the proxy (or manager when no proxies) via the func_codes_batch Broker
# event every master_state_flush_interval; proxies union-merge deltas from
# multiple workers before forwarding to the manager; all fields are accurate.

@load base/frameworks/notice
@load base/frameworks/sumstats
@load base/protocols/modbus
@load ./modbus_detect
@load cluster_relay_lib

module Modbus;

export {
	redef enum Log::ID += { LOG_SUMMARY };

	type SummaryInfo: record {
		## Hour boundary timestamp.
		ts: time &log;
		## Modbus master (source IP).
		master: addr &log;
		## Modbus slave (destination IP).
		slave: addr &log;
		## Unit ID on this slave.
		unit: count &log;
		## Total read-function-code PDUs this hour.
		read_count: count &log;
		## Total write-function-code PDUs this hour.
		write_count: count &log;
		## Total exception responses this hour.
		exception_count: count &log;
		## Unique function code strings observed.
		func_codes_seen: set[string] &log;
	};

	global log_modbus_summary: event(rec: SummaryInfo);

	## Broker event: workers relay per-PDU (key, func) observations to the
	## manager.  The manager accumulates _func_codes so func_codes_seen is
	## accurate in clustered deployments.
	## @deprecated Cluster mode: superseded by func_codes_batch (batch flush);
	## kept for API compatibility.  See modbus_masters.zeek master_state_update
	## for the same pattern.
	global func_code_observed: event(key: string, func: string);

	## Broker event: workers send accumulated func-code observations to the proxy
	## (or manager when no proxies) every master_state_flush_interval.  Proxies
	## union-merge deltas from multiple workers and forward to the manager.
	global func_codes_batch: event(codes: table[string] of set[string]);

	## Internal: scheduled event fired on each worker every flush_interval to
	## push worker-local func-code observations to the proxy/manager.  Exported
	## because Broker requires globally routable event names; not intended for
	## external use.
	global _flush_worker_func_codes: event();

	## Internal: scheduled event fired on each proxy to forward merged func-code
	## observations to the manager.  Exported because Broker requires globally
	## routable event names; not intended for external use.
	global _flush_proxy_summary: event();
}

# ---------------------------------------------------------------------------
# Log stream
# ---------------------------------------------------------------------------

event zeek_init() &priority=5
	{
	Log::create_stream(Modbus::LOG_SUMMARY, [$columns=SummaryInfo,
	    $ev=log_modbus_summary, $path="modbus_summary", ]);
	}

# ---------------------------------------------------------------------------
# func_codes_seen tracking — global table per SumStats key string.
# Standalone: populated directly in modbus_message.
# Cluster: populated on the manager via func_codes_batch Broker relay;
# workers accumulate in _worker_func_codes and flush every flush_interval.
# ---------------------------------------------------------------------------

# key_str → set of distinct function code strings observed this epoch.
global _func_codes: table[string] of set[string] &create_expire=7day;

# ---------------------------------------------------------------------------
# Cluster: Broker relay for func_codes_seen
# ---------------------------------------------------------------------------

@if ( Cluster::is_enabled() )

event Modbus::func_code_observed(key: string, func: string)
	{
	# Retained for external API compatibility only.  The internal cluster path
	# no longer calls this event (superseded by func_codes_batch).
	# Only the manager accumulates state.
	if ( Cluster::local_node_type() != Cluster::MANAGER )
		return;
	if ( key !in _func_codes )
		_func_codes[key] = set();
	add _func_codes[key][func];
	}

@endif

@if ( Cluster::is_enabled() )

# Worker-local func-code accumulation — flushed to proxy/manager every
# master_state_flush_interval.  Replaces per-PDU func_code_observed relay.
global _worker_func_codes: table[string] of set[string] &create_expire=5min;

event Modbus::_flush_worker_func_codes()
	{
	if ( ! ClusterRelay::is_worker() )
		return;
	# Skip the Broker send when nothing accumulated — avoids empty-batch messages
	# during quiet periods.  (modbus_masters.zeek always sends; asymmetry is fine.)
	if ( |_worker_func_codes| > 0 )
		{
		# Group entries by master IP for HRW routing.  Each master addr routes
		# to a consistent proxy so that proxy-side union merges are complete.
		local by_master: table[addr] of table[string] of set[string];
		local master_ip: addr;
		for ( key in _worker_func_codes )
			{
			local parts = split_string(key, /\//);
			master_ip = to_addr(parts[0]);
			if ( master_ip !in by_master )
				by_master[master_ip] = table();
			by_master[master_ip][key] = _worker_func_codes[key];
			}
		for ( master_ip in by_master )
			ClusterRelay::publish_to_proxy(master_ip, Cluster::make_event(
			    Modbus::func_codes_batch, by_master[master_ip]));
		_worker_func_codes = table();
		}
	schedule modbus_detect::master_state_flush_interval {
	    Modbus::_flush_worker_func_codes() };
	}

# Proxy-local merged func-code accumulation — union-merges deltas from
# multiple workers, then flushes merged state to manager.
global _proxy_func_codes: table[string] of set[string] &create_expire=5min;

event Modbus::func_codes_batch(codes: table[string] of set[string])
	{
	if ( ClusterRelay::is_proxy() )
		{
		# Proxy: union-merge deltas from workers into proxy state.
		for ( key in codes )
			{
			if ( key !in _proxy_func_codes )
				_proxy_func_codes[key] = set();
			for ( func in codes[key] )
				add _proxy_func_codes[key][func];
			}
		return;
		}
	if ( ClusterRelay::is_manager() )
		{
		# Manager: apply merged batch from proxy (or direct from worker when
		# no proxies exist) into authoritative state.
		for ( key in codes )
			{
			if ( key !in _func_codes )
				_func_codes[key] = set();
			for ( func in codes[key] )
				add _func_codes[key][func];
			}
		}
	}

event Modbus::_flush_proxy_summary()
	{
	if ( ! ClusterRelay::is_proxy() )
		return;
	if ( |_proxy_func_codes| > 0 )
		{
		ClusterRelay::publish_to_manager(Cluster::make_event(Modbus::func_codes_batch,
		    _proxy_func_codes));
		_proxy_func_codes = table();
		}
	schedule modbus_detect::master_state_flush_interval {
	    Modbus::_flush_proxy_summary() };
	}

event zeek_init() &priority=1
	{
	if ( ClusterRelay::is_worker() )
		schedule modbus_detect::master_state_flush_interval {
		    Modbus::_flush_worker_func_codes() };
	if ( ClusterRelay::is_proxy() )
		schedule modbus_detect::master_state_flush_interval {
		    Modbus::_flush_proxy_summary() };
	}

@endif

# ---------------------------------------------------------------------------
# Named callback functions for SumStats
# ---------------------------------------------------------------------------

function _summary_epoch_result(ts: time, key: SumStats::Key,
    result: SumStats::Result)
	{
	local parts = split_string(key$str, /\//);
	if ( |parts| < 3 )
		return;
	local master = to_addr(parts[0]);
	local slave = to_addr(parts[1]);
	local unit = to_count(parts[2]);

	local reads = "modbus.summary.reads" in result ? double_to_count(
	    result["modbus.summary.reads"]$sum) : 0;
	local writes = "modbus.summary.writes" in result ? double_to_count(
	    result["modbus.summary.writes"]$sum) : 0;
	local excpts = "modbus.summary.exceptions" in result ? double_to_count(
	    result["modbus.summary.exceptions"]$sum) : 0;

	local funcs: set[string] = set();
	if ( key$str in _func_codes )
		{
		funcs = copy(_func_codes[key$str]);
		delete _func_codes[key$str];
		}

	local rec: SummaryInfo = [$ts=ts, $master=master, $slave=slave, $unit=unit,
	    $read_count=reads, $write_count=writes, $exception_count=excpts,
	    $func_codes_seen=funcs, ];
	Log::write(LOG_SUMMARY, rec);
	}

function _flood_threshold_val(key: SumStats::Key, result: SumStats::Result)
    : double
	{
	if ( "modbus.flood" !in result )
		return 0.0;
	return result["modbus.flood"]$sum;
	}

function _flood_threshold_crossed(key: SumStats::Key, result: SumStats::Result)
	{
	if ( "modbus.flood" !in result )
		return;
	local parts = split_string(key$str, /\//);
	if ( |parts| < 2 )
		return;
	local master = to_addr(parts[0]);
	local slave = to_addr(parts[1]);
	local cnt = double_to_count(result["modbus.flood"]$sum);
	NOTICE([$note=Modbus::RequestFlood, $msg=fmt(
	    "%s sent %d requests to %s in %s (threshold: %d) — possible DoS",
	    master, cnt, slave, modbus_detect::request_flood_interval,
	    modbus_detect::request_flood_threshold), $src=master, $dst=slave,
	    $identifier=cat(master, slave), $suppress_for=30sec]);
	}

# ---------------------------------------------------------------------------
# SumStats setup
# ---------------------------------------------------------------------------

event zeek_init() &priority=3
	{
	# === Hourly summary (epoch configurable for testing) ====================
	SumStats::create([$name="modbus.summary", $epoch=modbus_detect::summary_epoch,
	    $reducers=set(SumStats::Reducer($stream="modbus.summary.reads",
	    $apply=set(SumStats::SUM)), SumStats::Reducer(
	    $stream="modbus.summary.writes", $apply=set(SumStats::SUM)),
	    SumStats::Reducer($stream="modbus.summary.exceptions", $apply=set(
	    SumStats::SUM)), ), $epoch_result=_summary_epoch_result, ]);

	# === 5-second RequestFlood =============================================
	SumStats::create([$name="modbus.flood",
	    $epoch=modbus_detect::request_flood_interval, $reducers=set(
	    SumStats::Reducer($stream="modbus.flood", $apply=set(
	    SumStats::SUM)), ), $threshold_val=_flood_threshold_val,
	    $threshold=modbus_detect::request_flood_threshold + 0.0,
	    $threshold_crossed=_flood_threshold_crossed, ]);
	}

# ---------------------------------------------------------------------------
# Event handlers: observe every PDU
# ---------------------------------------------------------------------------

event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool)
	{
	if ( ! is_orig )
		return;
	if ( ! c?$modbus || ! c$modbus?$func )
		return;

	local master = c$id$orig_h;
	local slave = c$id$resp_h;
	local unit = headers$uid;
	local func = c$modbus$func;

	local sum_key = SumStats::Key($str=cat(master, "/", slave, "/", unit));
	local flood_key = SumStats::Key($str=cat(master, "/", slave));
	local obs1 = SumStats::Observation($num=1);

	# Classify as read or write.
	if ( func in modbus_detect::write_function_codes )
		SumStats::observe("modbus.summary.writes", sum_key, obs1);
	else
		SumStats::observe("modbus.summary.reads", sum_key, obs1);

	# Track unique function codes.
	local kstr = sum_key$str;
@if ( Cluster::is_enabled() )
	# Accumulate locally; flushed to proxy/manager every flush_interval.
	if ( kstr !in _worker_func_codes )
		_worker_func_codes[kstr] = set();
	add _worker_func_codes[kstr][func];
@else
	if ( kstr !in _func_codes )
		_func_codes[kstr] = set();
	add _func_codes[kstr][func];
@endif

	# RequestFlood — every request counts.
	SumStats::observe("modbus.flood", flood_key, obs1);
	}

event modbus_exception(c: connection, headers: ModbusHeaders, code: count)
	{
	# Count exceptions in the hourly summary.
	local master = c$id$orig_h;
	local slave = c$id$resp_h;
	local unit = headers$uid;
	SumStats::observe("modbus.summary.exceptions", SumStats::Key($str=cat(master,
	    "/", slave, "/", unit)), SumStats::Observation($num=1));
	}
