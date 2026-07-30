# modbus_masters.zeek — Hourly master IP activity + rogue master detection.
#
# Produces modbus_masters.log: one row per master IP per hour.
# Provides the authorized master baseline for modbus_writes.log's authorized field.
#
# Notices:
#   Modbus::RogueMaster — first PDU from a source not in authorized_masters.
#       Cluster: workers raise Modbus::master_seen via Broker; the proxy
#       deduplicates and forwards to manager; the manager maintains the seen-set
#       and fires the notice exactly once per new IP.
#   Modbus::MultiSlaveSweep — >multi_slave_sweep_threshold distinct slave IPs
#       from the same master in multi_slave_sweep_interval (SumStats).
#
# Cluster log accuracy:
#   _master_states (slaves_contacted, unit_ids_used, write_count) is populated
#   via master_state_batch Broker relay: workers accumulate state locally and
#   flush a batch to the proxy every master_state_flush_interval (default 5s).
#   The proxy merges deltas from multiple workers and flushes a merged batch to
#   the manager.  All three fields are accurate in clustered deployments.

@load base/frameworks/notice
@load base/frameworks/sumstats
@load base/protocols/modbus
@load ./modbus_detect
@load cluster_relay_lib

module Modbus;

export {
	redef enum Log::ID += { LOG_MASTERS };

	type MastersInfo: record {
		## Hour boundary timestamp.
		ts: time &log;
		## Master IP address.
		master: addr &log;
		## Total Modbus requests issued this hour.
		request_count: count &log;
		## Slave IPs contacted this hour.
		slaves_contacted: set[addr] &log;
		## Unit IDs addressed across all slaves.
		unit_ids_used: set[count] &log;
		## Write operations issued this hour.
		write_count: count &log;
		## T on the first hour this master IP appears.
		first_seen: bool &log;
	};

	global log_modbus_masters: event(rec: MastersInfo);

	## Broker event: workers raise this for each new (or first-ever) Modbus PDU
	## from a source IP.  The proxy deduplicates and forwards to manager.
	## The manager checks the seen-set and fires RogueMaster exactly once per
	## new master IP.  Cluster-safe.
	global master_seen: event(master: addr, slave: addr);

	## Broker event: (DEPRECATED in cluster mode — superseded by master_state_batch)
	## Kept for API compatibility.  The internal cluster path no longer raises this
	## event; state accumulation now uses worker-local buffering + master_state_batch.
	## External callers may still raise this event; the manager handler remains active.
	global master_state_update: event(master: addr, slave: addr, unit: count,
	    is_write: bool);

	## Broker event: workers send batched master state to the proxy every
	## master_state_flush_interval.  The proxy merges and forwards to manager.
	## sample_slave is the first slave that received a write in this batch, or
	## 0.0.0.0 if write_count == 0.  Used only for DET-017 NOTICE context.
	global master_state_batch: event(master: addr, slaves: set[addr], units: set[
	    count], write_count: count, sample_slave: addr);

	## Internal: scheduled event fired on each worker every flush_interval to
	## push _local_master_states to the proxy.  Exported because Broker
	## requires globally routable event names; not intended for external use.
	global _flush_worker_master_states: event();

	## Internal: scheduled event fired on each proxy every flush_interval to
	## forward merged _proxy_master_state to the manager.  Exported because
	## Broker requires globally routable event names; not intended for external use.
	global _flush_proxy_master_states: event();
}

# ---------------------------------------------------------------------------
# Per-master per-epoch state
# Standalone: populated directly in modbus_message handlers.
# Cluster: populated on the manager via master_state_batch Broker relay;
# workers never write to this table.
# ---------------------------------------------------------------------------

type MasterState: record {
	slaves_contacted: set[addr] &default=set();
	unit_ids_used: set[count] &default=set();
	write_count: count &default=0;
};

# State accumulated between SumStats epochs (reset at each epoch_result).
global _master_states: table[addr] of MasterState &create_expire=7day;

# DET-017 AuthorizedMasterWriteEscalation state.
# Tracks which masters have issued at least one write.
global _master_has_written: set[addr] &create_expire=7day;
# First observation time per master, for grace period calculation.
global _master_first_seen: table[addr] of time &create_expire=7day;

# Seen-set for RogueMaster notice deduplication: populated in modbus_message.
# Manager-authoritative in cluster, global in standalone.
global _seen_masters: set[addr] &create_expire=1day;

# Separate set tracking masters that have been written to modbus_masters.log
# at least once.  Only updated in _masters_epoch_result, so first_seen=T
# correctly marks the first log row even when _seen_masters was already
# populated by modbus_message (for the RogueMaster notice).
global _logged_masters: set[addr] &create_expire=1day;

# ---------------------------------------------------------------------------
# Log stream
# ---------------------------------------------------------------------------

event zeek_init() &priority=5
	{
	Log::create_stream(Modbus::LOG_MASTERS, [$columns=MastersInfo,
	    $ev=log_modbus_masters, $path="modbus_masters", ]);
	}

# ---------------------------------------------------------------------------
# SumStats for MultiSlaveSweep
# ---------------------------------------------------------------------------

function _sweep_threshold_val(key: SumStats::Key, result: SumStats::Result)
    : double
	{
	if ( "modbus.masters.sweep" !in result )
		return 0.0;
	# UNIQUE reducer populates $unique (count), not $sum.
	return result["modbus.masters.sweep"]$unique + 0.0;
	}

function _sweep_threshold_crossed(key: SumStats::Key, result: SumStats::Result)
	{
	if ( "modbus.masters.sweep" !in result )
		return;
	local master = to_addr(key$str);
	local cnt = result["modbus.masters.sweep"]$unique;
	NOTICE([$note=Modbus::MultiSlaveSweep, $msg=fmt(
	    "%s contacted %d distinct slave IPs in %s (multi-slave sweep)",
	    master, cnt, modbus_detect::multi_slave_sweep_interval),
	    $src=master, $identifier=cat(master), $suppress_for=5min]);
	}

# Emit hourly summary from accumulated per-master state.
function _masters_epoch_result(ts: time, key: SumStats::Key,
    result: SumStats::Result)
	{
	local master = to_addr(key$str);
	# Use _logged_masters (not _seen_masters) so first_seen=T is correct even
	# when the RogueMaster notice already added this master to _seen_masters.
	local first = master !in _logged_masters;
	add _logged_masters[master];

	local slaves: set[addr] = set();
	local units: set[count] = set();
	local writes: count = 0;

	if ( master in _master_states )
		{
		local st = _master_states[master];
		slaves = copy(st$slaves_contacted);
		units = copy(st$unit_ids_used);
		writes = st$write_count;
		delete _master_states[master];
		}

	local reqs = "modbus.masters.summary" in result ? double_to_count(
	    result["modbus.masters.summary"]$sum) : 0;

	local rec: MastersInfo = [$ts=ts, $master=master, $request_count=reqs,
	    $slaves_contacted=slaves, $unit_ids_used=units, $write_count=writes,
	    $first_seen=first, ];
	Log::write(LOG_MASTERS, rec);
	}

event zeek_init() &priority=3
	{
	# SumStats for hourly per-master summary (key = master IP string).
	# We use a minimal SUM reducer as a "heartbeat" to get the epoch_result
	# callback; the actual data is in _master_states.
	SumStats::create([$name="modbus.masters.summary",
	    $epoch=modbus_detect::summary_epoch, $reducers=set(
	    SumStats::Reducer($stream="modbus.masters.summary", $apply=set(
	    SumStats::SUM)), ), $epoch_result=_masters_epoch_result, ]);

	# SumStats for MultiSlaveSweep (key = master IP, value = distinct slave count).
	SumStats::create([$name="modbus.masters.sweep",
	    $epoch=modbus_detect::multi_slave_sweep_interval, $reducers=set(
	    SumStats::Reducer($stream="modbus.masters.sweep", $apply=set(
	    SumStats::UNIQUE)), ), $threshold_val=_sweep_threshold_val,
	    $threshold=modbus_detect::multi_slave_sweep_threshold + 0.0,
	    $threshold_crossed=_sweep_threshold_crossed, ]);
	}

# ---------------------------------------------------------------------------
# Cluster: three-tier proxy-based relay for RogueMaster seen-set and
# master state behavioral accumulation
# ---------------------------------------------------------------------------

@if ( Cluster::is_enabled() )

# Worker-local dedup — relay master_seen to proxy at most once per master IP
# per worker lifetime.  Mirrors the _local_subscribed pattern in mqtt_clients.zeek.
global _local_seen_masters: set[addr] &create_expire=1hr;

# Worker-local master state — accumulated here, flushed to proxy every
# master_state_flush_interval.  Replaces per-PDU master_state_update relay.
global _local_master_states: table[addr] of MasterState &create_expire=5min;

# Records the first slave address that received a write from each master in the
# current flush window.  Passed to master_state_batch for DET-017 NOTICE context.
global _local_write_slave: table[addr] of addr &create_expire=5min;

# Proxy-local seen-set for master_seen dedup (seen-set family).
global _proxy_seen_masters: set[addr] &create_expire=1hr;

# Proxy-local merged delta state for behavioral accumulation.
global _proxy_master_state: table[addr] of MasterState &create_expire=5min;

event Modbus::_flush_worker_master_states()
	{
	if ( ! ClusterRelay::is_worker() )
		return;
	for ( master in _local_master_states )
		{
		local st = _local_master_states[master];
		local fws = master in _local_write_slave ? _local_write_slave[master] :
		    0.0.0.0;
		ClusterRelay::publish_to_proxy(master, Cluster::make_event(
		    Modbus::master_state_batch, master, st$slaves_contacted,
		    st$unit_ids_used, st$write_count, fws));
		}
	clear_table(_local_master_states);
	clear_table(_local_write_slave);
	# Note: on worker shutdown, any state pending in the cleared tables is lost
	# (up to master_state_flush_interval of data).  For hourly summaries this
	# is negligible; the tradeoff is accepted in exchange for reduced Broker load.
	schedule modbus_detect::master_state_flush_interval {
	    Modbus::_flush_worker_master_states() };
	}

event Modbus::_flush_proxy_master_states()
	{
	if ( ! ClusterRelay::is_proxy() )
		return;
	for ( master in _proxy_master_state )
		{
		local st = _proxy_master_state[master];
		# sample_slave: not tracked at proxy — pass 0.0.0.0
		ClusterRelay::publish_to_manager(Cluster::make_event(
		    Modbus::master_state_batch, master, st$slaves_contacted,
		    st$unit_ids_used, st$write_count, 0.0.0.0));
		}
	clear_table(_proxy_master_state);
	schedule modbus_detect::master_state_flush_interval {
	    Modbus::_flush_proxy_master_states() };
	}

event zeek_init() &priority=1
	{
	if ( ClusterRelay::is_worker() )
		schedule modbus_detect::master_state_flush_interval {
		    Modbus::_flush_worker_master_states() };
	if ( ClusterRelay::is_proxy() )
		schedule modbus_detect::master_state_flush_interval {
		    Modbus::_flush_proxy_master_states() };
	}

event Modbus::master_state_update(master: addr, slave: addr, unit: count,
    is_write: bool)
	{
	# Only the manager accumulates state.
	if ( Cluster::local_node_type() != Cluster::MANAGER )
		return;

	# DET-017: track first observation time per master.
	if ( master !in _master_first_seen )
		_master_first_seen[master] = network_time();

	if ( master !in _master_states )
		_master_states[master] = MasterState();
	local st = _master_states[master];
	add st$slaves_contacted[slave];
	add st$unit_ids_used[unit];
	if ( is_write )
		{
		++st$write_count;

		# DET-017 AuthorizedMasterWriteEscalation — cluster manager path.
		if ( master !in _master_has_written )
			{
			add _master_has_written[master];
			if ( ( master in modbus_detect::authorized_masters || master in
			    modbus_detect::_authorized_masters_tbl )
			    && master in _master_first_seen
			    && network_time() - _master_first_seen[master] >= modbus_detect::write_escalation_grace )
				{
				NOTICE([$note=Modbus::AuthorizedMasterWriteEscalation, $msg=fmt("authorized master %s issued first write to slave %s — was read-only for %s",
				    master, slave,
				    modbus_detect::write_escalation_grace),
				    $src=master, $dst=slave, $identifier=cat(
				    master), $suppress_for=1hr]);
				}
			}
		}
	}

event Modbus::master_seen(master: addr, slave: addr)
	{
	# Proxy: dedup and forward to manager.
	if ( ClusterRelay::is_proxy() )
		{
		if ( master in _proxy_seen_masters )
			return;
		add _proxy_seen_masters[master];
		ClusterRelay::publish_to_manager(Cluster::make_event(Modbus::master_seen,
		    master, slave));
		return;
		}

	# Only the manager fires the notice.
	if ( ! ClusterRelay::is_manager() )
		return;

	if ( master in _seen_masters )
		return;
	if ( master in modbus_detect::authorized_masters
	    || master in modbus_detect::_authorized_masters_tbl )
		{
		add _seen_masters[master];
		return;
		}

	add _seen_masters[master];
	NOTICE([$note=Modbus::RogueMaster, $msg=fmt(
	    "%s sent first Modbus traffic — not in authorized_masters",
	    master), $src=master, $dst=slave, $identifier=cat(master),
	    $suppress_for=1hr]);
	}

event Modbus::master_state_batch(master: addr, slaves: set[addr], units: set[
    count], write_count: count, sample_slave: addr)
	{
	# Proxy: accumulate merged delta, forward on flush timer.
	if ( ClusterRelay::is_proxy() )
		{
		if ( master !in _proxy_master_state )
			_proxy_master_state[master] = MasterState();
		local pst = _proxy_master_state[master];
		for ( s in slaves )
			add pst$slaves_contacted[s];
		for ( u in units )
			add pst$unit_ids_used[u];
		pst$write_count += write_count;
		return;
		}

	# Only the manager accumulates authoritative state.
	if ( ! ClusterRelay::is_manager() )
		return;

	# DET-017: track first observation time per master.
	if ( master !in _master_first_seen )
		_master_first_seen[master] = network_time();

	if ( master !in _master_states )
		_master_states[master] = MasterState();
	local st = _master_states[master];
	for ( s in slaves )
		add st$slaves_contacted[s];
	for ( u in units )
		add st$unit_ids_used[u];

	if ( write_count > 0 )
		{
		st$write_count += write_count;

		# DET-017 AuthorizedMasterWriteEscalation — cluster manager path.
		if ( master !in _master_has_written )
			{
			add _master_has_written[master];
			if ( ( master in modbus_detect::authorized_masters || master in
			    modbus_detect::_authorized_masters_tbl )
			    && master in _master_first_seen
			    && network_time() - _master_first_seen[master] >= modbus_detect::write_escalation_grace )
				{
				NOTICE([$note=Modbus::AuthorizedMasterWriteEscalation, $msg=fmt("authorized master %s issued first write to slave %s — was read-only for %s",
				    master, sample_slave,
				    modbus_detect::write_escalation_grace),
				    $src=master, $dst=sample_slave,
				    $identifier=cat(master), $suppress_for=1hr]);
				}
			}
		}
	}

@endif

# ---------------------------------------------------------------------------
# Modbus PDU event: observe every request
# ---------------------------------------------------------------------------

event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool)
	{
	if ( ! is_orig )
		return;

	local master = c$id$orig_h;
	local slave = c$id$resp_h;

	# Accumulate per-master state for the hourly summary.
@if ( Cluster::is_enabled() )
	# In cluster mode: accumulate locally; flushed to proxy every flush_interval.
	if ( master !in _local_master_states )
		_local_master_states[master] = MasterState();
	add _local_master_states[master]$slaves_contacted[slave];
	add _local_master_states[master]$unit_ids_used[headers$uid];
@else
	# DET-017: track first observation time per master.
	if ( master !in _master_first_seen )
		_master_first_seen[master] = network_time();

	if ( master !in _master_states )
		_master_states[master] = MasterState();
	local st = _master_states[master];
	add st$slaves_contacted[slave];
	add st$unit_ids_used[headers$uid];
@endif

	# Touch the SumStats stream to ensure epoch_result fires for this master.
	SumStats::observe("modbus.masters.summary", SumStats::Key($str=cat(master)),
	    SumStats::Observation($num=1));

	# MultiSlaveSweep: observe distinct slave IPs per master.
	SumStats::observe("modbus.masters.sweep", SumStats::Key($str=cat(master)),
	    SumStats::Observation($str=cat(slave)));

	# DET-009 RogueMaster
@if ( Cluster::is_enabled() )
	# In cluster mode: relay to proxy via Broker — once per master per worker.
	if ( master !in _local_seen_masters )
		{
		add _local_seen_masters[master];
		ClusterRelay::publish_to_proxy(master, Cluster::make_event(
		    Modbus::master_seen, master, slave));
		}
@else
	# Standalone mode: check locally.
	# RogueMaster fires for any first-seen master not in authorized_masters.
	# Unlike UnauthorizedWrite, this fires even when authorized_masters is
	# empty — it builds the master inventory from day 1.
	if ( master !in _seen_masters )
		{
		if ( master !in modbus_detect::authorized_masters
		    && master !in modbus_detect::_authorized_masters_tbl )
			{
			NOTICE([$note=Modbus::RogueMaster, $msg=fmt("%s sent first Modbus traffic — not in authorized_masters",
			    master), $conn=c, $identifier=cat(master),
			    $suppress_for=1hr]);
			}
		add _seen_masters[master];
		}
@endif
	}

event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool)
    &priority=-1
	{
	if ( ! is_orig )
		return;
	if ( ! c?$modbus || ! c$modbus?$func )
		return;

	local master = c$id$orig_h;
	local func = c$modbus$func;
	if ( func !in modbus_detect::write_function_codes )
		return;

@if ( Cluster::is_enabled() )
	# Accumulate write locally; flushed to proxy every flush_interval.
	if ( master !in _local_master_states )
		_local_master_states[master] = MasterState();
	++_local_master_states[master]$write_count;
	# Record first write target for DET-017 NOTICE context.
	if ( master !in _local_write_slave )
		_local_write_slave[master] = c$id$resp_h;
@else
	if ( master !in _master_states )
		return;
	++_master_states[master]$write_count;

	# DET-017 AuthorizedMasterWriteEscalation — standalone path.
	if ( master !in _master_has_written )
		{
		add _master_has_written[master];
		if ( ( master in modbus_detect::authorized_masters || master in
		    modbus_detect::_authorized_masters_tbl )
		    && master in _master_first_seen
		    && network_time() - _master_first_seen[master] >= modbus_detect::write_escalation_grace )
			{
			NOTICE([$note=Modbus::AuthorizedMasterWriteEscalation, $msg=fmt("authorized master %s issued first write to slave %s — was read-only for %s",
			    master, c$id$resp_h,
			    modbus_detect::write_escalation_grace), $conn=c,
			    $identifier=cat(master), $suppress_for=1hr]);
			}
		}
@endif
	}
