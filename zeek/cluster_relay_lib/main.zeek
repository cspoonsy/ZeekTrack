##! ClusterRelay — Three-tier cluster aggregation plumbing
##!
##! PURPOSE
##! Provides routing, node-role detection, and flush interval for the
##! worker → proxy → manager aggregation pattern used by all OT detection
##! suites.  Each detection script owns its own types, events, accumulation,
##! merge logic, and manager actions.  This module handles only the plumbing
##! that is identical across all scripts.
##!
##! THREE FAMILIES
##! Detection relay events fall into three families.  Each family uses a
##! different proxy strategy:
##!
##!   1. Seen-set (stateful proxy — dedup)
##!      Worker observes first-seen key → publish_to_proxy(key, ev).
##!      Proxy checks proxy-local seen-set; forwards to manager only if new.
##!      Manager checks authoritative set; fires notice if new.
##!      No batching — immediate relay.
##!
##!   2. Multi-stage temporal correlation (stateless proxy — batch & forward)
##!      Worker accumulates events in local buffer, flushes on timer via
##!      publish_to_proxy(src, ev).  Proxy accumulates in batch buffer,
##!      flushes on timer via publish_to_manager(ev).  Manager stores in
##!      correlation table (&create_expire) and fires notice on match.
##!
##!   3. Behavioral accumulation (stateful proxy — partial merge)
##!      Worker accumulates deltas (counts, sets), flushes on timer via
##!      publish_to_proxy(src, ev).  Proxy merges deltas from multiple
##!      workers (sum counts, union sets), flushes merged delta to manager.
##!      Manager applies to authoritative state.
##!
##! USAGE — SEEN-SET FAMILY
##!   # Worker side (in the protocol event handler):
##!   if ( ClusterRelay::is_standalone() )
##!       { handle_locally(...); return; }
##!   if ( key !in _local_seen )
##!       {
##!       add _local_seen[key];
##!       ClusterRelay::publish_to_proxy(key,
##!           Cluster::make_event(my_seen_relay, key, ...));
##!       }
##!
##!   # Proxy side:
##!   event my_seen_relay(key: addr, ...)
##!       {
##!       if ( ! ClusterRelay::is_proxy() ) return;
##!       if ( key in _proxy_seen ) return;
##!       add _proxy_seen[key];
##!       ClusterRelay::publish_to_manager(
##!           Cluster::make_event(my_manager_relay, key, ...));
##!       }
##!
##!   # Manager side (unchanged from direct-to-manager pattern):
##!   event my_manager_relay(key: addr, ...)
##!       { if ( ! ClusterRelay::is_manager() ) return; ... }
##!
##! USAGE — MULTI-STAGE CORRELATION FAMILY
##!   # Worker side:
##!   event ProtocolEvent(c: connection, ...)
##!       {
##!       if ( ClusterRelay::is_standalone() )
##!           { handle_locally(...); return; }
##!       _worker_buffer[key] = val;
##!       }
##!   event _flush_worker()
##!       {
##!       for ( [k] in _worker_buffer )
##!           ClusterRelay::publish_to_proxy(k,
##!               Cluster::make_event(my_relay, k, _worker_buffer[k]));
##!       clear_table(_worker_buffer);
##!       schedule ClusterRelay::flush_interval { _flush_worker() };
##!       }
##!
##!   # Proxy side (stateless — batch and forward):
##!   event my_relay(k: addr, val: MyType)
##!       { if ( ! ClusterRelay::is_proxy() ) return;
##!         _proxy_buffer[k] = val; }
##!   event _flush_proxy()
##!       {
##!       for ( [k] in _proxy_buffer )
##!           ClusterRelay::publish_to_manager(
##!               Cluster::make_event(my_mgr_relay, k, _proxy_buffer[k]));
##!       clear_table(_proxy_buffer);
##!       schedule ClusterRelay::flush_interval { _flush_proxy() };
##!       }
##!
##! USAGE — BEHAVIORAL ACCUMULATION FAMILY
##!   Same as multi-stage but proxy merges deltas before forwarding:
##!   event my_relay(k: addr, delta: MyDelta)
##!       { if ( ! ClusterRelay::is_proxy() ) return;
##!         _proxy_state[k]$count += delta$count;
##!         _proxy_state[k]$items |= delta$items; }
##!
##! REFERENCE
##! Full documentation: c/ics/planning.md Section 7f
##! Design spec: c/ics/cluster_design.md

@load base/frameworks/cluster

module ClusterRelay;

export {
	## Default flush interval for worker and proxy batching.
	## Individual scripts can override per-timer if needed.
	option flush_interval: interval = 5sec;

	## Whether proxies are available in this cluster.
	## Set at zeek_init; does not change at runtime.
	global has_proxies: bool = F;

	## Route an event to the proxy that owns this key via HRW.
	## Falls back to manager_topic when no proxies exist.
	## In standalone mode, does nothing (caller handles local path).
	global publish_to_proxy: function(key: addr, ev: any);

	## Route an event directly to the manager.
	## Called by proxies after merging deltas, or by publish_to_proxy
	## as a fallback when no proxies exist.  Not intended to be called
	## directly by detection scripts — use publish_to_proxy instead.
	## Guards against standalone mode but is never reached in practice
	## when callers use the is_standalone() guard.
	global publish_to_manager: function(ev: any);

	## Node role helpers — standalone returns F for all cluster roles.
	global is_worker: function(): bool;
	global is_proxy: function(): bool;
	global is_manager: function(): bool;
	global is_standalone: function(): bool;
}

function publish_to_proxy(key: addr, ev: any)
	{
	if ( ! Cluster::is_enabled() )
		return;
	if ( has_proxies )
		# NOTE: If proxy nodes are configured but not yet connected,
		# Cluster::publish_hrw silently drops the event.
		# This is inherent to Broker's async connection model.
		Cluster::publish_hrw(Cluster::proxy_pool, key, ev);
	else
		Cluster::publish(Cluster::manager_topic, ev);
	}

function publish_to_manager(ev: any)
	{
	if ( ! Cluster::is_enabled() )
		return;
	Cluster::publish(Cluster::manager_topic, ev);
	}

function is_worker(): bool
	{
	return Cluster::is_enabled() && Cluster::local_node_type() == Cluster::WORKER;
	}

function is_proxy(): bool
	{
	return Cluster::is_enabled() && Cluster::local_node_type() == Cluster::PROXY;
	}

function is_manager(): bool
	{
	return Cluster::is_enabled()
	    && Cluster::local_node_type() == Cluster::MANAGER;
	}

function is_standalone(): bool
	{
	return ! Cluster::is_enabled();
	}

event zeek_init() &priority=10
	{
	if ( ! Cluster::is_enabled() )
		return;
	for ( name, n in Cluster::nodes )
		{
		if ( n$node_type == Cluster::PROXY )
			{
			has_proxies = T;
			return;
			}
		}
	}
