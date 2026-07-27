@load base/protocols/mqtt
@load base/frameworks/notice
@load ./mqtt_detect
@load cluster_relay_lib

module MQTT;

# ---------------------------------------------------------------------------
# DET-012 ReconThenPublish — temporal multi-stage detection
#
# Stage 1: wildcard ("#") in mqtt_subscribe → arm recon window
# Stage 2: mqtt_publish to sensitive topic within window → fire notice
#
# Cluster: three-tier proxy aggregation (worker → proxy → manager).
# Standalone: same logic, no relay.
# ---------------------------------------------------------------------------

global _recon_sources: table[addr] of time &create_expire=1hr;

export {
	global recon_observed: event(src: addr, ts: time);
	global sensitive_publish_observed: event(src: addr, topic: string);
}

## Worker-local batch buffer for recon observations.
## Keyed src → timestamp. Flushed every ClusterRelay::flush_interval.
global _worker_recon_buffer: table[addr] of time &create_expire=5min;

## Worker-local batch buffer for sensitive publish observations.
## Keyed src → topic.
global _worker_publish_buffer: table[addr] of string &create_expire=5min;

## Proxy-side batch buffers (stateless — accumulate and forward).
global _proxy_recon_buffer: table[addr] of time &create_expire=5min;
global _proxy_publish_buffer: table[addr] of string &create_expire=5min;

## Worker flush event — self-rescheduling.
global _recon_flush_worker: event();

## Proxy flush event — self-rescheduling.
global _recon_flush_proxy: event();

# ---------------------------------------------------------------------------
# Relay event handlers
# ---------------------------------------------------------------------------

event MQTT::recon_observed(src: addr, ts: time)
	{
	if ( ClusterRelay::is_proxy() )
		{
		_proxy_recon_buffer[src] = ts;
		return;
		}

	if ( ! ClusterRelay::is_manager() )
		return;

	_recon_sources[src] = ts;
	}

event MQTT::sensitive_publish_observed(src: addr, topic: string)
	{
	if ( ClusterRelay::is_proxy() )
		{
		_proxy_publish_buffer[src] = topic;
		return;
		}

	if ( ! ClusterRelay::is_manager() )
		return;

	if ( src !in _recon_sources )
		return;

	if ( network_time() - _recon_sources[src] > mqtt_detect::recon_publish_window )
		{
		delete _recon_sources[src];
		return;
		}

	delete _recon_sources[src];
	NOTICE([$note=MQTT::ReconThenPublish, $msg=fmt("%s published to sensitive topic '%s' within %s of wildcard subscription",
	    src, topic, mqtt_detect::recon_publish_window), $src=src,
	    $identifier=cat(src),
	    $suppress_for=mqtt_detect::recon_publish_window]);
	}

# ---------------------------------------------------------------------------
# Worker flush
# ---------------------------------------------------------------------------

event MQTT::_recon_flush_worker()
	{
	if ( ! ClusterRelay::is_worker() )
		return;

	for ( src in _worker_recon_buffer )
		ClusterRelay::publish_to_proxy(src, Cluster::make_event(recon_observed, src,
		    _worker_recon_buffer[src]));

	for ( src in _worker_publish_buffer )
		ClusterRelay::publish_to_proxy(src, Cluster::make_event(
		    sensitive_publish_observed, src,
		    _worker_publish_buffer[src]));

	_worker_recon_buffer = table();
	_worker_publish_buffer = table();

	schedule ClusterRelay::flush_interval { MQTT::_recon_flush_worker() };
	}

# ---------------------------------------------------------------------------
# Proxy flush
# ---------------------------------------------------------------------------

event MQTT::_recon_flush_proxy()
	{
	if ( ! ClusterRelay::is_proxy() )
		return;

	for ( src in _proxy_recon_buffer )
		ClusterRelay::publish_to_manager(Cluster::make_event(recon_observed, src,
		    _proxy_recon_buffer[src]));

	for ( src in _proxy_publish_buffer )
		ClusterRelay::publish_to_manager(Cluster::make_event(
		    sensitive_publish_observed, src,
		    _proxy_publish_buffer[src]));

	_proxy_recon_buffer = table();
	_proxy_publish_buffer = table();

	schedule ClusterRelay::flush_interval { MQTT::_recon_flush_proxy() };
	}

# ---------------------------------------------------------------------------
# SUBSCRIBE handler — arm recon window on wildcard "#"
# ---------------------------------------------------------------------------

event mqtt_subscribe(c: connection, msg_id: count, topics: string_vec,
    requested_qos: index_vec)
	{
	if ( ! mqtt_detect::enable_recon_then_publish )
		return;

	local src = c$id$orig_h;

	for ( i in topics )
		{
		if ( "#" !in topics[i] )
			next;

		if ( ClusterRelay::is_standalone() )
			{
			_recon_sources[src] = network_time();
			return;
			}

		_worker_recon_buffer[src] = network_time();
		break;
		}
	}

# ---------------------------------------------------------------------------
# PUBLISH handler — check recon window on sensitive topic publish
# ---------------------------------------------------------------------------

event mqtt_publish(c: connection, is_orig: bool, msg_id: count,
    msg: MQTT::PublishMsg)
	{
	if ( ! is_orig )
		return;
	if ( ! mqtt_detect::enable_recon_then_publish )
		return;
	if ( ! match_pattern(msg$topic,
	    mqtt_detect::sensitive_topic_patterns)$matched )
		return;

	local src = c$id$orig_h;

	if ( ClusterRelay::is_standalone() )
		{
		if ( src !in _recon_sources )
			return;

		if ( network_time() - _recon_sources[src] >
		    mqtt_detect::recon_publish_window )
			{
			delete _recon_sources[src];
			return;
			}

		delete _recon_sources[src];
		NOTICE([$note=MQTT::ReconThenPublish, $msg=fmt("%s published to sensitive topic '%s' within %s of wildcard subscription",
		    src, msg$topic, mqtt_detect::recon_publish_window), $conn=c,
		    $identifier=cat(src),
		    $suppress_for=mqtt_detect::recon_publish_window]);
		return;
		}

	_worker_publish_buffer[src] = msg$topic;
	}

# ---------------------------------------------------------------------------
# Startup — schedule flush timers on workers and proxies
# ---------------------------------------------------------------------------

event zeek_init() &priority=1
	{
	if ( ClusterRelay::is_worker() )
		schedule ClusterRelay::flush_interval { MQTT::_recon_flush_worker() };
	if ( ClusterRelay::is_proxy() )
		schedule ClusterRelay::flush_interval { MQTT::_recon_flush_proxy() };
	}
