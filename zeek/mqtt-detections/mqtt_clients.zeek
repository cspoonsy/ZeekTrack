@load base/protocols/mqtt
@load base/frameworks/notice
@load base/frameworks/sumstats
@load ./mqtt_detect
@load cluster_relay_lib

module MQTT;

# ---------------------------------------------------------------------------
# DET-003 ConnectFailureFlood — SumStats callbacks
# ---------------------------------------------------------------------------

global _connfail_threshold_val: function(key: SumStats::Key,
    result: SumStats::Result): double;
global _connfail_threshold_crossed: function(key: SumStats::Key,
    result: SumStats::Result);

# ---------------------------------------------------------------------------
# DET-005 TopicEnumeration — SumStats callbacks
# ---------------------------------------------------------------------------

global _topenum_threshold_val: function(key: SumStats::Key,
    result: SumStats::Result): double;
global _topenum_threshold_crossed: function(key: SumStats::Key,
    result: SumStats::Result);

# ---------------------------------------------------------------------------
# DET-008 RogueClient — seen-set (manager-authoritative in cluster)
# ---------------------------------------------------------------------------

global _seen_clients: set[addr] &create_expire=1day;

# ---------------------------------------------------------------------------
# DET-011 SubscriberPublishEscalation — per-client behavioral state
# Manager-authoritative in cluster; populated directly in standalone.
# ---------------------------------------------------------------------------

global _client_first_connect: table[addr] of time &create_expire=7day;
global _client_has_subscribed: set[addr] &create_expire=7day;
global _client_has_published: set[addr] &create_expire=7day;

event zeek_init() &priority=4
	{
	_connfail_threshold_val = function(key: SumStats::Key,
	    result: SumStats::Result): double
		{
		if ( "mqtt.connfail.flood" !in result )
			return 0.0;
		return result["mqtt.connfail.flood"]$sum;
		};

	_connfail_threshold_crossed = function(key: SumStats::Key,
	    result: SumStats::Result)
		{
		if ( "mqtt.connfail.flood" !in result )
			return;
		local src = to_addr(key$str);
		local cnt = double_to_count(result["mqtt.connfail.flood"]$sum);
		NOTICE([$note=MQTT::ConnectFailureFlood, $msg=fmt(
		    "%s produced %d CONNACK failures in %s (threshold: %d)",
		    src, cnt, mqtt_detect::connect_failure_interval,
		    mqtt_detect::connect_failure_threshold), $src=src,
		    $identifier=key$str,
		    $suppress_for=mqtt_detect::connect_failure_interval]);
		};

	_topenum_threshold_val = function(key: SumStats::Key, result: SumStats::Result)
	    : double
		{
		if ( "mqtt.topic.enum" !in result )
			return 0.0;
		return result["mqtt.topic.enum"]$unique + 0.0;
		};

	_topenum_threshold_crossed = function(key: SumStats::Key,
	    result: SumStats::Result)
		{
		if ( "mqtt.topic.enum" !in result )
			return;
		local src = to_addr(key$str);
		local cnt = result["mqtt.topic.enum"]$unique;
		NOTICE([$note=MQTT::TopicEnumeration, $msg=fmt(
		    "%s subscribed to %d distinct topics in %s (threshold: %d)",
		    src, cnt, mqtt_detect::topic_enum_interval,
		    mqtt_detect::topic_enum_threshold), $src=src,
		    $identifier=key$str,
		    $suppress_for=mqtt_detect::topic_enum_interval]);
		};
	}

event zeek_init() &priority=3
	{
	# --- DET-003 ConnectFailureFlood ----------------------------------------
	SumStats::create([$name="mqtt.connfail.flood",
	    $epoch=mqtt_detect::connect_failure_interval, $reducers=set(
	    SumStats::Reducer($stream="mqtt.connfail.flood", $apply=set(
	    SumStats::SUM))), $threshold_val=_connfail_threshold_val,
	    $threshold=mqtt_detect::connect_failure_threshold + 0.0,
	    $threshold_crossed=_connfail_threshold_crossed]);

	# --- DET-005 TopicEnumeration -------------------------------------------
	SumStats::create([$name="mqtt.topic.enum",
	    $epoch=mqtt_detect::topic_enum_interval, $reducers=set(
	    SumStats::Reducer($stream="mqtt.topic.enum", $apply=set(
	    SumStats::UNIQUE))), $threshold_val=_topenum_threshold_val,
	    $threshold=mqtt_detect::topic_enum_threshold + 0.0,
	    $threshold_crossed=_topenum_threshold_crossed]);
	}

# ---------------------------------------------------------------------------
# Cluster: three-tier relay for DET-008 RogueClient seen-set and
# DET-011 SubscriberPublishEscalation behavioral accumulation
# ---------------------------------------------------------------------------

export {
	global client_seen: event(client: addr, broker: addr);
	global client_state_update: event(client: addr, is_subscribe: bool,
	    is_publish: bool, ts: time);

	## Delta record for DET-011 behavioral accumulation.
	type ClientStateDelta: record {
		has_subscribed: bool &default=F;
		has_published: bool &default=F;
	};
}

@if ( Cluster::is_enabled() )

# Worker-local dedup for DET-008 relay — only first connect relayed per worker.
global _local_seen_clients: set[addr] &create_expire=1hr;

# Worker-local dedup for DET-011 relay — only first subscribe/publish relayed.
global _local_subscribed: set[addr] &create_expire=1hr;
global _local_published: set[addr] &create_expire=1hr;

# Worker-local state buffer for DET-011 behavioral accumulation.
global _worker_state_buffer: table[addr] of ClientStateDelta &create_expire=5min;

# Proxy-local seen-set for DET-008 dedup.
global _proxy_seen_clients: set[addr] &create_expire=1hr;

# Proxy-local state buffer for DET-011 behavioral accumulation.
global _proxy_state_buffer: table[addr] of ClientStateDelta &create_expire=5min;

# ---------------------------------------------------------------------------
# Flush events for DET-011 behavioral accumulation
# ---------------------------------------------------------------------------

global _clients_flush_worker: event();
global _clients_flush_proxy: event();

event _clients_flush_worker()
	{
	if ( ClusterRelay::is_worker() )
		{
		for ( client in _worker_state_buffer )
			{
			local d = _worker_state_buffer[client];
			ClusterRelay::publish_to_proxy(client, Cluster::make_event(
			    MQTT::client_state_update, client, d$has_subscribed,
			    d$has_published, network_time()));
			}
		clear_table(_worker_state_buffer);
		}
	schedule ClusterRelay::flush_interval { _clients_flush_worker() };
	}

event _clients_flush_proxy()
	{
	if ( ClusterRelay::is_proxy() )
		{
		for ( client in _proxy_state_buffer )
			{
			local d = _proxy_state_buffer[client];
			ClusterRelay::publish_to_manager(Cluster::make_event(
			    MQTT::client_state_update, client, d$has_subscribed,
			    d$has_published, network_time()));
			}
		clear_table(_proxy_state_buffer);
		}
	schedule ClusterRelay::flush_interval { _clients_flush_proxy() };
	}

event zeek_init() &priority=2
	{
	if ( ClusterRelay::is_worker() )
		schedule ClusterRelay::flush_interval { _clients_flush_worker() };
	if ( ClusterRelay::is_proxy() )
		schedule ClusterRelay::flush_interval { _clients_flush_proxy() };
	}

# ---------------------------------------------------------------------------
# DET-008 RogueClient — client_seen handler (proxy + manager)
# ---------------------------------------------------------------------------

event MQTT::client_seen(client: addr, broker: addr)
	{
	if ( ClusterRelay::is_proxy() )
		{
		if ( client in _proxy_seen_clients )
			return;
		add _proxy_seen_clients[client];
		ClusterRelay::publish_to_manager(Cluster::make_event(MQTT::client_seen,
		    client, broker));
		return;
		}

	if ( ! ClusterRelay::is_manager() )
		return;

	if ( client in _seen_clients )
		return;
	add _seen_clients[client];

	if ( |mqtt_detect::known_clients| > 0
	    && client in mqtt_detect::known_clients )
		return;

	NOTICE([$note=MQTT::RogueClient, $msg=fmt(
	    "%s sent first MQTT CONNECT — not in known_clients", client),
	    $src=client, $dst=broker, $identifier=cat(client), $suppress_for=1hr]);
	}

# ---------------------------------------------------------------------------
# DET-011 SubscriberPublishEscalation — client_state_update handler (proxy + manager)
# ---------------------------------------------------------------------------

event MQTT::client_state_update(client: addr, is_subscribe: bool,
    is_publish: bool, ts: time)
	{
	if ( ClusterRelay::is_proxy() )
		{
		if ( client !in _proxy_state_buffer )
			_proxy_state_buffer[client] = ClientStateDelta();
		if ( is_subscribe )
			_proxy_state_buffer[client]$has_subscribed = T;
		if ( is_publish )
			_proxy_state_buffer[client]$has_published = T;
		return;
		}

	if ( ! ClusterRelay::is_manager() )
		return;

	if ( client !in _client_first_connect )
		_client_first_connect[client] = ts;

	if ( is_subscribe )
		add _client_has_subscribed[client];

	if ( is_publish && client !in _client_has_published )
		{
		add _client_has_published[client];

		if ( client in _client_has_subscribed
		    && client in _client_first_connect
		    && network_time() - _client_first_connect[client] >= mqtt_detect::subscriber_escalation_grace )
			{
			NOTICE([$note=MQTT::SubscriberPublishEscalation, $msg=fmt("%s issued first PUBLISH after %s as subscribe-only client",
			    client, network_time() -
			    _client_first_connect[client]), $src=client,
			    $identifier=cat(client), $suppress_for=1hr]);
			}
		}
	}

@endif

# ---------------------------------------------------------------------------
# CONNACK event handler — DET-003
# ---------------------------------------------------------------------------

event mqtt_connack(c: connection, msg: MQTT::ConnectAckMsg)
	{
	if ( msg$return_code == 0 )
		return;

	SumStats::observe("mqtt.connfail.flood", SumStats::Key($str=cat(c$id$orig_h)),
	    SumStats::Observation($num=1));
	}

# ---------------------------------------------------------------------------
# SUBSCRIBE event handler — DET-005
# ---------------------------------------------------------------------------

event mqtt_subscribe(c: connection, msg_id: count, topics: string_vec,
    requested_qos: index_vec)
	{
	for ( i in topics )
		{
		SumStats::observe("mqtt.topic.enum", SumStats::Key($str=cat(c$id$orig_h)),
		    SumStats::Observation($str=topics[i]));
		}
	}

# ---------------------------------------------------------------------------
# CONNECT event handler — DET-008
# ---------------------------------------------------------------------------

event mqtt_connect(c: connection, msg: MQTT::ConnectMsg)
	{
	local client = c$id$orig_h;
	local broker = c$id$resp_h;

@if ( Cluster::is_enabled() )
	if ( ClusterRelay::is_worker() )
		{
		if ( client !in _local_seen_clients )
			{
			add _local_seen_clients[client];
			ClusterRelay::publish_to_proxy(client, Cluster::make_event(MQTT::client_seen,
			    client, broker));
			}
		}
@else
	if ( client in _seen_clients )
		return;
	add _seen_clients[client];

	if ( |mqtt_detect::known_clients| > 0
	    && client in mqtt_detect::known_clients )
		return;

	NOTICE([$note=MQTT::RogueClient, $msg=fmt(
	    "%s sent first MQTT CONNECT — not in known_clients", client),
	    $conn=c, $identifier=cat(client), $suppress_for=1hr]);
@endif
	}

# ---------------------------------------------------------------------------
# PUBLISH event handler — DET-001
# ---------------------------------------------------------------------------

event mqtt_publish(c: connection, is_orig: bool, msg_id: count,
    msg: MQTT::PublishMsg)
	{
	if ( ! is_orig )
		return;

	# DET-001 UnauthorizedPublish — suppressed unless authorized_publishers is configured.
	if ( |mqtt_detect::authorized_publishers| == 0 )
		return;
	if ( ! match_pattern(msg$topic,
	    mqtt_detect::sensitive_topic_patterns)$matched )
		return;

	local src = c$id$orig_h;
	if ( src in mqtt_detect::authorized_publishers
	    && match_pattern(msg$topic, mqtt_detect::authorized_publishers[src])$matched )
		return;

	NOTICE([$note=MQTT::UnauthorizedPublish, $msg=fmt("%s PUBLISH to sensitive topic '%s' — source not in authorized_publishers",
	    src, msg$topic), $conn=c, $identifier=cat(src, msg$topic),
	    $suppress_for=1hr]);
	}

# ---------------------------------------------------------------------------
# DET-011 SubscriberPublishEscalation — priority=-5 handlers
# ---------------------------------------------------------------------------

event mqtt_connect(c: connection, msg: MQTT::ConnectMsg) &priority=-5
	{
	local client = c$id$orig_h;

@if ( Cluster::is_enabled() )
	if ( ClusterRelay::is_worker() )
		{
		if ( client !in _worker_state_buffer )
			_worker_state_buffer[client] = ClientStateDelta();
		# Record first-connect time via a state_update with no flags set
		# (manager uses ts from first such message).
		}
@else
	if ( client !in _client_first_connect )
		_client_first_connect[client] = network_time();
@endif
	}

event mqtt_subscribe(c: connection, msg_id: count, topics: string_vec,
    requested_qos: index_vec) &priority=-5
	{
	local client = c$id$orig_h;

@if ( Cluster::is_enabled() )
	if ( ClusterRelay::is_worker() )
		{
		if ( client in _local_subscribed )
			return;
		add _local_subscribed[client];
		if ( client !in _worker_state_buffer )
			_worker_state_buffer[client] = ClientStateDelta();
		_worker_state_buffer[client]$has_subscribed = T;
		}
@else
	add _client_has_subscribed[client];
@endif
	}

event mqtt_publish(c: connection, is_orig: bool, msg_id: count,
    msg: MQTT::PublishMsg) &priority=-5
	{
	if ( ! is_orig )
		return;

	local client = c$id$orig_h;

@if ( Cluster::is_enabled() )
	if ( ClusterRelay::is_worker() )
		{
		if ( client in _local_published )
			return;
		add _local_published[client];
		if ( client !in _worker_state_buffer )
			_worker_state_buffer[client] = ClientStateDelta();
		_worker_state_buffer[client]$has_published = T;
		}
@else
	if ( client in _client_has_published )
		return;
	add _client_has_published[client];

	if ( client in _client_has_subscribed
	    && client in _client_first_connect
	    && network_time() - _client_first_connect[client] >= mqtt_detect::subscriber_escalation_grace )
		{
		NOTICE([$note=MQTT::SubscriberPublishEscalation, $msg=fmt(
		    "%s issued first PUBLISH after %s as subscribe-only client",
		    client, network_time() - _client_first_connect[client]),
		    $conn=c, $identifier=cat(client), $suppress_for=1hr]);
		}
@endif
	}
