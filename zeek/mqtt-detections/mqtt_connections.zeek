@load base/protocols/mqtt
@load base/frameworks/notice
@load base/frameworks/sumstats
@load ./mqtt_detect

module MQTT;

# ---------------------------------------------------------------------------
# SumStats threshold callbacks (declared global, assigned in zeek_init)
# ---------------------------------------------------------------------------

global _connection_flood_threshold_val: function(key: SumStats::Key,
    result: SumStats::Result): double;
global _connection_flood_threshold_crossed: function(key: SumStats::Key,
    result: SumStats::Result);

event zeek_init() &priority=4
	{
	_connection_flood_threshold_val = function(key: SumStats::Key,
	    result: SumStats::Result): double
		{
		if ( "mqtt.connection.flood" !in result )
			return 0.0;
		return result["mqtt.connection.flood"]$sum;
		};

	_connection_flood_threshold_crossed = function(key: SumStats::Key,
	    result: SumStats::Result)
		{
		if ( "mqtt.connection.flood" !in result )
			return;
		local src = to_addr(key$str);
		local cnt = double_to_count(result["mqtt.connection.flood"]$sum);
		NOTICE([$note=MQTT::ConnectionFlood, $msg=fmt(
		    "%s sent %d CONNECT messages in %s (flood threshold: %d)",
		    src, cnt, mqtt_detect::connection_flood_interval,
		    mqtt_detect::connection_flood_threshold), $src=src,
		    $identifier=key$str,
		    $suppress_for=mqtt_detect::connection_flood_interval]);
		};
	}

event zeek_init() &priority=3
	{
	# --- DET-013 ConnectionFlood ---------------------------------------------
	SumStats::create([$name="mqtt.connection.flood",
	    $epoch=mqtt_detect::connection_flood_interval, $reducers=set(
	    SumStats::Reducer($stream="mqtt.connection.flood", $apply=set(
	    SumStats::SUM))), $threshold_val=_connection_flood_threshold_val,
	    $threshold=mqtt_detect::connection_flood_threshold + 0.0,
	    $threshold_crossed=_connection_flood_threshold_crossed]);
	}

# ---------------------------------------------------------------------------
# CONNECT event handler
# ---------------------------------------------------------------------------

event mqtt_connect(c: connection, msg: MQTT::ConnectMsg)
	{
	# DET-009 WillMessageAbuse — CONNECT with will_topic matching sensitive_topic_patterns
	if ( msg?$will_topic
	    && match_pattern(msg$will_topic, mqtt_detect::sensitive_topic_patterns)$matched )
		{
		NOTICE([$note=MQTT::WillMessageAbuse, $msg=fmt("MQTT CONNECT with will_topic='%s' matching sensitive topic — weaponized disconnect threat",
		    msg$will_topic), $conn=c, $identifier=cat(c$id$orig_h,
		    msg$will_topic), $suppress_for=1hr]);
		}

	# DET-013 ConnectionFlood — count every CONNECT from this source
	SumStats::observe("mqtt.connection.flood", SumStats::Key($str=cat(
	    c$id$orig_h)), SumStats::Observation($num=1));
	}
