@load base/protocols/mqtt
@load base/frameworks/notice
@load base/frameworks/sumstats
@load ./mqtt_detect

module MQTT;

# ---------------------------------------------------------------------------
# SumStats threshold callbacks (declared global, assigned in zeek_init)
# ---------------------------------------------------------------------------

global _publish_flood_threshold_val: function(key: SumStats::Key,
    result: SumStats::Result): double;
global _publish_flood_threshold_crossed: function(key: SumStats::Key,
    result: SumStats::Result);

event zeek_init() &priority=4
	{
	_publish_flood_threshold_val = function(key: SumStats::Key,
	    result: SumStats::Result): double
		{
		if ( "mqtt.publish.flood" !in result )
			return 0.0;
		return result["mqtt.publish.flood"]$sum;
		};

	_publish_flood_threshold_crossed = function(key: SumStats::Key,
	    result: SumStats::Result)
		{
		if ( "mqtt.publish.flood" !in result )
			return;
		local src = to_addr(key$str);
		local cnt = double_to_count(result["mqtt.publish.flood"]$sum);
		NOTICE([$note=MQTT::PublishFlood, $msg=fmt(
		    "%s sent %d PUBLISH messages in %s (flood threshold: %d)",
		    src, cnt, mqtt_detect::publish_flood_interval,
		    mqtt_detect::publish_flood_threshold), $src=src,
		    $identifier=key$str,
		    $suppress_for=mqtt_detect::publish_flood_interval]);
		};
	}

event zeek_init() &priority=3
	{
	# --- DET-010 PublishFlood ------------------------------------------------
	SumStats::create([$name="mqtt.publish.flood",
	    $epoch=mqtt_detect::publish_flood_interval, $reducers=set(
	    SumStats::Reducer($stream="mqtt.publish.flood", $apply=set(
	    SumStats::SUM))), $threshold_val=_publish_flood_threshold_val,
	    $threshold=mqtt_detect::publish_flood_threshold + 0.0,
	    $threshold_crossed=_publish_flood_threshold_crossed]);
	}

# ---------------------------------------------------------------------------
# PUBLISH event handler
# ---------------------------------------------------------------------------

event mqtt_publish(c: connection, is_orig: bool, msg_id: count,
    msg: MQTT::PublishMsg)
	{
	if ( ! is_orig )
		return;

	# DET-002 RetainedCommandMessage — retain=T to a sensitive topic
	if ( msg$retain
	    && match_pattern(msg$topic, mqtt_detect::sensitive_topic_patterns)$matched )
		{
		NOTICE([$note=MQTT::RetainedCommandMessage, $msg=fmt("MQTT PUBLISH with retain=T to sensitive topic '%s' — message persists on broker",
		    msg$topic), $conn=c, $identifier=cat(c$id$orig_h,
		    msg$topic), $suppress_for=1hr]);
		}

	# DET-010 PublishFlood — count every client PUBLISH
	SumStats::observe("mqtt.publish.flood", SumStats::Key($str=cat(c$id$orig_h)),
	    SumStats::Observation($num=1));
	}
