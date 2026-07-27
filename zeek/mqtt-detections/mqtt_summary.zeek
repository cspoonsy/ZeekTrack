# scripts/mqtt_summary.zeek — Hourly per-client aggregate of MQTT activity.
#
# Produces mqtt_summary.log: one row per source IP per SumStats epoch.
# In a busy IIoT environment, mqtt_publish.log can generate millions of rows
# per day from a handful of sensors publishing at 1 Hz. A 100-sensor site
# publishing at 1 Hz produces ~8.6M rows/day; this log produces ~2400 rows/day
# (one per sensor per hour) — a >99% volume reduction for trend analysis.
#
# SumStats is cluster-aware; all count fields are accurate in clustered deployments.

@load base/frameworks/notice
@load base/frameworks/sumstats
@load base/protocols/mqtt
@load ./mqtt_detect

module MQTT;

export {
	redef enum Log::ID += { MQTT::LOG_SUMMARY };

	type SummaryInfo: record {
		## Epoch boundary timestamp.
		ts: time &log;
		## MQTT client source IP.
		client: addr &log;
		## Total PUBLISH packets from this client this epoch.
		publish_count: count &log;
		## Total SUBSCRIBE packets from this client this epoch.
		subscribe_count: count &log;
		## Number of distinct topics this client published to this epoch.
		distinct_topics: count &log;
		## Sum of payload_len across all publishes.
		bytes_published: count &log;
	};

	global log_mqtt_summary: event(rec: SummaryInfo);
}

# ---------------------------------------------------------------------------
# Log stream
# ---------------------------------------------------------------------------

event zeek_init() &priority=5
	{
	Log::create_stream(MQTT::LOG_SUMMARY, [$columns=SummaryInfo,
	    $ev=log_mqtt_summary, $path="mqtt_summary"]);
	}

# ---------------------------------------------------------------------------
# Named callback function for SumStats
# ---------------------------------------------------------------------------

function _summary_epoch_result(ts: time, key: SumStats::Key,
    result: SumStats::Result)
	{
	local client = to_addr(key$str);

	local pub_cnt = "mqtt.summary.publish" in result ? double_to_count(
	    result["mqtt.summary.publish"]$sum) : 0;
	local sub_cnt = "mqtt.summary.subscribe" in result ? double_to_count(
	    result["mqtt.summary.subscribe"]$sum) : 0;
	local dist_topics = "mqtt.summary.topics" in result ?
	    |result["mqtt.summary.topics"]$unique| : 0;
	local pub_bytes = "mqtt.summary.bytes" in result ? double_to_count(
	    result["mqtt.summary.bytes"]$sum) : 0;

	local rec: SummaryInfo = [$ts=ts, $client=client, $publish_count=pub_cnt,
	    $subscribe_count=sub_cnt, $distinct_topics=dist_topics,
	    $bytes_published=pub_bytes];
	Log::write(LOG_SUMMARY, rec);
	}

# ---------------------------------------------------------------------------
# SumStats setup
# ---------------------------------------------------------------------------

event zeek_init() &priority=3
	{
	SumStats::create([$name="mqtt.summary", $epoch=mqtt_detect::summary_epoch,
	    $reducers=set(SumStats::Reducer($stream="mqtt.summary.publish",
	    $apply=set(SumStats::SUM)), SumStats::Reducer(
	    $stream="mqtt.summary.subscribe", $apply=set(SumStats::SUM)),
	    SumStats::Reducer($stream="mqtt.summary.topics", $apply=set(
	    SumStats::UNIQUE)), SumStats::Reducer($stream="mqtt.summary.bytes",
	    $apply=set(SumStats::SUM))), $epoch_result=_summary_epoch_result]);
	}

# ---------------------------------------------------------------------------
# Event handlers: observe every PUBLISH and SUBSCRIBE from originator
# ---------------------------------------------------------------------------

event mqtt_publish(c: connection, is_orig: bool, msg_id: count,
    msg: MQTT::PublishMsg)
	{
	if ( ! is_orig )
		return;

	local key = SumStats::Key($str=cat(c$id$orig_h));
	SumStats::observe("mqtt.summary.publish", key, SumStats::Observation($num=1));
	SumStats::observe("mqtt.summary.topics", key, SumStats::Observation(
	    $str=msg$topic));
	SumStats::observe("mqtt.summary.bytes", key, SumStats::Observation(
	    $num=msg$payload_len));
	}

event mqtt_subscribe(c: connection, msg_id: count, topics: string_vec,
    requested_qos: index_vec)
	{
	# mqtt_subscribe only fires on the originator (client→broker) by Zeek's
	# MQTT analyzer design; no is_orig guard needed.
	local key = SumStats::Key($str=cat(c$id$orig_h));
	SumStats::observe("mqtt.summary.subscribe", key, SumStats::Observation(
	    $num=1));
	}
