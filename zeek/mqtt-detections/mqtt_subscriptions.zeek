# scripts/mqtt_subscriptions.zeek — Detections on MQTT SUBSCRIBE events.
#
# Zero-config notices:
#   MQTT::WildcardSubscription — DET-004: "#" in any subscribed topic
#   MQTT::SystemTopicAccess   — DET-006: topic starting with "$SYS/"

@load base/frameworks/notice
@load base/protocols/mqtt
@load ./mqtt_detect

module MQTT;

event mqtt_subscribe(c: connection, msg_id: count, topics: string_vec,
    requested_qos: index_vec)
	{
	for ( i in topics )
		{
		local t = topics[i];

		# DET-004: Wildcard subscription (full broker enumeration).
		if ( "#" in t && c$id$orig_h !in mqtt_detect::wildcard_subscribe_allowed )
			{
			NOTICE([$note=MQTT::WildcardSubscription, $msg=fmt("%s: SUBSCRIBE to wildcard topic \"%s\" — full broker enumeration",
			    c$id$orig_h, t), $conn=c, $identifier=cat(
			    c$id$orig_h), $suppress_for=1hr]);
			}

		# DET-006: $SYS/ broker internal topics.
		if ( /^\$SYS\// in t
		    && c$id$orig_h !in mqtt_detect::sys_topic_subscribe_allowed )
			{
			NOTICE([$note=MQTT::SystemTopicAccess, $msg=fmt(
			    "%s: SUBSCRIBE to broker internal topic \"%s\"",
			    c$id$orig_h, t), $conn=c, $identifier=cat(
			    c$id$orig_h, t), $suppress_for=1hr]);
			}
		}
	}
