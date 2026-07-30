# scripts/mqtt_detect/__load__.zeek — Shared option constants and notice types
# for the MQTT security detection suite.
#
# All tunable thresholds are declared here as `option` constants so operators
# have one place to redef without editing individual detection scripts:
#
#   redef mqtt_detect::sensitive_topic_patterns = /\/(secret|private)\//;
#   redef mqtt_detect::publish_flood_threshold = 500;
#
# Phase 1 checks (zero-config) fire with default settings.  Phase 2 checks
# require at least one option to be populated (e.g. known_clients,
# authorized_publishers) before they will generate notices.

module mqtt_detect;

export {
	# -------------------------------------------------------------------------
	# Notice types — 13 total (Phases 1–3)
	# -------------------------------------------------------------------------

	redef enum Notice::Type += {
		## DET-002: PUBLISH with retain=T to a topic matching sensitive_topic_patterns.
		MQTT::RetainedCommandMessage,
		## DET-004: SUBSCRIBE containing "#" (multi-level wildcard).
		MQTT::WildcardSubscription,
		## DET-006: SUBSCRIBE to any topic beginning with "$SYS/".
		MQTT::SystemTopicAccess,
		## DET-007: >protocol_violation_threshold conn_weird events on port 1883.
		MQTT::ProtocolViolation,
		## DET-009: CONNECT with will_topic matching sensitive_topic_patterns.
		MQTT::WillMessageAbuse,
		## DET-010: >publish_flood_threshold publishes from same source in interval.
		MQTT::PublishFlood,
		## DET-013: >connection_flood_threshold CONNECTs from same source in interval.
		MQTT::ConnectionFlood,
		## DET-001 (Phase 2): PUBLISH to sensitive topic from unauthorized source.
		MQTT::UnauthorizedPublish,
		## DET-003 (Phase 2): >connect_failure_threshold CONNACK failures from same source.
		MQTT::ConnectFailureFlood,
		## DET-005 (Phase 2): >topic_enum_threshold distinct topics subscribed by one source.
		MQTT::TopicEnumeration,
		## DET-008 (Phase 2): First CONNECT from source not in known_clients.
		MQTT::RogueClient,
		## DET-011 (Phase 3): Subscribe-only client issues first PUBLISH after grace period.
		MQTT::SubscriberPublishEscalation,
		## DET-012 (Phase 3): Wildcard/bulk recon followed by publish to sensitive topic.
		MQTT::ReconThenPublish,
		## DET-SW-001: Any PUBLISH to a switch throw-command topic.
		MQTT::SwitchThrowCommand,
		## DET-SW-002: >switch_throw_burst_threshold throws in switch_throw_burst_interval from one source.
		MQTT::SwitchThrowRapidRepeat,
		## DET-SW-003: SUBSCRIBE to switch state/discovery topic, then throw within switch_recon_throw_window.
		MQTT::SwitchReconThenThrow,
	};

	# -------------------------------------------------------------------------
	# Topic classification
	# -------------------------------------------------------------------------

	## Regex matching command/control topics.  PUBLISH with retain=T or a CONNECT
	## will_topic matching this pattern fires RetainedCommandMessage or
	## WillMessageAbuse respectively.  Adjust to match your topic hierarchy.
	option sensitive_topic_patterns: pattern =
	    /\/(cmd|set|control|write|actuator|command)\//;

	# -------------------------------------------------------------------------
	# Suppression allow-lists — per-PDU zero-config detections (DET-004, DET-006)
	# -------------------------------------------------------------------------

	## Source IPs permitted to issue wildcard ("#") SUBSCRIBE requests.  Any
	## source not in this set fires MQTT::WildcardSubscription.  Empty by
	## default — add monitoring or management clients to suppress false positives.
	option wildcard_subscribe_allowed: set[addr] = {};

	## Source IPs permitted to SUBSCRIBE to topics beginning with "$SYS/".
	## Any source not in this set fires MQTT::SystemTopicAccess.  Empty by
	## default — add broker-management hosts to suppress false positives.
	option sys_topic_subscribe_allowed: set[addr] = {};

	# -------------------------------------------------------------------------
	# DET-007 ProtocolViolation
	# -------------------------------------------------------------------------

	## Number of conn_weird events on a single port-1883 connection that
	## triggers MQTT::ProtocolViolation.  A well-behaved MQTT session should
	## never produce frame-stacking or malformed-packet weirdness.
	option protocol_violation_threshold: count = 5;

	# -------------------------------------------------------------------------
	# DET-010 PublishFlood
	# -------------------------------------------------------------------------

	## PUBLISH messages per epoch from the same source IP that triggers
	## MQTT::PublishFlood.  Tune to your device's expected publish rate;
	## legitimate sensors typically publish at ≤1 Hz.
	option publish_flood_threshold: count = 1000;

	## Counting window for PublishFlood.  Short window catches burst attacks
	## before they saturate broker queues.
	option publish_flood_interval: interval = 5sec;

	# -------------------------------------------------------------------------
	# DET-013 ConnectionFlood
	# -------------------------------------------------------------------------

	## CONNECT packets per epoch from the same source IP that triggers
	## MQTT::ConnectionFlood.  Repeated reconnects may indicate credential
	## stuffing or a misbehaving client library.
	option connection_flood_threshold: count = 20;

	## Counting window for ConnectionFlood.
	option connection_flood_interval: interval = 60sec;

	# -------------------------------------------------------------------------
	# mqtt_summary.log
	# -------------------------------------------------------------------------

	## SumStats epoch for mqtt_summary.log.  Default 1 hour; reduce for
	## testing (e.g. redef mqtt_detect::summary_epoch = 10sec in a btest).
	option summary_epoch: interval = 1hr;

	# -------------------------------------------------------------------------
	# Phase 2 options
	# -------------------------------------------------------------------------

	## Set of source IPs that are known, legitimate MQTT clients.  When
	## non-empty, a CONNECT from any source not in this set fires
	## MQTT::RogueClient.  Empty by default — populate from at least one
	## week of mqtt_connections.log before enabling.
	option known_clients: set[addr] = {};

	## Per-source table of topic patterns that a source is authorized to
	## publish to.  PUBLISH to a topic not matched by the source's pattern
	## fires MQTT::UnauthorizedPublish.  Empty by default.
	option authorized_publishers: table[addr] of pattern = {};

	## CONNACK failure responses per epoch from the same source IP that
	## triggers MQTT::ConnectFailureFlood.  Indicates credential brute-force
	## or misconfigured clients.
	option connect_failure_threshold: count = 10;

	## Counting window for ConnectFailureFlood.
	option connect_failure_interval: interval = 60sec;

	## Distinct topics subscribed by one source in topic_enum_interval that
	## triggers MQTT::TopicEnumeration.  Indicates automated topic discovery.
	option topic_enum_threshold: count = 50;

	## Counting window for TopicEnumeration.
	option topic_enum_interval: interval = 60sec;

	# -------------------------------------------------------------------------
	# Phase 3 options
	# -------------------------------------------------------------------------

	## Grace period after first-seen CONNECT before a subscribe-only client
	## that issues a PUBLISH triggers MQTT::SubscriberPublishEscalation.
	## Default one week — long enough to observe normal client behavior.
	option subscriber_escalation_grace: interval = 168hr; # one week

	## Window after wildcard/bulk recon activity within which a subsequent
	## PUBLISH to a sensitive topic triggers MQTT::ReconThenPublish.
	option recon_publish_window: interval = 15min;

	## Master switch for DET-012 ReconThenPublish.  Set to F to disable
	## all DET-012 state tracking, Broker relay events, and notices.
	## Recommended in cluster deployments with high sensitive-topic
	## publish rates where the relay cost is unacceptable.
	option enable_recon_then_publish: bool = T;

	# -------------------------------------------------------------------------
	# Switch-specific options (DET-SW-001/002/003)
	# -------------------------------------------------------------------------

	## Pattern matching the switch throw-command topic.  Covers any switch ID:
	## choochoo/switch/<id>/cmd/throw
	## Adjust if the topic root changes.
	option switch_throw_cmd_pattern: pattern =
	    /choochoo\/switch\/[^\/]+\/cmd\/throw/;

	## Pattern matching switch state and discovery topics — subscriptions to
	## these indicate a client is profiling the switch before attempting a throw.
	option switch_recon_topic_pattern: pattern =
	    /choochoo\/switch\/[^\/]+\/(state|discovery)/;

	## How many throw-command publishes from one source IP in
	## switch_throw_burst_interval triggers MQTT::SwitchThrowRapidRepeat.
	## The safety cooldown is 2 s per throw, so >3 in 10 s means the client is
	## spamming faster than the mechanism can execute (or ignoring rejections).
	option switch_throw_burst_threshold: count = 3;

	## Counting window for SwitchThrowRapidRepeat.
	option switch_throw_burst_interval: interval = 10sec;

	## Window after observing a switch recon subscription within which a
	## subsequent throw-command publish fires MQTT::SwitchReconThenThrow.
	option switch_recon_throw_window: interval = 10min;
}
