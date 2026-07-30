# mqtt_switch.zeek — Detections for ChooChoo BLE track switch control plane.
#
# The physical switch is MQTT-only.  The train is Modbus-only.  These two
# protocols are entirely separate control planes — a publish to
# choochoo/switch/+/cmd/throw is therefore *always* an actuation event worth
# logging, and any client that profiles the switch (subscribes to state or
# discovery) before throwing it has done deliberate recon.
#
# Detections:
#   DET-SW-001  SwitchThrowCommand    — every throw-cmd publish (zero-config,
#                                       full audit trail for the demo)
#   DET-SW-002  SwitchThrowRapidRepeat — burst of throws faster than the
#                                       hardware cooldown allows legitimate use
#   DET-SW-003  SwitchReconThenThrow  — subscribe to state/discovery, then
#                                       throw within the recon window

@load base/protocols/mqtt
@load base/frameworks/notice
@load base/frameworks/sumstats
@load ./mqtt_detect

module MQTT;

# ---------------------------------------------------------------------------
# DET-SW-002 SumStats reducer callbacks — declared global, assigned in zeek_init
# ---------------------------------------------------------------------------

global _switch_burst_threshold_val: function(key: SumStats::Key,
    result: SumStats::Result): double;
global _switch_burst_threshold_crossed: function(key: SumStats::Key,
    result: SumStats::Result);

event zeek_init() &priority=4
	{
	_switch_burst_threshold_val = function(key: SumStats::Key,
	    result: SumStats::Result): double
		{
		if ( "mqtt.switch.throw.burst" !in result )
			return 0.0;
		return result["mqtt.switch.throw.burst"]$sum;
		};

	_switch_burst_threshold_crossed = function(key: SumStats::Key,
	    result: SumStats::Result)
		{
		if ( "mqtt.switch.throw.burst" !in result )
			return;
		local src = to_addr(key$str);
		local cnt = double_to_count(result["mqtt.switch.throw.burst"]$sum);
		NOTICE([$note=MQTT::SwitchThrowRapidRepeat, $msg=fmt(
		    "%s sent %d switch throw commands in %s — exceeds hardware cooldown rate",
		    src, cnt, mqtt_detect::switch_throw_burst_interval),
		    $src=src, $identifier=cat(src),
		    $suppress_for=mqtt_detect::switch_throw_burst_interval]);
		};
	}

event zeek_init() &priority=3
	{
	# DET-SW-002 burst counter
	SumStats::create([$name="mqtt.switch.throw.burst",
	    $epoch=mqtt_detect::switch_throw_burst_interval, $reducers=set(
	    SumStats::Reducer($stream="mqtt.switch.throw.burst", $apply=set(
	    SumStats::SUM))),
	    $threshold_val=_switch_burst_threshold_val,
	    $threshold=mqtt_detect::switch_throw_burst_threshold + 0.0,
	    $threshold_crossed=_switch_burst_threshold_crossed]);
	}

# ---------------------------------------------------------------------------
# DET-SW-003 recon window table
# ---------------------------------------------------------------------------

# src → time of first switch recon subscription
global _switch_recon_sources: table[addr] of time &create_expire=1hr;

# ---------------------------------------------------------------------------
# SUBSCRIBE handler — arm recon window on switch state/discovery subscriptions
# ---------------------------------------------------------------------------

event mqtt_subscribe(c: connection, msg_id: count, topics: string_vec,
    requested_qos: index_vec)
	{
	local src = c$id$orig_h;
	for ( i in topics )
		{
		if ( match_pattern(topics[i],
		    mqtt_detect::switch_recon_topic_pattern)$matched )
			{
			if ( src !in _switch_recon_sources )
				_switch_recon_sources[src] = network_time();
			break;
			}
		}
	}

# ---------------------------------------------------------------------------
# PUBLISH handler — DET-SW-001 / DET-SW-002 / DET-SW-003
# ---------------------------------------------------------------------------

event mqtt_publish(c: connection, is_orig: bool, msg_id: count,
    msg: MQTT::PublishMsg)
	{
	if ( ! is_orig )
		return;

	if ( ! match_pattern(msg$topic,
	    mqtt_detect::switch_throw_cmd_pattern)$matched )
		return;

	local src = c$id$orig_h;

	# DET-SW-001: log every throw-command publish (operators always want this).
	# Include uid in identifier so each publish fires its own notice entry.
	NOTICE([$note=MQTT::SwitchThrowCommand, $msg=fmt(
	    "%s issued a switch throw command to topic '%s'",
	    src, msg$topic), $conn=c,
	    $identifier=cat(src, msg$topic, c$uid),
	    $suppress_for=0sec]);

	# DET-SW-002: burst counter
	SumStats::observe("mqtt.switch.throw.burst",
	    SumStats::Key($str=cat(src)),
	    SumStats::Observation($num=1));

	# DET-SW-003: check if this source did recon first
	if ( src !in _switch_recon_sources )
		return;

	if ( network_time() - _switch_recon_sources[src] >
	    mqtt_detect::switch_recon_throw_window )
		{
		delete _switch_recon_sources[src];
		return;
		}

	delete _switch_recon_sources[src];
	NOTICE([$note=MQTT::SwitchReconThenThrow, $msg=fmt(
	    "%s subscribed to switch state/discovery topics and then issued a throw command to '%s' within %s — indicates deliberate switch recon",
	    src, msg$topic, mqtt_detect::switch_recon_throw_window), $conn=c,
	    $identifier=cat(src),
	    $suppress_for=mqtt_detect::switch_recon_throw_window]);
	}
