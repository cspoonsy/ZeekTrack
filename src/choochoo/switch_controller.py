"""Subscribes to MQTT switch-command topics and drives a SwitchClient.

Mirrors `choochoo.controller.Controller` for the train: same shutdown
discipline, same LWT + retained-discovery beacon, same "log + ignore" policy
on malformed payloads. All hardware safety (bounded burst, cooldown, stop
in finally) lives in SwitchClient — this class just wires MQTT to it.
"""

from __future__ import annotations

import json
import logging
import signal
import time
from dataclasses import dataclass

import paho.mqtt.client as mqtt
from pydantic import ValidationError

from choochoo import mqtt_auth
from choochoo.switch import SwitchClient, build_switch
from choochoo.switch_protocol import (
    SwitchDiscovery,
    SwitchState,
    ThrowCommand,
    ThrowEvent,
    ThrowOutcome,
    switch_cmd_topic,
    switch_cmd_wildcard,
    switch_discovery_topic,
    switch_event_topic,
    switch_state_topic,
)

log = logging.getLogger(__name__)


@dataclass
class SwitchControllerConfig:
    broker_host: str = "localhost"
    broker_port: int = 1883
    switch_id: str = "sw1"
    switch_kind: str = "fake"


class SwitchController:
    def __init__(self, cfg: SwitchControllerConfig) -> None:
        self.cfg = cfg
        self.switch: SwitchClient = build_switch(cfg.switch_kind, cfg.switch_id)
        self.client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=f"choochoo-switch-controller-{cfg.switch_id}",
        )
        mqtt_auth.configure(self.client)
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message
        # Event-timestamp clock (swapped in tests).
        self._clock = time.time

        offline = SwitchDiscovery(
            switch_id=cfg.switch_id,
            cmd_topic=switch_cmd_topic(cfg.switch_id, "+"),
            state_topic=switch_state_topic(cfg.switch_id),
            online=False,
        )
        self.client.will_set(
            switch_discovery_topic(cfg.switch_id),
            offline.model_dump_json(),
            qos=1,
            retain=True,
        )

    def run(self) -> None:
        self.switch.connect()
        self._publish_state()
        self.client.connect(self.cfg.broker_host, self.cfg.broker_port, keepalive=30)
        signal.signal(signal.SIGINT, lambda *_: self._shutdown())
        signal.signal(signal.SIGTERM, lambda *_: self._shutdown())
        self.client.loop_forever()

    def _shutdown(self) -> None:
        log.info("shutting down")
        try:
            self.switch.disconnect()
        finally:
            self.client.disconnect()

    def _on_connect(self, client, _userdata, _flags, reason_code, _props) -> None:
        topic = switch_cmd_wildcard(self.cfg.switch_id)
        log.info("connected rc=%s, subscribing to %s", reason_code, topic)
        client.subscribe(topic)
        self._publish_discovery(online=True)

    def _publish_discovery(self, online: bool) -> None:
        ann = SwitchDiscovery(
            switch_id=self.cfg.switch_id,
            cmd_topic=switch_cmd_topic(self.cfg.switch_id, "+"),
            state_topic=switch_state_topic(self.cfg.switch_id),
            online=online,
        )
        self.client.publish(
            switch_discovery_topic(self.cfg.switch_id),
            ann.model_dump_json(),
            qos=1,
            retain=True,
        )

    def _on_message(self, _client, _userdata, msg: mqtt.MQTTMessage) -> None:
        action = msg.topic.rsplit("/", 1)[-1]
        try:
            payload = json.loads(msg.payload)
        except json.JSONDecodeError:
            log.warning("non-JSON payload on %s: %r", msg.topic, msg.payload)
            return

        if action != "throw":
            log.warning("unknown action: %s", action)
            return

        try:
            cmd = ThrowCommand.model_validate(payload)
        except ValidationError as e:
            log.warning("bad payload on %s: %s", msg.topic, e)
            return

        outcome = self.switch.throw(cmd.direction)
        self._publish_event(cmd, outcome)
        self._publish_state()

    def _publish_event(self, cmd: ThrowCommand, outcome: ThrowOutcome) -> None:
        ev = ThrowEvent(
            switch_id=self.cfg.switch_id,
            direction=cmd.direction,
            outcome=outcome,
            ts=self._clock(),
        )
        self.client.publish(
            switch_event_topic(self.cfg.switch_id),
            ev.model_dump_json(),
        )

    def _publish_state(self) -> None:
        state: SwitchState = self.switch.state()
        self.client.publish(
            switch_state_topic(self.cfg.switch_id),
            state.model_dump_json(),
            retain=True,
        )
