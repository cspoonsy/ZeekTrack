"""Subscribes to MQTT command topics and drives a TrainClient."""

from __future__ import annotations

import json
import logging
import signal
from dataclasses import dataclass

import paho.mqtt.client as mqtt
from pydantic import ValidationError

from choochoo import mqtt_auth
from choochoo.protocol import (
    MAX_POWER,
    DiscoveryAnnouncement,
    LightCommand,
    MotorCommand,
    StopCommand,
    cmd_topic,
    cmd_wildcard,
    discovery_topic,
    state_topic,
)
from choochoo.train import TrainClient, build_train

log = logging.getLogger(__name__)


@dataclass
class ControllerConfig:
    broker_host: str = "localhost"
    broker_port: int = 1883
    train_id: str = "t1"
    train_kind: str = "fake"


class Controller:
    def __init__(self, cfg: ControllerConfig) -> None:
        self.cfg = cfg
        self.train: TrainClient = build_train(cfg.train_kind, cfg.train_id)
        self.client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=f"choochoo-controller-{cfg.train_id}",
        )
        mqtt_auth.configure(self.client)
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message

        # Last Will & Testament: if the controller drops without sending a
        # DISCONNECT, the broker publishes this on its behalf. Convenient for
        # legitimate dashboards that want a hard "offline" signal — also a
        # gift to an attacker: they can sit on the discovery topic and time
        # a hijack for the moment the legit controller restarts.
        offline = DiscoveryAnnouncement(
            train_id=cfg.train_id,
            cmd_topic=cmd_topic(cfg.train_id, "+"),
            state_topic=state_topic(cfg.train_id),
            online=False,
        )
        self.client.will_set(
            discovery_topic(cfg.train_id),
            offline.model_dump_json(),
            qos=1,
            retain=True,
        )
        # Deprecation notice — the ChooChoo event runs Modbus for the train.
        # This controller stays as a demonstrable legacy MQTT surface (still
        # covered by V1-V10 in VULNERABILITIES.md), but operators pointing
        # at it should be nudged toward the Modbus profile.
        log.warning(
            "MQTT train controller is deprecated for the ChooChoo event; "
            "the event runs Modbus-only. Set CHOOCHOO_PROTOCOL=modbus.",
        )

    def run(self) -> None:
        self.train.connect()
        self._publish_state()
        self.client.connect(self.cfg.broker_host, self.cfg.broker_port, keepalive=30)
        signal.signal(signal.SIGINT, lambda *_: self._shutdown())
        signal.signal(signal.SIGTERM, lambda *_: self._shutdown())
        self.client.loop_forever()

    def _shutdown(self) -> None:
        log.info("shutting down")
        try:
            self.train.stop()
            self.train.disconnect()
        finally:
            self.client.disconnect()

    def _on_connect(self, client, _userdata, _flags, reason_code, _props) -> None:
        topic = cmd_wildcard(self.cfg.train_id)
        log.info("connected rc=%s, subscribing to %s", reason_code, topic)
        client.subscribe(topic)
        self._publish_discovery(online=True)

    def _publish_discovery(self, online: bool) -> None:
        ann = DiscoveryAnnouncement(
            train_id=self.cfg.train_id,
            cmd_topic=cmd_topic(self.cfg.train_id, "+"),
            state_topic=state_topic(self.cfg.train_id),
            online=online,
        )
        self.client.publish(
            discovery_topic(self.cfg.train_id),
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

        try:
            match action:
                case "motor":
                    cmd = MotorCommand.model_validate(payload)
                    # Hardware-safety clamp — applies regardless of source.
                    safe_power = min(cmd.power, MAX_POWER)
                    if safe_power != cmd.power:
                        log.warning(
                            "clamping power %d -> %d (MAX_POWER)", cmd.power, safe_power
                        )
                    self.train.motor(cmd.direction, safe_power)
                case "stop":
                    StopCommand.model_validate(payload)
                    self.train.stop()
                case "light":
                    cmd = LightCommand.model_validate(payload)
                    self.train.light(cmd.brightness)
                case _:
                    log.warning("unknown action: %s", action)
                    return
        except ValidationError as e:
            log.warning("bad payload on %s: %s", msg.topic, e)
            return

        self._publish_state()

    def _publish_state(self) -> None:
        state = self.train.state()
        self.client.publish(
            state_topic(self.cfg.train_id),
            state.model_dump_json(),
            retain=True,
        )
