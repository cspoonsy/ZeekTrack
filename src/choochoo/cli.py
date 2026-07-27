"""CLI entrypoint."""

from __future__ import annotations

import json
import logging
import os

import click
import paho.mqtt.publish as publish

from choochoo import mqtt_auth
from choochoo.controller import Controller, ControllerConfig
from choochoo.protocol import Direction, LightCommand, MotorCommand, StopCommand, cmd_topic
from choochoo.switch_controller import SwitchController, SwitchControllerConfig
from choochoo.switch_protocol import ThrowCommand, switch_cmd_topic


def _broker_opts(f):
    f = click.option("--host", default=lambda: os.environ.get("CHOOCHOO_BROKER", "localhost"))(f)
    f = click.option("--port", default=lambda: mqtt_auth.default_port(), type=int)(f)
    f = click.option("--train-id", default=lambda: os.environ.get("CHOOCHOO_TRAIN_ID", "t1"))(f)
    return f


def _switch_opts(f):
    f = click.option(
        "--switch-id",
        default=lambda: os.environ.get("CHOOCHOO_SWITCH_ID", "sw1"),
    )(f)
    return f


@click.group()
@click.option("-v", "--verbose", is_flag=True)
def main(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def _protocol_default() -> str:
    return os.environ.get("CHOOCHOO_PROTOCOL", "mqtt").lower()


def _protocol_option(f):
    return click.option(
        "--protocol",
        type=click.Choice(["mqtt", "modbus"]),
        default=_protocol_default,
        show_default=True,
        help="IoT (MQTT) vs. enterprise (Modbus/TCP) control plane.",
    )(f)


@main.command()
@_broker_opts
@_protocol_option
def controller(host: str, port: int, train_id: str, protocol: str) -> None:
    """Run the protocol <-> train bridge."""
    kind = os.environ.get("CHOOCHOO_TRAIN", "fake")
    if protocol == "modbus":
        from choochoo.modbus_controller import ModbusController, ModbusControllerConfig
        modbus_port = (
            int(os.environ["CHOOCHOO_MODBUS_PORT"])
            if "CHOOCHOO_MODBUS_PORT" in os.environ else 5020
        )
        bind = os.environ.get("CHOOCHOO_MODBUS_BIND", "0.0.0.0")  # noqa: S104
        cfg = ModbusControllerConfig(
            bind=bind, port=modbus_port, train_id=train_id, train_kind=kind,
        )
        ModbusController(cfg).run()
        return
    cfg = ControllerConfig(broker_host=host, broker_port=port, train_id=train_id, train_kind=kind)
    Controller(cfg).run()


@main.command()
@_broker_opts
@_protocol_option
@click.option(
    "--bind",
    default="0.0.0.0",  # noqa: S104 — intentionally LAN-reachable for the exercise
    help="Address to bind the HTTP server. Default 0.0.0.0 exposes the UI to "
         "the LAN, which is part of the deliberately-vulnerable posture.",
)
@click.option("--http-port", default=8000, type=int)
def web(host: str, port: int, train_id: str, bind: str, http_port: int, protocol: str) -> None:
    """Run the FastAPI web UI."""
    import uvicorn

    os.environ["CHOOCHOO_PROTOCOL"] = protocol
    os.environ["CHOOCHOO_BROKER"] = host
    os.environ["CHOOCHOO_BROKER_PORT"] = str(port)
    os.environ["CHOOCHOO_TRAIN_ID"] = train_id
    uvicorn.run("choochoo.web:app", host=bind, port=http_port, log_level="info")


@main.group()
def send() -> None:
    """Publish a command to the broker."""


_SEND_DEPRECATION = (
    "warning: `choochoo send` targets the MQTT train, which is deprecated "
    "for the ChooChoo event. Use `choochoo controller --protocol modbus` "
    "and drive the train from the web UI."
)


@send.command("motor")
@_broker_opts
@click.argument("direction", type=click.Choice([d.value for d in Direction]))
@click.argument("power", type=click.IntRange(0, 100))
def send_motor(host: str, port: int, train_id: str, direction: str, power: int) -> None:
    click.echo(_SEND_DEPRECATION, err=True)
    cmd = MotorCommand(direction=Direction(direction), power=power)
    _publish(host, port, cmd_topic(train_id, "motor"), cmd.model_dump())


@send.command("stop")
@_broker_opts
def send_stop(host: str, port: int, train_id: str) -> None:
    click.echo(_SEND_DEPRECATION, err=True)
    _publish(host, port, cmd_topic(train_id, "stop"), StopCommand().model_dump())


@send.command("light")
@_broker_opts
@click.argument("brightness", type=click.IntRange(0, 10))
def send_light(host: str, port: int, train_id: str, brightness: int) -> None:
    click.echo(_SEND_DEPRECATION, err=True)
    cmd = LightCommand(brightness=brightness)
    _publish(host, port, cmd_topic(train_id, "light"), cmd.model_dump())


@main.command("switch-controller")
@click.option("--host", default=lambda: os.environ.get("CHOOCHOO_BROKER", "localhost"))
@click.option("--port", default=lambda: mqtt_auth.default_port(), type=int)
@_switch_opts
def switch_controller_cmd(host: str, port: int, switch_id: str) -> None:
    """Run the MQTT ↔ track-switch bridge."""
    kind = os.environ.get("CHOOCHOO_SWITCH_KIND", "fake")
    cfg = SwitchControllerConfig(
        broker_host=host, broker_port=port, switch_id=switch_id, switch_kind=kind,
    )
    SwitchController(cfg).run()


@main.group("switch-send")
def switch_send() -> None:
    """Publish a command to a switch controller."""


@switch_send.command("throw")
@click.option("--host", default=lambda: os.environ.get("CHOOCHOO_BROKER", "localhost"))
@click.option("--port", default=lambda: mqtt_auth.default_port(), type=int)
@_switch_opts
@click.argument("direction", type=click.Choice([d.value for d in Direction]))
def switch_send_throw(host: str, port: int, switch_id: str, direction: str) -> None:
    cmd = ThrowCommand(direction=Direction(direction))
    _publish(host, port, switch_cmd_topic(switch_id, "throw"), cmd.model_dump())


def _publish(host: str, port: int, topic: str, payload: dict) -> None:
    publish.single(
        topic,
        json.dumps(payload),
        hostname=host,
        port=port,
        auth=mqtt_auth.publish_auth(),
        tls=mqtt_auth.publish_tls(),
    )
    click.echo(f"-> {topic} {payload}")
