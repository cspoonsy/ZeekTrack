"""Env-driven auth + TLS for paho clients.

Three env vars control everything:
    CHOOCHOO_USER       — MQTT username (omit for anonymous = baseline)
    CHOOCHOO_PASSWORD   — MQTT password
    CHOOCHOO_TLS_CA     — path to a CA cert; if set, we connect over TLS

Defaults intentionally match the deliberately-vulnerable baseline. The
hardened compose profile + run-hardened.sh wrapper sets all three.
"""

from __future__ import annotations

import os

import paho.mqtt.client as mqtt


def configure(client: mqtt.Client) -> None:
    """Apply username/password and TLS to a paho client."""
    user = os.environ.get("CHOOCHOO_USER")
    password = os.environ.get("CHOOCHOO_PASSWORD")
    if user:
        client.username_pw_set(user, password)

    ca = os.environ.get("CHOOCHOO_TLS_CA")
    if ca:
        client.tls_set(ca_certs=ca)


def default_port() -> int:
    """1883 if plaintext, 8883 if TLS — unless explicitly overridden."""
    explicit = os.environ.get("CHOOCHOO_BROKER_PORT")
    if explicit:
        return int(explicit)
    return 8883 if os.environ.get("CHOOCHOO_TLS_CA") else 1883


def publish_auth() -> dict[str, str] | None:
    """`auth=` dict for `paho.mqtt.publish.single`. None when anonymous."""
    user = os.environ.get("CHOOCHOO_USER")
    if not user:
        return None
    return {"username": user, "password": os.environ.get("CHOOCHOO_PASSWORD", "")}


def publish_tls() -> dict[str, str] | None:
    """`tls=` dict for `paho.mqtt.publish.single`. None when plaintext."""
    ca = os.environ.get("CHOOCHOO_TLS_CA")
    if not ca:
        return None
    return {"ca_certs": ca}
