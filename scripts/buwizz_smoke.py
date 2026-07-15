"""End-to-end smoke test for the BuWizz BLE backend.

Run on whatever host owns the BLE radio (Mac with Bluetooth permission, or
the Pi). No MQTT / Modbus / web UI involved — just the BuWizzTrain class.

  CHOOCHOO_BUWIZZ_NAME='BuWizz3' uv run python scripts/buwizz_smoke.py

The test:
  1. Connects (BLE scan + GATT)
  2. Lights all 4 LEDs at brightness 5 (white)
  3. Drives forward at power 30 for 3 seconds
  4. Stops
  5. Drives reverse at power 30 for 2 seconds
  6. Stops
  7. Lights off (back to default)
  8. Disconnects

Watch for the train physically responding and for `BuWizz status` debug
lines confirming notifications are flowing.
"""
from __future__ import annotations

import logging
import sys
import time

from choochoo.protocol import Direction
from choochoo.train.buwizz import BuWizzTrain

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)


def main() -> int:
    train = BuWizzTrain("smoke")
    print("connecting...")
    try:
        train.connect()
    except Exception as e:
        print(f"connect failed: {e}")
        return 1

    try:
        print("light on (brightness=5)")
        train.light(5)
        time.sleep(1)

        print("forward @ 30 for 3s")
        train.motor(Direction.FORWARD, 30)
        time.sleep(3)

        print("stop")
        train.stop()
        time.sleep(1)

        print("reverse @ 30 for 2s")
        train.motor(Direction.REVERSE, 30)
        time.sleep(2)

        print("stop")
        train.stop()
        time.sleep(1)

        print("light off")
        train.light(0)
        time.sleep(0.5)

        print(f"final state: {train.state()}")
    finally:
        print("disconnecting...")
        train.disconnect()
    print("done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
