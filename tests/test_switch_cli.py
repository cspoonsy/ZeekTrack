"""Very light CLI wiring test — invokes click without hitting a broker."""

from __future__ import annotations

from unittest.mock import patch

from click.testing import CliRunner

from choochoo.cli import main


def test_switch_send_throw_calls_publish():
    with patch("choochoo.cli.publish.single") as pub:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["switch-send", "throw", "forward", "--switch-id", "sw1", "--host", "127.0.0.1"],
        )
        assert result.exit_code == 0, result.output
        pub.assert_called_once()
        args, kwargs = pub.call_args
        assert kwargs["hostname"] == "127.0.0.1"
        # Topic is first positional arg.
        assert args[0] == "choochoo/switch/sw1/cmd/throw"


def test_switch_controller_subcommand_is_registered():
    runner = CliRunner()
    result = runner.invoke(main, ["switch-controller", "--help"])
    assert result.exit_code == 0
    assert "switch" in result.output.lower()
