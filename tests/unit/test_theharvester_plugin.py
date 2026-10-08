"""
tests/unit/test_theharvester_plugin.py

Unit tests for the current theHarvester Docker integration.

The current plugin:
1. Removes any stale temporary container.
2. Runs theHarvester in a named Docker container.
3. Copies /tmp/result.json from the container with `docker cp`.
4. Parses the copied JSON.
5. Removes the temporary container during cleanup.

These tests mock subprocess.run so no real Docker daemon is required.
"""

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from core.exceptions import PluginExecutionError
from core.models import DataType
from plugins.docker_plugins.theharvester_plugin import (
    DOCKER_IMAGE_NAME,
    TheHarvesterPlugin,
)


def test_is_available_false_when_docker_binary_missing():
    with patch("shutil.which", return_value=None):
        assert TheHarvesterPlugin().is_available() is False


def test_is_available_false_when_image_missing():
    with patch("shutil.which", return_value="/usr/bin/docker"), \
         patch("subprocess.run") as mock_run:

        mock_run.return_value = MagicMock(returncode=1)

        assert TheHarvesterPlugin().is_available() is False


def test_is_available_true_when_docker_and_image_present():
    with patch("shutil.which", return_value="/usr/bin/docker"), \
         patch("subprocess.run") as mock_run:

        mock_run.return_value = MagicMock(returncode=0)

        assert TheHarvesterPlugin().is_available() is True


def test_run_raises_on_nonzero_exit_code():
    def fake_run(cmd, capture_output, text, timeout):
        if cmd[1] == "rm":
            return MagicMock(returncode=0, stdout="", stderr="")

        if cmd[1] == "run":
            return MagicMock(
                returncode=1,
                stdout="",
                stderr="theHarvester crashed",
            )

        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("subprocess.run", side_effect=fake_run):
        with pytest.raises(
            PluginExecutionError,
            match="exited with code 1",
        ):
            TheHarvesterPlugin().run("example.com")


def test_run_raises_on_timeout():
    def fake_run(cmd, capture_output, text, timeout):
        if cmd[1] == "rm":
            return MagicMock(returncode=0, stdout="", stderr="")

        if cmd[1] == "run":
            raise subprocess.TimeoutExpired(
                cmd="docker",
                timeout=90,
            )

        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("subprocess.run", side_effect=fake_run):
        with pytest.raises(
            PluginExecutionError,
            match="exceeded 90s",
        ):
            TheHarvesterPlugin().run("example.com")


def test_run_raises_when_output_file_missing():
    def fake_run(cmd, capture_output, text, timeout):
        if cmd[1] == "rm":
            return MagicMock(returncode=0, stdout="", stderr="")

        if cmd[1] == "run":
            return MagicMock(returncode=0, stdout="", stderr="")

        if cmd[1] == "cp":
            # Simulate docker cp succeeding but the expected file
            # not actually being created.
            return MagicMock(returncode=0, stdout="", stderr="")

        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("subprocess.run", side_effect=fake_run):
        with pytest.raises(
            PluginExecutionError,
            match="Could not read theHarvester JSON output",
        ):
            TheHarvesterPlugin().run("example.com")


def test_run_raises_on_malformed_json_output():
    def fake_run(cmd, capture_output, text, timeout):
        if cmd[1] == "rm":
            return MagicMock(returncode=0, stdout="", stderr="")

        if cmd[1] == "run":
            return MagicMock(returncode=0, stdout="", stderr="")

        if cmd[1] == "cp":
            host_json = cmd[-1]

            with open(host_json, "w", encoding="utf-8") as f:
                f.write("{not valid json")

            return MagicMock(returncode=0, stdout="", stderr="")

        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("subprocess.run", side_effect=fake_run):
        with pytest.raises(
            PluginExecutionError,
            match="Could not read theHarvester JSON output",
        ):
            TheHarvesterPlugin().run("example.com")


def test_run_parses_valid_output_correctly():
    def fake_run(cmd, capture_output, text, timeout):
        if cmd[1] == "rm":
            return MagicMock(returncode=0, stdout="", stderr="")

        if cmd[1] == "run":
            return MagicMock(returncode=0, stdout="", stderr="")

        if cmd[1] == "cp":
            host_json = cmd[-1]

            with open(host_json, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "emails": [
                            "admin@example.com",
                            "sales@example.com",
                        ],
                        "hosts": [
                            "mail.example.com:1.2.3.4",
                            "vpn.example.com",
                        ],
                    },
                    f,
                )

            return MagicMock(returncode=0, stdout="", stderr="")

        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("subprocess.run", side_effect=fake_run):
        findings = TheHarvesterPlugin().run("example.com")

    emails = {
        f.value
        for f in findings
        if f.data_type == DataType.EMAIL
    }

    hosts = {
        f.value
        for f in findings
        if f.data_type == DataType.SUBDOMAIN
    }

    assert emails == {
        "admin@example.com",
        "sales@example.com",
    }

    assert hosts == {
        "mail.example.com",
        "vpn.example.com",
    }


def test_docker_image_name_constant_used_in_run_command():
    commands = []

    def fake_run(cmd, capture_output, text, timeout):
        commands.append(cmd)

        if cmd[1] == "rm":
            return MagicMock(returncode=0, stdout="", stderr="")

        if cmd[1] == "run":
            return MagicMock(
                returncode=1,
                stdout="",
                stderr="x",
            )

        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("subprocess.run", side_effect=fake_run):
        with pytest.raises(PluginExecutionError):
            TheHarvesterPlugin().run("example.com")

    docker_run_commands = [
        command
        for command in commands
        if len(command) > 1 and command[1] == "run"
    ]

    assert docker_run_commands

    docker_run_command = docker_run_commands[0]

    assert DOCKER_IMAGE_NAME in docker_run_command
    assert "--name" in docker_run_command
    assert "osint-lens-theharvester-temp" in docker_run_command
    assert "-b" in docker_run_command
    assert "crtsh" in docker_run_command
