"""
tests/unit/test_theharvester_plugin.py

Mocks subprocess.run and shutil.which so the plugin's logic (building
the docker command, handling exit codes, reading the output file,
parsing JSON) can be exercised without an actual Docker daemon -- which
this sandbox does not have. This directly targets the spec requirement
to test "Docker unavailable", "missing executable", and "malformed tool
output" for the Type B integration.
"""

import json
import os
from unittest.mock import patch, MagicMock

import pytest

from plugins.docker_plugins.theharvester_plugin import TheHarvesterPlugin, DOCKER_IMAGE_NAME
from core.exceptions import PluginExecutionError
from core.models import DataType


def test_is_available_false_when_docker_binary_missing():
    with patch("shutil.which", return_value=None):
        assert TheHarvesterPlugin().is_available() is False


def test_is_available_false_when_image_missing():
    with patch("shutil.which", return_value="/usr/bin/docker"), \
         patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1)  # docker image inspect fails
        assert TheHarvesterPlugin().is_available() is False


def test_is_available_true_when_docker_and_image_present():
    with patch("shutil.which", return_value="/usr/bin/docker"), \
         patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        assert TheHarvesterPlugin().is_available() is True


def test_run_raises_on_nonzero_exit_code():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=1, stdout="", stderr="theHarvester crashed"
        )
        with pytest.raises(PluginExecutionError, match="exited with code 1"):
            TheHarvesterPlugin().run("example.com")


def test_run_raises_on_timeout():
    import subprocess as sp
    with patch("subprocess.run", side_effect=sp.TimeoutExpired(cmd="docker", timeout=60)):
        with pytest.raises(PluginExecutionError, match="exceeded"):
            TheHarvesterPlugin().run("example.com")


def test_run_raises_when_output_file_missing():
    # subprocess "succeeds" (returncode 0) but never actually writes the
    # JSON file the plugin expects inside the temp mount -- this is a
    # real failure mode if the tool's CLI flags silently change.
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        with pytest.raises(PluginExecutionError, match="did not produce"):
            TheHarvesterPlugin().run("example.com")


def test_run_raises_on_malformed_json_output():
    def fake_run(cmd, capture_output, text, timeout):
        # cmd includes "-v", "<hostdir>:/output" -- extract hostdir and
        # write garbage where the plugin expects valid JSON.
        mount_arg = cmd[cmd.index("-v") + 1]
        host_dir = mount_arg.split(":")[0]
        with open(os.path.join(host_dir, "result.json"), "w") as f:
            f.write("{not valid json")
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("subprocess.run", side_effect=fake_run):
        with pytest.raises(PluginExecutionError, match="not valid JSON"):
            TheHarvesterPlugin().run("example.com")


def test_run_parses_valid_output_correctly():
    def fake_run(cmd, capture_output, text, timeout):
        mount_arg = cmd[cmd.index("-v") + 1]
        host_dir = mount_arg.split(":")[0]
        with open(os.path.join(host_dir, "result.json"), "w") as f:
            json.dump({
                "emails": ["admin@example.com", "sales@example.com"],
                "hosts": ["mail.example.com:1.2.3.4", "vpn.example.com"],
            }, f)
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("subprocess.run", side_effect=fake_run):
        findings = TheHarvesterPlugin().run("example.com")

    emails = {f.value for f in findings if f.data_type == DataType.EMAIL}
    hosts = {f.value for f in findings if f.data_type == DataType.SUBDOMAIN}
    assert emails == {"admin@example.com", "sales@example.com"}
    # "mail.example.com:1.2.3.4" must be split on ":" -- only the
    # hostname portion should survive.
    assert hosts == {"mail.example.com", "vpn.example.com"}


def test_docker_image_name_constant_used_in_command():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="x")
        try:
            TheHarvesterPlugin().run("example.com")
        except PluginExecutionError:
            pass
        called_cmd = mock_run.call_args[0][0]
        assert DOCKER_IMAGE_NAME in called_cmd
        assert "--rm" in called_cmd
