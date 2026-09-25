"""
tests/unit/test_shodan_plugin.py

These tests use unittest.mock to fake `requests.get` responses -- the
sandbox this project was built in cannot reach api.shodan.io (network
allowlist), so these mocks are the only way to actually exercise the
plugin's response-handling branches (200/401/404/429/malformed JSON)
without a live network call. This directly targets the spec requirement
to test "API failures" and "malformed tool output".
"""

from unittest.mock import patch, MagicMock

import pytest
import requests

from plugins.api_plugins.shodan_plugin import ShodanPlugin
from core.exceptions import PluginExecutionError
from core.models import DataType


def _mock_response(status_code=200, json_data=None, raise_json_error=False):
    resp = MagicMock()
    resp.status_code = status_code
    if raise_json_error:
        resp.json.side_effect = ValueError("not valid json")
    else:
        resp.json.return_value = json_data or {}
    return resp


def test_is_available_false_without_key(monkeypatch):
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    assert ShodanPlugin().is_available() is False


def test_is_available_true_with_key(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "fake_key")
    assert ShodanPlugin().is_available() is True


def test_run_raises_without_key(monkeypatch):
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    with pytest.raises(PluginExecutionError):
        ShodanPlugin().run("8.8.8.8")


@patch("plugins.api_plugins.shodan_plugin.requests.get")
def test_run_parses_ports_and_hostnames(mock_get, monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "fake_key")
    mock_get.return_value = _mock_response(200, {
        "ports": [22, 443],
        "hostnames": ["a.example.com", "b.example.com"],
    })
    findings = ShodanPlugin().run("8.8.8.8")
    port_values = {f.value for f in findings if f.data_type == DataType.OPEN_PORT}
    host_values = {f.value for f in findings if f.data_type == DataType.SUBDOMAIN}
    assert port_values == {"22", "443"}
    assert host_values == {"a.example.com", "b.example.com"}


@patch("plugins.api_plugins.shodan_plugin.requests.get")
def test_run_returns_empty_list_on_404(mock_get, monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "fake_key")
    mock_get.return_value = _mock_response(404)
    findings = ShodanPlugin().run("8.8.8.8")
    assert findings == []


@patch("plugins.api_plugins.shodan_plugin.requests.get")
def test_run_raises_on_401(mock_get, monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "bad_key")
    mock_get.return_value = _mock_response(401)
    with pytest.raises(PluginExecutionError, match="401"):
        ShodanPlugin().run("8.8.8.8")


@patch("plugins.api_plugins.shodan_plugin.requests.get")
def test_run_raises_on_429(mock_get, monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "fake_key")
    mock_get.return_value = _mock_response(429)
    with pytest.raises(PluginExecutionError, match="rate limit"):
        ShodanPlugin().run("8.8.8.8")


@patch("plugins.api_plugins.shodan_plugin.requests.get")
def test_run_raises_on_malformed_json(mock_get, monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "fake_key")
    mock_get.return_value = _mock_response(200, raise_json_error=True)
    with pytest.raises(PluginExecutionError, match="malformed"):
        ShodanPlugin().run("8.8.8.8")


@patch("plugins.api_plugins.shodan_plugin.requests.get")
def test_run_raises_on_network_error(mock_get, monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "fake_key")
    mock_get.side_effect = requests.ConnectionError("no route to host")
    with pytest.raises(PluginExecutionError, match="Network error"):
        ShodanPlugin().run("8.8.8.8")


def test_domain_gets_resolved_before_query(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "fake_key")
    plugin = ShodanPlugin()
    # google-public-dns-a.google.com reliably resolves to 8.8.8.8; this
    # only tests the resolution helper, not the network call itself.
    with patch("socket.gethostbyname", return_value="8.8.8.8") as mock_resolve:
        ip = plugin._resolve_to_ip("example.com")
        assert ip == "8.8.8.8"
        mock_resolve.assert_called_once_with("example.com")


def test_resolve_raises_on_unresolvable_domain(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "fake_key")
    plugin = ShodanPlugin()
    with patch("socket.gethostbyname", side_effect=__import__("socket").gaierror("no such host")):
        with pytest.raises(PluginExecutionError):
            plugin._resolve_to_ip("this-does-not-exist.invalid")
