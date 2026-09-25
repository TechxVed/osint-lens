"""
plugins/api_plugins/shodan_plugin.py

TYPE C integration (Web API) per the project spec.

Calls Shodan's real, documented host lookup endpoint:
    GET https://api.shodan.io/shodan/host/{ip}?key={API_KEY}
Docs: https://developer.shodan.io/api

IMPORTANT LIMITATION, stated plainly rather than hidden: Shodan's host
endpoint expects an IP address, not a domain name. If a domain is given,
this plugin will attempt a best-effort resolution to an IP using Python's
standard `socket.gethostbyname`. This is a deliberate, documented choice,
not a silent assumption -- if resolution fails, the plugin fails cleanly
with a PluginExecutionError rather than guessing.

SECRETS HANDLING: the API key is read from the SHODAN_API_KEY environment
variable (populated by python-dotenv from .env at program startup). It is
never placed in the URL logged anywhere by this code, and `raw` responses
stored on Finding objects come from Shodan's JSON body, which does not
echo the key back.

WITHOUT AN API KEY: `is_available()` returns False, so the orchestrator
marks this plugin SKIPPED rather than attempting and failing a call. This
means the MVP demo (mock_example only) and a real run with a key both
work correctly through the same orchestrator code path.
"""

import os
import socket

import requests

from core.base_plugin import BasePlugin
from core.exceptions import PluginExecutionError
from core.models import Finding, DataType

SHODAN_HOST_URL = "https://api.shodan.io/shodan/host/{ip}"


class ShodanPlugin(BasePlugin):
    name = "shodan"
    description = (
        "Queries Shodan's host lookup API for open ports and known "
        "services on a target IP (domains are resolved to an IP first). "
        "Requires SHODAN_API_KEY in .env."
    )
    timeout_seconds = 20

    def is_available(self) -> bool:
        return bool(os.getenv("SHODAN_API_KEY"))

    def _resolve_to_ip(self, target: str) -> str:
        try:
            socket.inet_aton(target)
            return target  # already an IP
        except OSError:
            pass
        try:
            return socket.gethostbyname(target)
        except socket.gaierror as e:
            raise PluginExecutionError(
                f"Could not resolve '{target}' to an IP address: {e}"
            ) from e

    def run(self, target: str) -> list[Finding]:
        api_key = os.getenv("SHODAN_API_KEY")
        if not api_key:
            raise PluginExecutionError("SHODAN_API_KEY not set.")

        ip = self._resolve_to_ip(target)

        try:
            response = requests.get(
                SHODAN_HOST_URL.format(ip=ip),
                params={"key": api_key},
                timeout=self.timeout_seconds,
            )
        except requests.RequestException as e:
            raise PluginExecutionError(f"Network error calling Shodan: {e}") from e

        if response.status_code == 404:
            return []  # Shodan has no data for this host -- a valid, empty result
        if response.status_code == 401:
            raise PluginExecutionError("Shodan rejected the API key (401 Unauthorized).")
        if response.status_code == 429:
            raise PluginExecutionError("Shodan rate limit exceeded (429).")
        if response.status_code != 200:
            raise PluginExecutionError(
                f"Shodan returned unexpected status {response.status_code}."
            )

        try:
            data = response.json()
        except ValueError as e:
            raise PluginExecutionError(f"Shodan returned malformed JSON: {e}") from e

        findings: list[Finding] = []
        for port in data.get("ports", []):
            findings.append(Finding(
                source=self.name,
                target=target,
                data_type=DataType.OPEN_PORT,
                value=str(port),
                confidence=0.9,
                metadata={"resolved_ip": ip},
                raw=data,
            ))

        for hostname in data.get("hostnames", []):
            findings.append(Finding(
                source=self.name,
                target=target,
                data_type=DataType.SUBDOMAIN,
                value=hostname,
                confidence=0.7,
                metadata={"resolved_ip": ip},
                raw=data,
            ))

        return findings
