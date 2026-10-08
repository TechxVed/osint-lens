"""
plugins/docker_plugins/sublist3r_plugin.py

Sublist3r plugin.

Runs Sublist3r inside Docker to discover subdomains
for a domain target.
"""

import re
import subprocess

from core.base_plugin import BasePlugin
from core.models import Finding, DataType


DOCKER_IMAGE_NAME = "osint-lens-sublist3r"


class Sublist3rPlugin(BasePlugin):
    """Run Sublist3r inside Docker."""

    name = "sublist3r"
    description = (
        "Runs Sublist3r inside Docker to discover subdomains "
        "of a target domain."
    )
    timeout_seconds = 120

    def is_available(self) -> bool:
        """Return True when Docker and the Sublist3r image are available."""
        try:
            result = subprocess.run(
                [
                    "docker",
                    "image",
                    "inspect",
                    DOCKER_IMAGE_NAME,
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )

            return result.returncode == 0

        except (
            subprocess.SubprocessError,
            FileNotFoundError,
        ):
            return False

    def run(self, target: str) -> list[Finding]:
        """Run Sublist3r against a domain."""

        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                "bridge",
                DOCKER_IMAGE_NAME,
                "-d",
                target,
                "-o",
                "/tmp/subdomains.txt",
            ],
            capture_output=True,
            text=True,
            timeout=self.timeout_seconds,
        )

        if result.returncode != 0:
            raise RuntimeError(
                f"Sublist3r failed with exit code "
                f"{result.returncode}: {result.stderr.strip()}"
            )

        findings: list[Finding] = []

        for line in result.stdout.splitlines():
            line = line.strip()

            if not line:
                continue

            if not self._is_valid_subdomain(line, target):
                continue

            findings.append(
                Finding(
                    source=self.name,
                    target=target,
                    data_type=DataType.SUBDOMAIN,
                    value=line,
                    confidence=0.80,
                    raw={
                        "output": line,
                    },
                )
            )

        return findings

    @staticmethod
    def _is_valid_subdomain(value: str, target: str) -> bool:
        """Return True when value looks like a subdomain of target."""

        value = value.rstrip(".").lower()
        target = target.rstrip(".").lower()

        if value == target:
            return False

        if not value.endswith("." + target):
            return False

        hostname_pattern = (
            r"^(?=.{1,253}$)"
            r"(?:[a-z0-9]"
            r"(?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
            r"[a-z]{2,63}$"
        )

        return bool(re.fullmatch(hostname_pattern, value))
