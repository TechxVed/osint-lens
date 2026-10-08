"""
plugins/docker_plugins/sherlock_plugin.py

Sherlock plugin.

Runs Sherlock inside Docker to search for a username across
social networks and converts discovered profile URLs into
normalized OSINT-Lens findings.
"""

import subprocess

from core.base_plugin import BasePlugin
from core.models import Finding, DataType


DOCKER_IMAGE_NAME = "osint-lens-sherlock"


class SherlockPlugin(BasePlugin):
    """Run Sherlock inside Docker."""

    name = "sherlock"
    description = (
        "Runs Sherlock inside Docker to search for a username "
        "across social networks."
    )
    timeout_seconds = 90

    def is_available(self) -> bool:
        """Return True when Docker and the Sherlock image are available."""
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
        """Run Sherlock against a username."""

        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                "bridge",
                DOCKER_IMAGE_NAME,
                target,
                "--print-found",
            ],
            capture_output=True,
            text=True,
            timeout=self.timeout_seconds,
        )

        if result.returncode != 0:
            raise RuntimeError(
                f"Sherlock failed with exit code "
                f"{result.returncode}: {result.stderr.strip()}"
            )

        findings: list[Finding] = []

        for line in result.stdout.splitlines():
            line = line.strip()

            if not line:
                continue

            if line.startswith("http://") or line.startswith("https://"):
                findings.append(
                    Finding(
                        source=self.name,
                        target=target,
                        data_type=DataType.OTHER,
                        value=line,
                        confidence=0.90,
                        raw={
                            "output": line,
                        },
                    )
                )

        return findings
