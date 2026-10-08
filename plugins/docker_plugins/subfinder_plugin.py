"""
plugins/docker_plugins/subfinder_plugin.py

Docker integration for ProjectDiscovery Subfinder.
"""

import shutil
import subprocess

from core.base_plugin import BasePlugin
from core.exceptions import PluginExecutionError
from core.models import Finding, DataType


DOCKER_IMAGE_NAME = "osint-lens-subfinder"


class SubfinderPlugin(BasePlugin):
    name = "subfinder"
    description = (
        "Runs ProjectDiscovery Subfinder inside a Docker container "
        "to discover subdomains."
    )
    timeout_seconds = 60

    def is_available(self) -> bool:
        """Check whether Docker and the Subfinder image are available."""
        if shutil.which("docker") is None:
            return False

        try:
            result = subprocess.run(
                ["docker", "image", "inspect", DOCKER_IMAGE_NAME],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0

        except (subprocess.SubprocessError, OSError):
            return False

    def run(self, target: str) -> list[Finding]:
        """Run Subfinder against the target domain."""
        cmd = [
            "docker",
            "run",
            "--rm",
            "--network",
            "bridge",
            DOCKER_IMAGE_NAME,
            "-d",
            target,
            "-silent",
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )

        except subprocess.TimeoutExpired as e:
            raise PluginExecutionError(
                f"Subfinder container exceeded {self.timeout_seconds}s."
            ) from e

        except OSError as e:
            raise PluginExecutionError(
                f"Could not launch Docker: {e}"
            ) from e

        if result.returncode != 0:
            raise PluginExecutionError(
                f"Subfinder container exited with code {result.returncode}. "
                f"stderr: {result.stderr.strip()[:500]}"
            )

        findings: list[Finding] = []

        for line in result.stdout.splitlines():
            subdomain = line.strip()

            if not subdomain:
                continue

            findings.append(
                Finding(
                    source=self.name,
                    target=target,
                    data_type=DataType.SUBDOMAIN,
                    value=subdomain,
                    confidence=0.85,
                    raw={"output": subdomain},
                )
            )

        return findings
