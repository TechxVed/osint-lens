"""
plugins/docker_plugins/theharvester_plugin.py

Docker integration for theHarvester.
"""

import json
import shutil
import subprocess
import tempfile

from core.base_plugin import BasePlugin
from core.exceptions import PluginExecutionError
from core.models import Finding, DataType


DOCKER_IMAGE_NAME = "osint-lens-theharvester"


class TheHarvesterPlugin(BasePlugin):
    name = "theharvester"
    description = (
        "Runs theHarvester inside Docker to discover subdomains "
        "and email addresses."
    )
    timeout_seconds = 90

    def is_available(self) -> bool:
        if shutil.which("docker") is None:
            return False

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
                timeout=5,
            )

            return result.returncode == 0

        except (subprocess.SubprocessError, OSError):
            return False

    def run(self, target: str) -> list[Finding]:
        container_name = "osint-lens-theharvester-temp"

        try:
            subprocess.run(
                [
                    "docker",
                    "rm",
                    "-f",
                    container_name,
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )

            result = subprocess.run(
                [
                    "docker",
                    "run",
                    "--name",
                    container_name,
                    "--network",
                    "bridge",
                    DOCKER_IMAGE_NAME,
                    "-d",
                    target,
                    "-b",
                    "crtsh",
                    "-f",
                    "/tmp/result",
                ],
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )

            if result.returncode != 0:
                raise PluginExecutionError(
                    f"theHarvester exited with code "
                    f"{result.returncode}. "
                    f"stderr: {result.stderr.strip()[:500]}"
                )

            # Copy the JSON result from the container to a temporary
            # directory on the host before removing the container.
            with tempfile.TemporaryDirectory() as temp_dir:
                host_json = f"{temp_dir}/result.json"

                copy_result = subprocess.run(
                    [
                        "docker",
                        "cp",
                        f"{container_name}:/tmp/result.json",
                        host_json,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )

                if copy_result.returncode != 0:
                    raise PluginExecutionError(
                        "theHarvester completed but its JSON output "
                        "could not be copied from the container. "
                        f"stderr: {copy_result.stderr.strip()[:500]}"
                    )

                try:
                    with open(
                        host_json,
                        "r",
                        encoding="utf-8",
                    ) as f:
                        data = json.load(f)

                except (
                    OSError,
                    json.JSONDecodeError,
                ) as e:
                    raise PluginExecutionError(
                        f"Could not read theHarvester JSON output: {e}"
                    ) from e

                return self._parse_output(
                    data,
                    target,
                )

        except subprocess.TimeoutExpired as e:
            raise PluginExecutionError(
                f"theHarvester container exceeded "
                f"{self.timeout_seconds}s."
            ) from e

        except OSError as e:
            raise PluginExecutionError(
                f"Could not launch Docker: {e}"
            ) from e

        finally:
            subprocess.run(
                [
                    "docker",
                    "rm",
                    "-f",
                    container_name,
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )

    def _parse_output(
        self,
        data: dict,
        target: str,
    ) -> list[Finding]:

        findings: list[Finding] = []

        for email in data.get("emails", []) or []:
            if email:
                findings.append(
                    Finding(
                        source=self.name,
                        target=target,
                        data_type=DataType.EMAIL,
                        value=str(email),
                        confidence=0.75,
                        raw=data,
                    )
                )

        for hostname in data.get("hosts", []) or []:
            if not hostname:
                continue

            name = str(hostname).split(":")[0].strip()

            if not name:
                continue

            findings.append(
                Finding(
                    source=self.name,
                    target=target,
                    data_type=DataType.SUBDOMAIN,
                    value=name,
                    confidence=0.75,
                    raw=data,
                )
            )

        return findings
