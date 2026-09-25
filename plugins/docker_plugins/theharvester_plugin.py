"""
plugins/docker_plugins/theharvester_plugin.py

TYPE B integration (Dockerized CLI tool) per the project spec.

HONESTY NOTE, stated up front: this plugin was written and statically
reviewed, but could NOT be executed in the sandbox this project was
built in (no Docker daemon, and the sandbox's network allowlist does not
include Docker Hub). It has NOT been run against a live theHarvester
container. Section "Testing this plugin on Kali Linux" in the README
gives the exact commands to build the image and verify this plugin for
real -- do that before you rely on it in your demo, and be ready to say
in a viva "the pipeline and mock plugin are fully tested; this specific
integration is implemented and documented but requires Docker to verify,
which I did/did not have time to do on [machine]."

WHY DOCKER FOR THIS TOOL SPECIFICALLY:
theHarvester has its own Python dependency tree that can conflict with
this project's own virtual environment (different library versions).
Running it inside a container gives it an isolated environment that
works identically on any machine with Docker installed, rather than
requiring theHarvester to be pip-installed system-wide or into this
project's venv.

IMAGE VS CONTAINER (viva-ready): the Docker *image* is the built,
read-only template (theHarvester + its dependencies, layered on a base
OS image) defined by docker/theharvester.Dockerfile. A *container* is a
running instance of that image -- `docker run` creates one, executes the
command, and (because of `--rm`) deletes the container afterward. The
image itself is NOT deleted; only the ephemeral container is.

theHarvester's real CLI supports a JSON output flag via `-f <path>`
which writes results as JSON *inside* the container's filesystem. To get
that file back out, we bind-mount a host directory into the container
(`-v <host_dir>:/output`) and tell theHarvester to write there, so the
JSON file exists on the host after the container exits. We do NOT assume
theHarvester's exact output schema beyond what's documented -- if the
schema differs across versions, `_parse_output` below fails loudly
(raises PluginExecutionError) rather than silently returning wrong data.
"""

import json
import os
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
        "Runs theHarvester (email/subdomain OSINT) inside a Docker "
        "container for dependency isolation. Requires Docker installed "
        "and the osint-lens-theharvester image built (see README)."
    )
    timeout_seconds = 60

    def is_available(self) -> bool:
        """Cheap pre-flight check: is the `docker` binary on PATH, and
        does the required image exist locally? Does NOT run a container
        just to check availability.
        """
        if shutil.which("docker") is None:
            return False
        try:
            result = subprocess.run(
                ["docker", "image", "inspect", DOCKER_IMAGE_NAME],
                capture_output=True, text=True, timeout=5,
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, OSError):
            return False

    def run(self, target: str) -> list[Finding]:
        with tempfile.TemporaryDirectory() as host_output_dir:
            container_output_path = "/output/result.json"
            cmd = [
                "docker", "run", "--rm",
                "--network", "bridge",
                "-v", f"{host_output_dir}:/output",
                DOCKER_IMAGE_NAME,
                "-d", target,
                "-b", "all",
                "-f", container_output_path,
            ]
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=self.timeout_seconds,
                )
            except subprocess.TimeoutExpired as e:
                raise PluginExecutionError(
                    f"theHarvester container exceeded {self.timeout_seconds}s."
                ) from e
            except OSError as e:
                raise PluginExecutionError(f"Could not launch Docker: {e}") from e

            if result.returncode != 0:
                raise PluginExecutionError(
                    f"theHarvester container exited with code {result.returncode}. "
                    f"stderr: {result.stderr.strip()[:500]}"
                )

            host_json_path = os.path.join(host_output_dir, "result.json")
            if not os.path.exists(host_json_path):
                raise PluginExecutionError(
                    "theHarvester did not produce an output file at the "
                    "expected path. stdout: " + result.stdout.strip()[:500]
                )

            with open(host_json_path, "r", encoding="utf-8") as f:
                try:
                    data = json.load(f)
                except json.JSONDecodeError as e:
                    raise PluginExecutionError(
                        f"theHarvester output was not valid JSON: {e}"
                    ) from e

            return self._parse_output(data, target)

    def _parse_output(self, data: dict, target: str) -> list[Finding]:
        findings: list[Finding] = []

        for email in data.get("emails", []) or []:
            findings.append(Finding(
                source=self.name, target=target,
                data_type=DataType.EMAIL, value=email,
                confidence=0.75, raw=data,
            ))

        for hostname in data.get("hosts", []) or []:
            # theHarvester's "hosts" entries are sometimes "host:ip" strings;
            # split defensively rather than assuming a fixed format.
            name = hostname.split(":")[0].strip() if isinstance(hostname, str) else str(hostname)
            if name:
                findings.append(Finding(
                    source=self.name, target=target,
                    data_type=DataType.SUBDOMAIN, value=name,
                    confidence=0.75, raw=data,
                ))

        return findings
