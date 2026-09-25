"""
plugins/mock_example_plugin.py

The MVP's reference plugin. Produces realistic-shaped but entirely
synthetic data so the whole pipeline (orchestrator -> normalizer ->
correlator -> storage -> report) can be built, run, and demonstrated
without any API key, installed tool, or Docker image.

IMPORTANT (from the "do not fabricate findings" requirement): this
plugin's `source` is explicitly "mock_example", never disguised as a
real OSINT source. Every Finding it returns is clearly attributable to
this mock plugin in the database and in the report -- it must never be
presented as if it were live intelligence.
"""

import random
import time

from core.base_plugin import BasePlugin
from core.models import Finding, DataType


class MockExamplePlugin(BasePlugin):
    name = "mock_example"
    description = (
        "Synthetic plugin with no external dependencies. Returns "
        "realistic-shaped fake data. Used to validate the pipeline "
        "end-to-end and for demos without API keys or installed tools."
    )
    timeout_seconds = 10

    def is_available(self) -> bool:
        return True  # always available, by design

    def run(self, target: str) -> list[Finding]:
        # Small artificial delay so concurrency is actually visible when
        # this plugin runs alongside others (useful for demonstrating
        # ThreadPoolExecutor's effect during a viva).
        time.sleep(random.uniform(0.5, 1.5))

        findings = [
            Finding(
                source=self.name,
                target=target,
                data_type=DataType.SUBDOMAIN,
                value=f"mail.{target}",
                confidence=0.6,
                metadata={"note": "synthetic example data"},
                raw={"example": True},
            ),
            Finding(
                source=self.name,
                target=target,
                data_type=DataType.SUBDOMAIN,
                value=f"vpn.{target}",
                confidence=0.6,
                metadata={"note": "synthetic example data"},
                raw={"example": True},
            ),
            Finding(
                source=self.name,
                target=target,
                data_type=DataType.EMAIL,
                value=f"admin@{target}",
                confidence=0.5,
                metadata={"note": "synthetic example data"},
                raw={"example": True},
            ),
            Finding(
                source=self.name,
                target=target,
                data_type=DataType.OPEN_PORT,
                value="22",
                confidence=0.7,
                metadata={"note": "synthetic example data", "service": "ssh"},
                raw={"example": True},
            ),
        ]
        return findings
