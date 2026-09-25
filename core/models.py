"""
core/models.py

Defines the common data structures every plugin, the normalizer, the
correlator, the database layer, and the report generator all agree on.

WHY THIS FILE EXISTS:
Every OSINT tool returns data in a different shape (JSON, XML, plain text).
Instead of every downstream component needing to know about every tool's
format, each plugin converts its own tool's output into these two objects.
After that point, nothing else in the codebase needs to know or care which
tool produced a piece of data — it's just a Finding.

We use @dataclass instead of a plain class or Pydantic because:
- It's standard library (no extra dependency).
- It auto-generates __init__, __repr__, and __eq__ for us.
- The validation logic is small enough that we can hand-write it in
  core/validators.py and core/normalizer.py, which is easier to explain
  in a viva than pointing at a third-party validation library.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class PluginStatus(str, Enum):
    """Represents how a plugin's execution ended.

    Using a str Enum (not a bare string) means typos like "sucess" become
    an error at the point they're written, not a silent bug discovered
    later when a report shows the wrong status.
    """
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"


class DataType(str, Enum):
    """Known finding categories. The normalizer rejects anything outside
    this list, which keeps garbage/typo'd categories out of the database
    and out of the correlation engine (which matches on these exact
    values).
    """
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP_ADDRESS = "ip_address"
    OPEN_PORT = "open_port"
    EMAIL = "email"
    DNS_RECORD = "dns_record"
    TECHNOLOGY = "technology"
    CERTIFICATE = "certificate"
    OTHER = "other"


@dataclass
class Finding:
    """A single normalized observation produced by one plugin.

    Fields:
        source:      which plugin produced this (e.g. "shodan", "mock_example")
        target:      what was scanned (e.g. "example.com")
        data_type:   one of DataType — what kind of observation this is
        value:       the actual observed value (e.g. "22", "admin@example.com")
        confidence:  0.0-1.0, how much the plugin author trusts this source's
                     accuracy for this kind of data. Not a security severity —
                     just "how reliable is this observation, typically."
        metadata:    small dict of extra context (e.g. {"banner": "OpenSSH 8.2"})
        raw:         the plugin's original, untouched output for this item,
                     kept for provenance/debugging. Never shown raw in the
                     report if it might contain secrets — see normalizer.
        timestamp:   when this finding was created (UTC, timezone-aware)
    """
    source: str
    target: str
    data_type: DataType
    value: str
    confidence: float = 0.5
    metadata: dict = field(default_factory=dict)
    raw: dict = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self):
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"confidence must be between 0.0 and 1.0, got {self.confidence}")
        if not self.value or not self.value.strip():
            raise ValueError("Finding.value cannot be empty")


@dataclass
class Alert:
    """Output of the correlation engine: a rule fired against a set of
    findings. Deliberately uses cautious language fields (see `evidence`,
    `rationale`) rather than a single "severity: CRITICAL" string, because
    OSINT observations alone rarely justify strong severity claims.
    """
    rule_name: str
    description: str
    rationale: str                  # why this combination matters, in plain language
    evidence: list                     # list of Finding objects that triggered this
    target: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class PluginResult:
    """Wraps a plugin's execution outcome — not just its findings, but
    whether it succeeded, so the orchestrator can report per-plugin status
    without one failure hiding another plugin's success.
    """
    plugin_name: str
    status: PluginStatus
    findings: list = field(default_factory=list)
    error_message: str = ""
    duration_seconds: float = 0.0
