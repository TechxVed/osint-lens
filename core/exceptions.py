"""
core/exceptions.py

Custom exceptions so the orchestrator can distinguish "this plugin failed
in an expected way" (bad target, tool not installed, API rate-limited)
from "something in my own code is broken" (a real bug). This matters for
a viva question like "how do you handle errors" — the answer is "we have
specific exception types per failure mode, not one giant try/except".
"""


class OsintLensError(Exception):
    """Base class for every exception this project defines on purpose."""


class TargetValidationError(OsintLensError):
    """Raised when the user-supplied target fails format or authorization
    checks (core/validators.py)."""


class PluginExecutionError(OsintLensError):
    """Raised by a plugin when its tool/API call fails in an expected,
    recoverable way (e.g. non-2xx HTTP response, non-zero exit code)."""


class PluginTimeoutError(OsintLensError):
    """Raised when a plugin does not finish within its allotted time."""


class ToolUnavailableError(OsintLensError):
    """Raised when a required binary or Docker image is missing."""


class NormalizationError(OsintLensError):
    """Raised when a Finding cannot be reconciled with the common schema."""
