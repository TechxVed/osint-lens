"""
core/base_plugin.py

Defines the contract every plugin must follow.

WHY AN ABSTRACT BASE CLASS (ABC):
Without a shared contract, the orchestrator would need to know the
internal details of every plugin ("if it's a Shodan plugin, call it like
this; if it's theHarvester, call it like that"). With an ABC, the
orchestrator only ever calls `plugin.run(target)` and trusts it returns
`list[Finding]` — it does not know or care whether that happened via an
HTTP request, a subprocess call, or a Docker container underneath.

`ABC` + `@abstractmethod` means Python will refuse to let you instantiate
a subclass that hasn't implemented `run()`. This is a language-enforced
guarantee, not just a convention — if you write a new plugin and forget
`run()`, you get a TypeError the moment you try to use it, not a mystery
bug during a scan.

HOW TO ADD A NEW PLUGIN WITHOUT TOUCHING THE REST OF THE APP:
1. Create a new file in plugins/ (or a subfolder).
2. Subclass BasePlugin, set `name` and `description`.
3. Implement `run(self, target)`.
4. Register it in core/registry.py (one line).
That's the entire extension surface — nothing in core/orchestrator.py,
core/normalizer.py, or the CLI needs to change.
"""

from abc import ABC, abstractmethod

from core.models import Finding


class BasePlugin(ABC):
    """Every OSINT plugin, regardless of whether it wraps a local CLI
    tool, a Docker container, or a web API, inherits from this class.
    """

    name: str = "base_plugin"
    description: str = "No description provided."
    # Seconds the orchestrator will wait before treating this plugin as
    # timed out. Subclasses can override this if a tool is known to be slow.
    timeout_seconds: int = 30

    def is_available(self) -> bool:
        """Optional pre-flight check (e.g. is the API key set? Is Docker
        installed? Is the binary on PATH?). Default: assume available.
        Subclasses should override this when there's a cheap way to check
        before actually running the tool.
        """
        return True

    @abstractmethod
    def run(self, target: str) -> list[Finding]:
        """Execute the tool/API call against `target` and return a list
        of normalized Finding objects.

        Implementations should:
        - Raise core.exceptions.PluginExecutionError for expected failures
          (bad response, tool crashed) rather than letting raw exceptions
          (KeyError, ConnectionError) escape uncaught.
        - Never raise for "zero results found" — that's a valid outcome,
          return an empty list.
        """
        raise NotImplementedError
