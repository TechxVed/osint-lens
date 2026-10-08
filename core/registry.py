"""
core/registry.py

A single source of truth mapping a plugin's CLI-facing name (e.g.
"mock_example") to its class. This is the ONLY file you edit to make a
new plugin available to the CLI -- nothing else needs to change.

WHY A DICT AND NOT SOMETHING FANCIER (e.g. auto-discovery via scanning
the plugins/ folder):
Auto-discovery is a nice feature but it hides what's actually happening
-- if asked "how does the tool know which plugins exist," "there's a
dict in registry.py" is an answer you can defend line by line. Dynamic
folder-scanning would need its own explanation and its own failure modes
(what if a file in plugins/ fails to import?) for a benefit that doesn't
matter at this project's scale.
"""

from core.base_plugin import BasePlugin
from plugins.mock_example_plugin import MockExamplePlugin
from plugins.api_plugins.shodan_plugin import ShodanPlugin
from plugins.docker_plugins.theharvester_plugin import TheHarvesterPlugin
from plugins.docker_plugins.subfinder_plugin import SubfinderPlugin
from plugins.docker_plugins.sherlock_plugin import SherlockPlugin
from plugins.docker_plugins.sublist3r_plugin import Sublist3rPlugin


PLUGIN_REGISTRY: dict[str, type[BasePlugin]] = {
    "mock_example": MockExamplePlugin,
    "shodan": ShodanPlugin,
    "theharvester": TheHarvesterPlugin,
    "subfinder": SubfinderPlugin,
    "sherlock": SherlockPlugin,
    "sublist3r": Sublist3rPlugin,
}


def get_plugin_classes(names: list[str]) -> list[type[BasePlugin]]:
    """Resolve a list of plugin name strings to their classes.
    Raises KeyError with a helpful message if an unknown name is given.
    """
    resolved = []

    for name in names:
        name = name.strip()

        if name not in PLUGIN_REGISTRY:
            available = ", ".join(sorted(PLUGIN_REGISTRY.keys()))
            raise KeyError(
                f"Unknown plugin '{name}'. Available plugins: {available}"
            )

        resolved.append(PLUGIN_REGISTRY[name])

    return resolved


def list_available_plugins() -> list[dict]:
    """Used by the `modules` CLI command to print what's available."""
    result = []

    for key, cls in PLUGIN_REGISTRY.items():
        instance = cls()

        result.append({
            "key": key,
            "name": instance.name,
            "description": instance.description,
            "available": instance.is_available(),
        })

    return result
