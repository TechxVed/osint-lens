"""
core/normalizer.py

WHAT THIS FILE IS *NOT*: it does not convert raw tool output into
Finding objects -- that happens inside each plugin (e.g.
plugins/api_plugins/shodan_plugin.py), because only that plugin knows
Shodan's specific JSON shape.

WHAT THIS FILE *IS*: a second pass across the combined list of Finding
objects from ALL plugins. It knows nothing about any specific tool. Its
job is to enforce the common schema and clean up cross-plugin noise:

  1. Strip whitespace from values.
  2. Drop empty/garbage values that slipped through a plugin.
  3. Deduplicate identical (source, target, data_type, value) tuples --
     e.g. if two modules both report the same open port, we keep it once
     per source (we keep provenance, we don't merge sources into one).
  4. Confirm data_type is a real DataType enum member (defence in depth,
     in case a plugin author passes a raw string by mistake).

Distinction worth remembering for a viva question ("raw vs parsed vs
normalized vs correlated"):
  - Raw tool output    = whatever Shodan/theHarvester/etc. actually returns
                          (JSON blob, stdout text) -- stored in Finding.raw
  - Parsed data          = that raw output pulled apart into Python values
                          (done inside the plugin, e.g. data["ports"])
  - Normalized finding = the parsed value wrapped as a Finding object,
                          validated and de-duplicated by THIS file
  - Correlated observation = an Alert produced by combining multiple
                          normalized findings (core/correlator.py)
"""

from core.models import Finding, DataType


def normalize_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple] = set()
    normalized: list[Finding] = []

    for f in findings:
        value = (f.value or "").strip()
        if not value:
            continue  # drop empty values a plugin should not have produced

        if not isinstance(f.data_type, DataType):
            try:
                f.data_type = DataType(f.data_type)
            except ValueError:
                f.data_type = DataType.OTHER

        key = (f.source, f.target, f.data_type, value)
        if key in seen:
            continue  # exact duplicate from the same plugin, skip
        seen.add(key)

        f.value = value
        normalized.append(f)

    return normalized
