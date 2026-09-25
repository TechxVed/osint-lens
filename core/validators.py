"""
core/validators.py

Two responsibilities:
1. Confirm the target string is a plausible domain or IP (basic format
   check — this is NOT a security control, just a sanity check to avoid
   sending garbage to plugins).
2. Force an explicit authorization confirmation before any scan runs.
   This is the ethical/legal safeguard: the tool will not run against a
   target unless the operator affirmatively confirms they're authorized
   to scan it. This is not enforceable against a determined bad actor,
   and we say so plainly — it is a deliberate friction step, a recorded
   acknowledgment, not an access-control mechanism.
"""

import ipaddress
import re

from core.exceptions import TargetValidationError

# Deliberately simple: matches a domain-like string (labels separated by
# dots, each label alphanumeric/hyphen, final label at least 2 chars).
# This is intentionally permissive -- it exists to catch obvious typos
# and empty input, not to be a strict RFC 1035 validator.
_DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,}$"
)


def is_valid_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def is_valid_domain(target: str) -> bool:
    return bool(_DOMAIN_RE.match(target))


def validate_target(target: str) -> str:
    """Returns the cleaned target string, or raises TargetValidationError."""
    target = target.strip().lower()
    if not target:
        raise TargetValidationError("Target cannot be empty.")
    if is_valid_ip(target) or is_valid_domain(target):
        return target
    raise TargetValidationError(
        f"'{target}' does not look like a valid domain or IP address."
    )


def confirm_authorization(target: str, assume_yes: bool = False) -> bool:
    """Blocks execution until the operator explicitly confirms they are
    authorized to run OSINT reconnaissance against `target`.

    assume_yes exists ONLY for automated tests (so tests don't hang on
    input()) -- it is never wired to a CLI flag that skips the prompt
    silently in normal use, on purpose.
    """
    if assume_yes:
        return True
    print(f"\nYou are about to run OSINT reconnaissance against: {target}")
    print("This tool must only be used against targets you own or are")
    print("explicitly authorized to test (e.g. via a signed engagement).")
    answer = input("Confirm you are authorized to scan this target? [y/N]: ")
    return answer.strip().lower() in ("y", "yes")
