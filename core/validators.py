"""
core/validators.py

Target validation and authorization confirmation.
"""

import ipaddress
import re

from core.exceptions import TargetValidationError


_DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*"
    r"\.[A-Za-z]{2,}$"
)


def is_valid_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def is_valid_domain(target: str) -> bool:
    return bool(_DOMAIN_RE.match(target))


def is_valid_username(target: str) -> bool:
    """Basic username validation for username-based OSINT tools."""
    return bool(re.fullmatch(r"[A-Za-z0-9._-]{1,50}", target))


def validate_username(target: str) -> str:
    """Validate a username target."""
    target = target.strip()

    if not target:
        raise TargetValidationError("Username cannot be empty.")

    if not is_valid_username(target):
        raise TargetValidationError(
            f"'{target}' does not look like a valid username."
        )

    return target


def validate_target(target: str) -> str:
    """Validate a domain or IP target."""
    target = target.strip().lower()

    if not target:
        raise TargetValidationError("Target cannot be empty.")

    if is_valid_ip(target) or is_valid_domain(target):
        return target

    raise TargetValidationError(
        f"'{target}' does not look like a valid domain or IP address."
    )


def confirm_authorization(target: str, assume_yes: bool = False) -> bool:
    """Require explicit authorization before reconnaissance."""
    if assume_yes:
        return True

    print(f"\nYou are about to run OSINT reconnaissance against: {target}")
    print("This tool must only be used against targets you own or are")
    print("explicitly authorized to test (e.g. via a signed engagement).")

    answer = input(
        "Confirm you are authorized to scan this target? [y/N]: "
    )

    return answer.strip().lower() in ("y", "yes")
