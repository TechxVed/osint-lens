import pytest

from core.validators import validate_target, is_valid_domain, is_valid_ip
from core.exceptions import TargetValidationError


def test_valid_domain_passes():
    assert validate_target("example.com") == "example.com"


def test_valid_ip_passes():
    assert validate_target("8.8.8.8") == "8.8.8.8"


def test_empty_target_raises():
    with pytest.raises(TargetValidationError):
        validate_target("   ")


def test_garbage_target_raises():
    with pytest.raises(TargetValidationError):
        validate_target("not a domain!!")


def test_is_valid_domain_rejects_leading_hyphen():
    assert is_valid_domain("-bad.com") is False


def test_is_valid_ip_rejects_domain():
    assert is_valid_ip("example.com") is False
