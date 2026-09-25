import pytest

from core.models import Finding, DataType


def test_finding_valid_construction():
    f = Finding(source="test", target="example.com",
                 data_type=DataType.EMAIL, value="a@example.com")
    assert f.confidence == 0.5
    assert f.value == "a@example.com"


def test_finding_rejects_empty_value():
    with pytest.raises(ValueError):
        Finding(source="test", target="example.com",
                 data_type=DataType.EMAIL, value="   ")


def test_finding_rejects_out_of_range_confidence():
    with pytest.raises(ValueError):
        Finding(source="test", target="example.com",
                 data_type=DataType.EMAIL, value="a@example.com",
                 confidence=1.5)
