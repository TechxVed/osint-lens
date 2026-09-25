from core.normalizer import normalize_findings
from core.models import Finding, DataType


def test_deduplicates_identical_findings():
    f1 = Finding(source="x", target="t.com", data_type=DataType.EMAIL, value="a@t.com")
    f2 = Finding(source="x", target="t.com", data_type=DataType.EMAIL, value="a@t.com")
    result = normalize_findings([f1, f2])
    assert len(result) == 1


def test_keeps_same_value_from_different_sources():
    f1 = Finding(source="x", target="t.com", data_type=DataType.EMAIL, value="a@t.com")
    f2 = Finding(source="y", target="t.com", data_type=DataType.EMAIL, value="a@t.com")
    result = normalize_findings([f1, f2])
    assert len(result) == 2


def test_strips_whitespace_from_values():
    f1 = Finding(source="x", target="t.com", data_type=DataType.EMAIL, value="  a@t.com  ")
    result = normalize_findings([f1])
    assert result[0].value == "a@t.com"
