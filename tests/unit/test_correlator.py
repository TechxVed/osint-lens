from core.correlator import run_correlation
from core.models import Finding, DataType


def test_admin_port_and_email_rule_fires():
    findings = [
        Finding(source="x", target="t.com", data_type=DataType.EMAIL, value="a@t.com"),
        Finding(source="x", target="t.com", data_type=DataType.OPEN_PORT, value="3389"),
    ]
    alerts = run_correlation(findings, "t.com")
    names = {a.rule_name for a in alerts}
    assert "exposed_admin_port_with_emails" in names


def test_admin_port_rule_does_not_fire_without_email():
    findings = [
        Finding(source="x", target="t.com", data_type=DataType.OPEN_PORT, value="3389"),
    ]
    alerts = run_correlation(findings, "t.com")
    names = {a.rule_name for a in alerts}
    assert "exposed_admin_port_with_emails" not in names


def test_subdomain_footprint_rule_fires_at_threshold():
    findings = [
        Finding(source="x", target="t.com", data_type=DataType.SUBDOMAIN, value=f"s{i}.t.com")
        for i in range(5)
    ]
    alerts = run_correlation(findings, "t.com")
    names = {a.rule_name for a in alerts}
    assert "large_subdomain_footprint" in names


def test_no_rules_fire_on_empty_findings():
    alerts = run_correlation([], "t.com")
    assert alerts == []
