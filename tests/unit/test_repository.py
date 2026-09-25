import sqlite3

import pytest

from database.schema import SCHEMA_SQL
from database import repository
from core.models import Finding, DataType, PluginResult, PluginStatus, Alert


@pytest.fixture
def conn():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript(SCHEMA_SQL)
    yield c
    c.close()


def test_create_scan_returns_id(conn):
    scan_id = repository.create_scan(conn, "example.com", ["mock_example"])
    assert isinstance(scan_id, int)
    assert scan_id > 0


def test_save_and_retrieve_findings(conn):
    scan_id = repository.create_scan(conn, "example.com", ["mock_example"])
    findings = [
        Finding(source="mock_example", target="example.com",
                 data_type=DataType.EMAIL, value="a@example.com"),
    ]
    repository.save_findings(conn, scan_id, findings)
    detail = repository.get_scan_detail(conn, scan_id)
    assert len(detail["findings"]) == 1
    assert detail["findings"][0]["value"] == "a@example.com"


def test_save_plugin_result(conn):
    scan_id = repository.create_scan(conn, "example.com", ["mock_example"])
    result = PluginResult(plugin_name="mock_example", status=PluginStatus.SUCCESS,
                            duration_seconds=0.5)
    repository.save_plugin_result(conn, scan_id, result)
    detail = repository.get_scan_detail(conn, scan_id)
    assert detail["plugin_runs"][0]["plugin_name"] == "mock_example"
    assert detail["plugin_runs"][0]["status"] == "success"


def test_save_alerts_links_evidence(conn):
    scan_id = repository.create_scan(conn, "example.com", ["mock_example"])
    f = Finding(source="mock_example", target="example.com",
                 data_type=DataType.EMAIL, value="a@example.com")
    id_map = repository.save_findings(conn, scan_id, [f])
    alert = Alert(rule_name="test_rule", description="desc", rationale="why",
                    evidence=[f], target="example.com")
    repository.save_alerts(conn, scan_id, [alert], id_map)
    detail = repository.get_scan_detail(conn, scan_id)
    assert len(detail["alerts"]) == 1
    assert detail["alerts"][0]["rule_name"] == "test_rule"


def test_get_scan_detail_missing_scan_returns_empty(conn):
    assert repository.get_scan_detail(conn, 9999) == {}
