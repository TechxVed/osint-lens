from pathlib import Path

from reports.generator import generate_html_report


def test_generate_html_report_with_mock_data(tmp_path):
    scan_detail = {
        "scan": {"target": "example.com", "started_at": "2026-01-01T00:00:00",
                  "modules_requested": "mock_example"},
        "plugin_runs": [
            {"plugin_name": "mock_example", "status": "success",
             "duration_seconds": 0.8, "error_message": None},
        ],
        "findings": [
            {"source": "mock_example", "data_type": "email", "value": "a@example.com",
             "confidence": 0.5, "timestamp": "2026-01-01T00:00:01",
             "metadata_json": "{}"},
        ],
        "alerts": [],
    }
    out_path = tmp_path / "report.html"
    result_path = generate_html_report(scan_detail, out_path)

    assert result_path.exists()
    content = result_path.read_text(encoding="utf-8")
    assert "example.com" in content
    assert "a@example.com" in content
    assert "mock_example" in content


def test_report_escapes_html_in_finding_values(tmp_path):
    """Proves autoescape is actually on: a finding value containing HTML
    must not be rendered as live markup in the output file."""
    scan_detail = {
        "scan": {"target": "example.com", "started_at": "t", "modules_requested": "x"},
        "plugin_runs": [],
        "findings": [
            {"source": "x", "data_type": "email",
             "value": "<script>alert(1)</script>",
             "confidence": 0.5, "timestamp": "t", "metadata_json": "{}"},
        ],
        "alerts": [],
    }
    out_path = tmp_path / "report.html"
    generate_html_report(scan_detail, out_path)
    content = out_path.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in content
    assert "&lt;script&gt;" in content
