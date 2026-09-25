from plugins.mock_example_plugin import MockExamplePlugin
from core.models import DataType


def test_mock_plugin_returns_findings():
    plugin = MockExamplePlugin()
    findings = plugin.run("example.com")
    assert len(findings) > 0
    assert all(f.source == "mock_example" for f in findings)
    assert all(f.target == "example.com" for f in findings)


def test_mock_plugin_always_available():
    assert MockExamplePlugin().is_available() is True


def test_mock_plugin_includes_expected_data_types():
    findings = MockExamplePlugin().run("example.com")
    types_present = {f.data_type for f in findings}
    assert DataType.SUBDOMAIN in types_present
    assert DataType.EMAIL in types_present
    assert DataType.OPEN_PORT in types_present
