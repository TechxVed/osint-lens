import time

from core.orchestrator import run_scan
from core.base_plugin import BasePlugin
from core.models import Finding, DataType, PluginStatus
from core.exceptions import PluginExecutionError


class _GoodPlugin(BasePlugin):
    name = "good_plugin"
    timeout_seconds = 5

    def run(self, target):
        return [Finding(source=self.name, target=target,
                          data_type=DataType.EMAIL, value="a@x.com")]


class _FailingPlugin(BasePlugin):
    name = "failing_plugin"
    timeout_seconds = 5

    def run(self, target):
        raise PluginExecutionError("simulated failure")


class _CrashingPlugin(BasePlugin):
    """Raises a raw, unexpected exception type -- not our own exception
    class -- to prove the orchestrator isolates ANY exception, not just
    the ones we anticipated."""
    name = "crashing_plugin"
    timeout_seconds = 5

    def run(self, target):
        raise KeyError("unexpected bug")


class _SlowPlugin(BasePlugin):
    name = "slow_plugin"
    timeout_seconds = 1

    def run(self, target):
        time.sleep(3)
        return []


class _UnavailablePlugin(BasePlugin):
    name = "unavailable_plugin"

    def is_available(self):
        return False

    def run(self, target):
        return []


def test_one_failing_plugin_does_not_stop_others():
    results = run_scan("example.com", [_GoodPlugin(), _FailingPlugin()])
    by_name = {r.plugin_name: r for r in results}
    assert by_name["good_plugin"].status == PluginStatus.SUCCESS
    assert by_name["failing_plugin"].status == PluginStatus.FAILED
    assert len(by_name["good_plugin"].findings) == 1


def test_unexpected_exception_is_caught_not_propagated():
    # This must not raise -- proves _run_single_plugin's bare except works.
    results = run_scan("example.com", [_CrashingPlugin()])
    assert results[0].status == PluginStatus.FAILED
    assert "unexpected" in results[0].error_message.lower() or "KeyError" in results[0].error_message


def test_plugin_timeout_is_reported():
    results = run_scan("example.com", [_SlowPlugin()])
    assert results[0].status == PluginStatus.TIMEOUT


def test_unavailable_plugin_is_skipped():
    results = run_scan("example.com", [_UnavailablePlugin()])
    assert results[0].status == PluginStatus.SKIPPED


def test_concurrent_execution_faster_than_sequential():
    """Two plugins that each sleep ~1s should complete in well under 2s
    combined when run concurrently -- proves ThreadPoolExecutor is
    actually overlapping their waits, not running them one after another.
    """
    class _OneSecondPlugin(BasePlugin):
        name = "one_second_plugin"
        timeout_seconds = 5

        def run(self, target):
            time.sleep(1)
            return []

    start = time.monotonic()
    run_scan("example.com", [_OneSecondPlugin(), _OneSecondPlugin()])
    elapsed = time.monotonic() - start
    assert elapsed < 1.8  # generous margin above 1s, well below 2s sequential
