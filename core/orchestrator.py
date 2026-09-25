"""
core/orchestrator.py

Runs the selected plugins against a target using a bounded thread pool.

WHAT A THREAD IS (viva-ready explanation):
A thread is a separate line of execution within the same process. Unlike
a separate process, threads share memory, which is why we're careful
not to mutate shared state from multiple threads at once (each plugin
call here returns its own PluginResult; we only combine results back on
the main thread, after `future.result()` -- there is no shared mutable
state being written concurrently).

WHAT ThreadPoolExecutor DOES:
It maintains a fixed-size pool of worker threads (`max_workers`) and a
queue of jobs. `pool.submit(fn, *args)` hands one job to the pool and
immediately returns a Future -- a placeholder for a result that doesn't
exist yet. The pool decides which idle worker thread actually runs the
job. This bounds concurrency deliberately: if you had 20 plugins and no
limit, you could open 20 simultaneous connections to external services
and get rate-limited or IP-banned. `max_workers=5` (configurable) caps
that.

WHAT A FUTURE REPRESENTS:
A Future is an object representing "the result of a job that may not
have finished yet." Calling `.result()` on it blocks until the job
finishes (or raises whatever exception the job raised). `as_completed()`
yields futures in the order they actually finish, not the order they
were submitted -- so a fast plugin's result is available immediately
even if a slow plugin was submitted first.

WHY CONCURRENCY HELPS HERE:
Each plugin spends most of its time waiting on I/O (a network response,
or a subprocess/Docker container). While one plugin is waiting, Python
can switch to running another plugin's code. This is different from
CPU-bound parallelism (which Python's GIL limits) -- I/O-bound waiting
is exactly the case threads are good at in Python.

WHEN SEQUENTIAL WOULD BE PREFERABLE:
If plugins depend on each other's output (e.g. plugin B needs a
subdomain list that plugin A produces), concurrency would be actively
wrong -- you'd need to run A, wait for it, then run B. None of our
plugins depend on each other, so concurrent execution is safe here. This
project keeps plugins deliberately independent for that reason.

WHY THIS DOESN'T GUARANTEE SPEEDUP:
If you only run one plugin, there is no other work to overlap, so
concurrency has zero effect. If plugins hit the same external service and
that service rate-limits you, running them "in parallel" may just cause
retries/backoff that erase the time saved. Concurrency helps precisely
when there are multiple *independent, I/O-bound* jobs -- which is our
case, but it's worth being honest that it isn't magic.
"""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FutureTimeoutError

from core.exceptions import PluginExecutionError
from core.models import PluginResult, PluginStatus
from core.base_plugin import BasePlugin


def _run_single_plugin(plugin: BasePlugin, target: str) -> PluginResult:
    """Runs exactly one plugin and always returns a PluginResult -- never
    raises. This is what makes "one plugin's failure can't take down the
    whole scan" true: every possible outcome (success, expected failure,
    timeout, unexpected exception) is caught here and converted into data.
    """
    start = time.monotonic()
    try:
        if not plugin.is_available():
            return PluginResult(
                plugin_name=plugin.name,
                status=PluginStatus.SKIPPED,
                error_message="Plugin reported itself unavailable "
                              "(missing API key, binary, or Docker image).",
                duration_seconds=time.monotonic() - start,
            )
        findings = plugin.run(target)
        return PluginResult(
            plugin_name=plugin.name,
            status=PluginStatus.SUCCESS,
            findings=findings,
            duration_seconds=time.monotonic() - start,
        )
    except PluginExecutionError as e:
        return PluginResult(
            plugin_name=plugin.name,
            status=PluginStatus.FAILED,
            error_message=str(e),
            duration_seconds=time.monotonic() - start,
        )
    except Exception as e:  # noqa: BLE001 - deliberate: isolate ANY unexpected error
        return PluginResult(
            plugin_name=plugin.name,
            status=PluginStatus.FAILED,
            error_message=f"Unexpected error: {e!r}",
            duration_seconds=time.monotonic() - start,
        )


def run_scan(target: str, plugins: list[BasePlugin], max_workers: int = 5) -> list[PluginResult]:
    """Runs every plugin against `target` concurrently (bounded by
    max_workers) and returns one PluginResult per plugin, regardless of
    whether that plugin succeeded, failed, or timed out.
    """
    results: list[PluginResult] = []
    pool = ThreadPoolExecutor(max_workers=max_workers)
    try:
        future_to_plugin = {
            pool.submit(_run_single_plugin, plugin, target): plugin
            for plugin in plugins
        }
        # NOTE on timeout, worth knowing for a viva question: we call
        # future.result(timeout=...) directly (not via as_completed) so
        # the timeout is measured from "now" for each future individually.
        # Important honesty point: Python cannot forcibly kill a running
        # thread. If a plugin ignores this and hangs, this wrapper stops
        # *waiting* for it and reports TIMEOUT, but the underlying thread
        # may still be running in the background until it finishes or the
        # process exits. The real protection against a hang is inside each
        # plugin itself (requests' own `timeout=` parameter, subprocess's
        # own `timeout=` parameter) -- this wrapper is a safety net on top
        # of that, not a substitute for it.
        for future, plugin in future_to_plugin.items():
            try:
                result = future.result(timeout=plugin.timeout_seconds)
            except FutureTimeoutError:
                result = PluginResult(
                    plugin_name=plugin.name,
                    status=PluginStatus.TIMEOUT,
                    error_message=f"Exceeded {plugin.timeout_seconds}s timeout.",
                )
            results.append(result)
    finally:
        # BUG FIXED DURING TESTING: using `with ThreadPoolExecutor() as pool:`
        # calls pool.shutdown(wait=True) on exit, which blocks until EVERY
        # submitted thread has actually finished -- including ones we just
        # reported as TIMEOUT above. That made run_scan() silently block for
        # the full duration of a hung plugin anyway, defeating the purpose
        # of reporting a timeout at all. shutdown(wait=False) lets this
        # function return as soon as we've stopped waiting on each future,
        # while the (rare, hopefully) still-running background thread is
        # left to finish on its own. One remaining caveat, disclosed here
        # rather than hidden: Python's concurrent.futures module registers
        # an atexit hook that still joins any outstanding worker threads
        # before the *process* exits, so a truly hung plugin can delay the
        # CLI's own shutdown even though run_scan() itself returns promptly.
        pool.shutdown(wait=False)
    return results
