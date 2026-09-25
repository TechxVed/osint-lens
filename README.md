# OSINT-Lens

A single-terminal OSINT aggregation and correlation framework, built as an
industrial training project. Runs multiple OSINT modules (local logic,
Docker-isolated tools, and web APIs) against one target, normalizes their
output into a common schema, runs a transparent rule-based correlation
engine over the combined results, stores everything in SQLite, and
displays it in one Rich terminal view -- with an optional HTML report.

## What's actually verified vs not (read this first)

Being upfront, per the project's own testing requirements:

| Component | Status |
|---|---|
| Core pipeline (CLI -> orchestrator -> normalizer -> correlator -> SQLite -> report) | **Built, executed, and tested.** 51/51 pytest tests pass. Full `scan` -> `history` -> `report` flow run manually end to end. |
| `mock_example` plugin | **Built and executed.** No external dependencies; always available. |
| `shodan` plugin (Web API integration) | **Built and unit-tested with mocked HTTP responses** (11 tests covering success, 401/404/429, malformed JSON, network errors, and domain resolution). The actual **live** API call was **not** exercised in this environment (no network access to api.shodan.io from this sandbox). Get a free-tier key at https://account.shodan.io/register and test the live call yourself before relying on it in a demo. |
| `theharvester` plugin (Docker integration) | **Built and unit-tested with a mocked subprocess** (9 tests covering missing Docker binary, missing image, non-zero exit, timeout, missing output file, malformed JSON, and correct parsing). The actual **live** Docker container was **not** run -- this sandbox has no Docker daemon. Build the image and test it for real on your own Kali machine (steps below) before demoing it. |

Two real bugs were found and fixed during testing (not hypothetical -- both actually reproduced and fixed):
1. Jinja2's `select_autoescape(["html"])` checks the *template filename's* extension. The template is named `report.html.j2`, which does not end in `.html`, so autoescape was silently OFF. Fixed by forcing `autoescape=True` directly in `reports/generator.py`. Caught by `tests/unit/test_report_generator.py::test_report_escapes_html_in_finding_values`.
2. `typer==0.12.5` crashes on `--help` when `click>=8.2` is installed (`Parameter.make_metavar() missing 1 required positional argument: 'ctx'`). Fixed by pinning `click<8.2` in `requirements.txt`.
3. `core/orchestrator.py` used `with ThreadPoolExecutor() as pool:`, whose `__exit__` calls `shutdown(wait=True)` -- this silently blocked `run_scan()` until *every* thread fully finished, including ones already reported as `TIMEOUT`, defeating the purpose of a timeout. Measured directly: a plugin timing out after 1s still made the whole function take 3s (its actual sleep duration) before this fix. Fixed by managing the pool manually and calling `shutdown(wait=False)`; confirmed by direct timing (`run_scan()` now returns in 1.00s, not 3s) and by `test_plugin_timeout_is_reported`'s measured duration dropping from 3.00s to 1.00s in the test run.

## Architecture

```
CLI (Typer) -> Target validation -> Plugin registry -> Orchestrator
(ThreadPoolExecutor, bounded, per-plugin error isolation)
-> Plugins (mock / Docker / Web API, each returns list[Finding])
-> Normalizer (cross-plugin dedup + schema enforcement)
-> Correlator (rule-based engine -> list[Alert])
-> SQLite (scans / plugin_runs / findings / alerts tables)
-> Rich terminal output + optional Jinja2 HTML report
```

## Project structure

```
osint-lens/
├── main.py                          # entry point, loads .env, launches Typer app
├── requirements.txt
├── .env.example
├── .gitignore
├── core/
│   ├── models.py                    # Finding, Alert, PluginResult dataclasses
│   ├── base_plugin.py                 # abstract base every plugin implements
│   ├── exceptions.py                   # custom exception hierarchy
│   ├── validators.py                    # target format + authorization prompt
│   ├── registry.py                       # plugin name -> class mapping
│   ├── orchestrator.py                    # ThreadPoolExecutor concurrency logic
│   ├── normalizer.py                        # cross-plugin sanity/dedup pass
│   └── correlator.py                          # rule-based correlation engine
├── plugins/
│   ├── mock_example_plugin.py             # dependency-free MVP plugin
│   ├── api_plugins/shodan_plugin.py        # Web API integration
│   └── docker_plugins/theharvester_plugin.py # Docker integration
├── docker/theharvester.Dockerfile           # image definition for theHarvester
├── database/
│   ├── schema.py                            # CREATE TABLE statements
│   ├── connection.py                        # SQLite connection + init
│   └── repository.py                        # all SQL lives here (parameterized)
├── reports/
│   ├── templates/report.html.j2
│   └── generator.py
├── cli/
│   ├── commands.py                          # scan / modules / history / report / version
│   └── output.py                            # Rich rendering
└── tests/unit/                              # 31 tests, all passing
```

## Installation (Kali Linux / any Debian-based system)

```bash
# 1. Check Python version (need 3.11+)
python3 --version

# 2. Install system dependencies (if not already present)
sudo apt update
sudo apt install -y python3-venv python3-pip git

# 3. Get the project onto the machine (copy the folder, or git clone your own repo)
cd ~/osint-lens

# 4. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# 5. Install Python dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 6. Configure environment variables
cp .env.example .env
# edit .env and add SHODAN_API_KEY=your_key_here (optional -- mock_example works without it)

# 7. Initialize the database (also happens automatically on first `scan`)
python -c "from database.connection import init_db; init_db()"

# 8. Run the test suite
python -m pytest tests/ -v
# expect: 51 passed

# 9. Run your first scan
python main.py scan --target example.com --modules mock_example --report

# 10. View the generated report
xdg-open data/report_scan_1.html   # or just open it in a browser manually
```

## Usage

```bash
python main.py --help                      # see all commands
python main.py modules                      # list available plugins + availability
python main.py scan --target example.com --modules mock_example
python main.py scan --target example.com --modules mock_example,shodan --report
python main.py history                       # list past scans
python main.py report <scan_id>              # regenerate a report for a past scan
python main.py version
```

`scan` will interactively ask you to confirm authorization before running
against a target. Use `--yes` only in scripted contexts where you've
already separately confirmed authorization.

## Testing this plugin on Kali Linux: theHarvester (Docker)

This is the one piece not verified in the build environment. To actually
test it:

```bash
# 1. Install Docker if not already present
sudo apt install -y docker.io
sudo systemctl enable --now docker
sudo usermod -aG docker $USER   # then log out/in for group change to apply

# 2. Build the image
cd ~/osint-lens
docker build -t osint-lens-theharvester -f docker/theharvester.Dockerfile .

# 3. Confirm the plugin now reports itself available
python main.py modules
# theharvester should now show "available"

# 4. Run a real scan
python main.py scan --target example.com --modules theharvester --yes
```

If the container's output schema doesn't match what `_parse_output()` in
`plugins/docker_plugins/theharvester_plugin.py` expects (theHarvester's
JSON keys can change between versions), the plugin will raise a clear
`PluginExecutionError` rather than silently returning wrong data --
check the error message, inspect theHarvester's actual output JSON, and
adjust `_parse_output` accordingly.

## Troubleshooting

| Problem | Fix |
|---|---|
| `ModuleNotFoundError` on any import | Make sure the venv is activated (`source venv/bin/activate`) and you're running commands from the project root, not from inside `cli/` or `core/`. |
| `--help` crashes with a `make_metavar` TypeError | You have `click>=8.2` installed alongside `typer==0.12.5`. Run `pip install "click<8.2"`. |
| `shodan` always shows "unavailable" | `SHODAN_API_KEY` isn't set. Check `.env` exists (not just `.env.example`) and the key has no quotes/spaces around it. |
| `docker: permission denied` | Your user isn't in the `docker` group yet, or you haven't logged out/in since being added. Run `groups` to check. |
| `theharvester` plugin fails with "did not produce an output file" | The container likely crashed before writing JSON -- rerun with the Docker command from the plugin manually (copy the `cmd` list in `theharvester_plugin.py`) to see raw stderr. |
| SQLite "database is locked" | Only one process should write to `data/osint_lens.db` at a time; don't run two scans simultaneously against the same DB file. |

## Viva / cross-question prep

**"Why not just use SpiderFoot, it already does this?"**
SpiderFoot aggregates OSINT sources. This project's contribution on top of
aggregation is (1) a hand-designed common `Finding` schema that every
plugin -- regardless of whether it's a local mock, a Docker-isolated CLI
tool, or a web API -- normalizes into, and (2) an explainable, rule-based
correlation layer that flags specific cross-source combinations (e.g. an
open admin port plus harvested emails) rather than just listing raw
results per tool.

**"Why threads (`ThreadPoolExecutor`) and not `asyncio`?"**
The work is I/O-bound (waiting on network responses or subprocess/Docker
completion). Threads give real concurrency benefit for I/O-bound waiting
without asyncio's added complexity (`async`/`await` throughout every
plugin, an event loop). This was a deliberate simplicity trade-off given
the project timeline, and it's demonstrated by
`test_concurrent_execution_faster_than_sequential`, which proves two
1-second-sleep plugins finish in under 1.8s combined, not 2s+.

**"Why can't you just kill a plugin that hangs?"**
Python cannot forcibly terminate a running thread. The orchestrator's
`future.result(timeout=...)` stops *waiting* for a slow plugin and
reports it as `TIMEOUT`, but the thread may keep running in the
background. Real protection against a hang comes from each plugin's own
timeout (`requests(timeout=...)`, `subprocess.run(timeout=...)`) --
documented directly in the code comments in `core/orchestrator.py`.

**"Why SQLite, won't it not scale?"**
For a single-analyst CLI tool at this scope, SQLite avoids running a
database server entirely -- the whole database is one file. All SQL
access is isolated to `database/repository.py`; nothing else in the
codebase runs raw SQL, so swapping to Postgres later would be a
contained change, not a rewrite.

**"Why dataclasses instead of Pydantic?"**
Dataclasses are standard library (no added dependency) and the
validation logic that exists (`Finding.__post_init__`, `core/validators.py`,
`core/normalizer.py`) is hand-written and small enough to walk through
line by line in a viva, rather than pointing at a third-party library's
internals.

**"How do you prevent one plugin's crash from killing the whole scan?"**
`core/orchestrator.py`'s `_run_single_plugin()` wraps every plugin call in
try/except blocks for both expected failures (`PluginExecutionError`) and
literally any other exception type (a bare `except Exception`), always
returning a `PluginResult` object rather than letting an exception
propagate. `tests/unit/test_orchestrator.py::test_unexpected_exception_is_caught_not_propagated`
proves this by having a test plugin raise a raw `KeyError` and confirming
the scan still completes.

**"How do you handle secrets?"**
API keys live in a local `.env` file (never committed -- see
`.gitignore`), loaded via `python-dotenv` at startup, read with
`os.getenv()` inside each plugin. Never hardcoded, never logged, never
placed in report output.

**"Is this legal/ethical to run?"**
`core/validators.py::confirm_authorization()` requires an explicit
interactive confirmation before every scan (unless `--yes` is passed for
scripted contexts). This is a recorded friction step and acknowledgment,
not an access-control mechanism -- it cannot stop a determined bad actor,
and the README says so plainly rather than overclaiming what it does.
The correlation engine also deliberately avoids overclaiming: alerts use
language like "indicator that warrants verification," never "confirmed
vulnerability," per `core/correlator.py`'s docstring.

**"What's the difference between raw, parsed, normalized, and correlated data?"**
Raw = the tool's untouched original output (stored in `Finding.raw`).
Parsed = that raw output pulled apart into Python values inside the
plugin (only the plugin knows its own tool's shape). Normalized = the
parsed value wrapped as a `Finding` object and sanity-checked/deduped by
`core/normalizer.py` (which knows nothing about any specific tool).
Correlated = an `Alert` produced by `core/correlator.py` combining
multiple normalized findings via an explicit rule.

## Known limitations

- `theharvester` plugin is unverified end-to-end (no Docker in the build
  environment) -- test it yourself before your demo.
- `shodan` plugin's live API call is unverified (no key configured here)
  -- test it yourself with a real key before your demo.
- Correlation rules are intentionally simple (3 rules) and rule-based --
  no machine learning, by design.
- Target validation (`core/validators.py`) is a basic format sanity
  check, not a security boundary.
- Single-writer SQLite -- not designed for concurrent multi-user access.

## Next steps for future development

- Add more correlation rules as more plugins are added.
- Add a `--output json` flag to `scan` for machine-readable output.
- Add integration tests that exercise the real Shodan API and a real
  Docker container (currently only unit-tested with mocks/isolation).
- Consider a PDF export option built on top of the existing HTML report.
