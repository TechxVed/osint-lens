"""
database/schema.py

Defines the SQLite table structure. Three tables, deliberately kept flat
and easy to explain:

  scans
    One row per `scan` command invocation. Holds the target and when it
    started. `id` is the primary key everything else hangs off.

  findings
    One row per normalized Finding. `scan_id` is a FOREIGN KEY back to
    scans.id -- this is how we know which scan a finding belongs to, and
    it's how `history`/`report` commands pull the right data for a given
    scan without scanning the whole table.

  alerts
    One row per correlation Alert produced for a scan. Also FOREIGN KEY'd
    to scans.id. Kept separate from findings because an alert references
    MULTIPLE findings as evidence -- we store that evidence as a JSON-
    encoded list of finding ids in `evidence_finding_ids`, which is a
    deliberate simplification (a proper many-to-many join table would be
    "more correct" relationally, but for this project's scale a JSON
    column is genuinely simpler to explain and query, and I can defend
    that trade-off directly if asked).

WHY SQLITE: no server process to install/run/manage, the whole database
is one file (data/osint_lens.db), and Python's `sqlite3` module is
built into the standard library -- zero extra dependencies. For a
single-analyst tool at this scale, that's a better fit than running
Postgres. If this needed to become a multi-user product later, the fact
that all database access goes through database/repository.py (nothing
else touches SQL directly) means swapping the backend is a contained
change, not a rewrite.
"""

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    started_at TEXT NOT NULL,
    modules_requested TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS plugin_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    plugin_name TEXT NOT NULL,
    status TEXT NOT NULL,
    error_message TEXT,
    duration_seconds REAL,
    FOREIGN KEY (scan_id) REFERENCES scans (id)
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    source TEXT NOT NULL,
    target TEXT NOT NULL,
    data_type TEXT NOT NULL,
    value TEXT NOT NULL,
    confidence REAL NOT NULL,
    metadata_json TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans (id)
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    rule_name TEXT NOT NULL,
    description TEXT NOT NULL,
    rationale TEXT NOT NULL,
    evidence_finding_ids TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans (id)
);
"""
