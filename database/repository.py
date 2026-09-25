"""
database/repository.py

Every SQL statement in the entire project lives in this file. This is a
deliberate boundary: cli/, core/, and plugins/ never import sqlite3
directly. If you ever wanted to swap SQLite for another database, this
is the only file that would need to change.

SECURITY NOTE: every query below uses '?' placeholders with a separate
parameters tuple (parameterized queries), never Python f-strings to
build SQL. This is what prevents SQL injection -- the target string (or
any other user-supplied value) is never concatenated directly into a
SQL statement.
"""

import json
import sqlite3
from datetime import datetime, timezone

from core.models import Finding, Alert, PluginResult


def create_scan(conn: sqlite3.Connection, target: str, modules_requested: list[str]) -> int:
    cursor = conn.execute(
        "INSERT INTO scans (target, started_at, modules_requested) VALUES (?, ?, ?)",
        (target, datetime.now(timezone.utc).isoformat(), ",".join(modules_requested)),
    )
    conn.commit()
    return cursor.lastrowid


def save_plugin_result(conn: sqlite3.Connection, scan_id: int, result: PluginResult) -> None:
    conn.execute(
        """INSERT INTO plugin_runs
           (scan_id, plugin_name, status, error_message, duration_seconds)
           VALUES (?, ?, ?, ?, ?)""",
        (scan_id, result.plugin_name, result.status.value,
         result.error_message, result.duration_seconds),
    )
    conn.commit()


def save_findings(conn: sqlite3.Connection, scan_id: int, findings: list[Finding]) -> dict:
    """Returns a mapping of (source, value) -> inserted row id, so the
    correlator's Alert.evidence (Finding objects) can be translated into
    finding ids for storage in the alerts table.
    """
    id_map = {}
    for f in findings:
        cursor = conn.execute(
            """INSERT INTO findings
               (scan_id, source, target, data_type, value, confidence, metadata_json, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, f.source, f.target, f.data_type.value, f.value,
             f.confidence, json.dumps(f.metadata), f.timestamp.isoformat()),
        )
        id_map[(f.source, f.value)] = cursor.lastrowid
    conn.commit()
    return id_map


def save_alerts(conn: sqlite3.Connection, scan_id: int, alerts: list[Alert],
                 finding_id_map: dict) -> None:
    for a in alerts:
        evidence_ids = [
            finding_id_map.get((f.source, f.value)) for f in a.evidence
        ]
        evidence_ids = [i for i in evidence_ids if i is not None]
        conn.execute(
            """INSERT INTO alerts
               (scan_id, rule_name, description, rationale, evidence_finding_ids, timestamp)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (scan_id, a.rule_name, a.description, a.rationale,
             json.dumps(evidence_ids), a.timestamp.isoformat()),
        )
    conn.commit()


def get_recent_scans(conn: sqlite3.Connection, limit: int = 10) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT id, target, started_at, modules_requested FROM scans "
        "ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()


def get_scan_detail(conn: sqlite3.Connection, scan_id: int) -> dict:
    scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if scan is None:
        return {}
    plugin_runs = conn.execute(
        "SELECT * FROM plugin_runs WHERE scan_id = ?", (scan_id,)
    ).fetchall()
    findings = conn.execute(
        "SELECT * FROM findings WHERE scan_id = ?", (scan_id,)
    ).fetchall()
    alerts = conn.execute(
        "SELECT * FROM alerts WHERE scan_id = ?", (scan_id,)
    ).fetchall()
    return {
        "scan": dict(scan),
        "plugin_runs": [dict(r) for r in plugin_runs],
        "findings": [dict(r) for r in findings],
        "alerts": [dict(r) for r in alerts],
    }
