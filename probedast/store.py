"""Findings store. SQLite by default (zero-dependency, matches the schema in
sql/schema_sqlite.sql 1:1 with sql/schema.sql), with the same interface ready
to point at PostgreSQL in production — see Section 3 of the design doc for
why JSONB/TEXT evidence and a UNIQUE(scan_id, signature) endpoint constraint
matter (idempotent endpoint insertion, same idea as ON CONFLICT DO NOTHING).
"""
from __future__ import annotations
import json
import os
import sqlite3
import threading
from datetime import datetime, timezone

from .models import Endpoint, Candidate, new_id

SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "..", "sql", "schema_sqlite.sql")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, db_path: str = "probedast.db"):
        self.db_path = db_path
        self._local = threading.local()
        self._init_schema()

    @property
    def conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn"):
            self._local.conn = sqlite3.connect(self.db_path)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA foreign_keys = ON")
        return self._local.conn

    def _init_schema(self):
        conn = sqlite3.connect(self.db_path)
        try:
            with open(SCHEMA_PATH) as f:
                conn.executescript(f.read())
            conn.commit()
        finally:
            conn.close()

    # --- scans ---------------------------------------------------------
    def create_scan(self, scan_id: str, target: str, scope: dict) -> None:
        self.conn.execute(
            "INSERT INTO scans (scan_id, target, scope, status, started_at) VALUES (?,?,?,?,?)",
            (scan_id, target, json.dumps(scope), "RUNNING", _now()))
        self.conn.commit()

    def set_scan_status(self, scan_id: str, status: str, finished: bool = False) -> None:
        if finished:
            self.conn.execute("UPDATE scans SET status=?, finished_at=? WHERE scan_id=?",
                               (status, _now(), scan_id))
        else:
            self.conn.execute("UPDATE scans SET status=? WHERE scan_id=?", (status, scan_id))
        self.conn.commit()

    def get_scan(self, scan_id: str) -> dict | None:
        row = self.conn.execute("SELECT * FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
        return dict(row) if row else None

    def list_scans(self) -> list[dict]:
        rows = self.conn.execute("SELECT * FROM scans ORDER BY started_at DESC").fetchall()
        return [dict(r) for r in rows]

    # --- endpoints -------------------------------------------------------
    def upsert_endpoint(self, ep: Endpoint) -> str:
        """Idempotent on (scan_id, signature) — re-discovering the same
        structural endpoint is a no-op, mirroring UNIQUE + ON CONFLICT."""
        existing = self.conn.execute(
            "SELECT endpoint_id FROM endpoints WHERE scan_id=? AND signature=?",
            (ep.scan_id, ep.signature)).fetchone()
        if existing:
            return existing["endpoint_id"]
        eid = ep.endpoint_id or new_id()
        self.conn.execute(
            "INSERT INTO endpoints (endpoint_id, scan_id, method, path_template, params, "
            "auth_required, signature) VALUES (?,?,?,?,?,?,?)",
            (eid, ep.scan_id, ep.method, ep.path_template,
             json.dumps([p.to_dict() for p in ep.params]), int(ep.auth_required), ep.signature))
        self.conn.commit()
        return eid

    def get_endpoint(self, endpoint_id: str) -> dict | None:
        row = self.conn.execute("SELECT * FROM endpoints WHERE endpoint_id=?", (endpoint_id,)).fetchone()
        return dict(row) if row else None

    def list_endpoints(self, scan_id: str) -> list[dict]:
        rows = self.conn.execute("SELECT * FROM endpoints WHERE scan_id=?", (scan_id,)).fetchall()
        return [dict(r) for r in rows]

    # --- findings --------------------------------------------------------
    def record_finding(self, scan_id: str, endpoint_id: str, vuln_type: str, param: str | None,
                        severity: str, confidence: float, status: str, evidence: dict) -> str:
        """Writes both CONFIRMED and REJECTED rows. REJECTED rows are kept —
        they're what the false-positive ablation in benchmark/ counts against."""
        fid = new_id()
        self.conn.execute(
            "INSERT INTO findings (finding_id, scan_id, endpoint_id, vuln_type, param, severity, "
            "confidence, status, evidence, found_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (fid, scan_id, endpoint_id, vuln_type, param, severity, confidence, status,
             json.dumps(evidence), _now()))
        self.conn.commit()
        return fid

    def list_findings(self, scan_id: str, status: str | None = None) -> list[dict]:
        if status:
            rows = self.conn.execute("SELECT * FROM findings WHERE scan_id=? AND status=? "
                                      "ORDER BY found_at", (scan_id, status)).fetchall()
        else:
            rows = self.conn.execute("SELECT * FROM findings WHERE scan_id=? ORDER BY found_at",
                                      (scan_id,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["evidence"] = json.loads(d["evidence"])
            out.append(d)
        return out

    def counts(self, scan_id: str) -> dict:
        rows = self.conn.execute(
            "SELECT status, COUNT(*) c FROM findings WHERE scan_id=? GROUP BY status",
            (scan_id,)).fetchall()
        out = {"CONFIRMED": 0, "REJECTED": 0}
        for r in rows:
            out[r["status"]] = r["c"]
        return out
