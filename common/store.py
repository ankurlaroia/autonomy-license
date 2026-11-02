"""Local state store (SQLite). Stands in for the DynamoDB tables used on AWS:
licences (status registry), warnings, approvals, audit, simulator cells.

The audit table is append-only; incident ids are stored as salted SHA-256 hashes.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time

DEFAULT_DB = os.environ.get("AL_DB", os.path.join(os.path.dirname(os.path.dirname(__file__)), "state", "al.db"))
AUDIT_SALT = os.environ.get("AL_AUDIT_SALT", "demo-salt-change-me")

SCHEMA = """
CREATE TABLE IF NOT EXISTS licences (jti TEXT PRIMARY KEY, token TEXT, status TEXT, issued_at INTEGER,
                                     updated_at INTEGER, note TEXT);
CREATE TABLE IF NOT EXISTS warnings (nonce TEXT PRIMARY KEY, issuer TEXT, receiver TEXT, category TEXT,
                                     signal TEXT, iat INTEGER, exp INTEGER, raw TEXT, status TEXT);
CREATE TABLE IF NOT EXISTS approvals (approval_id TEXT PRIMARY KEY, incident_id TEXT, action_digest TEXT,
                                      role TEXT, decided_by TEXT, decision TEXT, expires_at INTEGER,
                                      created_at INTEGER, consumed INTEGER DEFAULT 0, request TEXT);
CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, operator TEXT,
                                  incident_hash TEXT, kind TEXT, record TEXT);
CREATE TABLE IF NOT EXISTS cells (incident_id TEXT, cell_id TEXT, params TEXT, version INTEGER,
                                  PRIMARY KEY (incident_id, cell_id));
CREATE TABLE IF NOT EXISTS sim_actions (action_id TEXT PRIMARY KEY, incident_id TEXT, action TEXT,
                                        cells TEXT, before TEXT, after TEXT, resolved INTEGER, ts REAL);
CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS changed_cells (incident_id TEXT, cell_id TEXT, PRIMARY KEY (incident_id, cell_id));
"""


class Store:
    _lock = threading.RLock()
    sink = None     # optional callable(kind, record, operator, incident_id); on AWS, the lasting audit (aws/audit.py)

    def __init__(self, path: str = DEFAULT_DB):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(SCHEMA)

    # ---------- generic ----------
    def q(self, sql, args=()):
        with self._lock:
            return self.db.execute(sql, args).fetchall()

    def x(self, sql, args=()):
        with self._lock:
            self.db.execute(sql, args)

    def kv_set(self, k, v):
        self.x("INSERT OR REPLACE INTO kv VALUES (?,?)", (k, json.dumps(v)))

    def kv_get(self, k, default=None):
        r = self.q("SELECT v FROM kv WHERE k=?", (k,))
        return json.loads(r[0][0]) if r else default

    def reset(self):
        with self._lock:
            for t in ("licences", "warnings", "approvals", "audit", "cells", "sim_actions", "kv", "changed_cells"):
                self.db.execute(f"DELETE FROM {t}")

    # ---------- audit (append-only) ----------
    @staticmethod
    def hash_incident(incident_id: str) -> str:
        return "sha256:" + hashlib.sha256((AUDIT_SALT + incident_id).encode()).hexdigest()[:24]

    def audit(self, kind: str, record: dict, operator: str = "A", incident_id: str | None = None):
        rec = dict(record)
        if "incident_id" in rec:            # never export raw incident ids (test T28)
            rec["incident_hash"] = self.hash_incident(rec.pop("incident_id"))
        ih = self.hash_incident(incident_id) if incident_id else rec.get("incident_hash")
        self.x("INSERT INTO audit (ts, operator, incident_hash, kind, record) VALUES (?,?,?,?,?)",
               (time.time(), operator, ih, kind, json.dumps(rec, default=str)))
        if self.sink:                       # raises if the lasting copy cannot be written
            self.sink(kind, record, operator, incident_id or record.get("incident_id"))

    def audit_tail(self, n=50, kinds=None):
        """The last n audit records, newest first; `kinds` limits them to those record kinds."""
        where, args = "", ()
        if kinds:
            where, args = f"WHERE kind IN ({','.join('?' * len(kinds))}) ", tuple(kinds)
        rows = self.q(f"SELECT seq, ts, operator, incident_hash, kind, record FROM audit {where}ORDER BY seq DESC LIMIT ?",
                      (*args, n))
        out = []
        for r in rows:
            d = json.loads(r[5])
            d.update(seq=r[0], ts=r[1], operator=r[2], incident_hash=r[3], kind=r[4])
            out.append(d)
        return out
