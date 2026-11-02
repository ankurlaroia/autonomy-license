"""Licence status registry and warning state (DynamoDB on AWS; SQLite locally).

Status values: active | suspended | revoked. Revocation is one write and is read on every
tool call by Path B, so it takes effect immediately (spec 9.4).
"""
from __future__ import annotations

import time

from common.store import Store


class Registry:
    def __init__(self, store: Store):
        self.s = store

    def put(self, jti: str, token: str, status: str = "active"):
        now = int(time.time())
        self.s.x("INSERT OR REPLACE INTO licences VALUES (?,?,?,?,?,?)", (jti, token, status, now, now, ""))

    def status(self, jti: str) -> str:
        r = self.s.q("SELECT status FROM licences WHERE jti=?", (jti,))
        return r[0][0] if r else "unknown"

    def set_status(self, jti: str, status: str, note: str = ""):
        assert status in ("active", "suspended", "revoked")
        self.s.x("UPDATE licences SET status=?, updated_at=?, note=? WHERE jti=?", (status, int(time.time()), note, jti))

    def current(self) -> tuple[str, str] | None:
        """Most recent licence (jti, token), whatever its status."""
        r = self.s.q("SELECT jti, token FROM licences ORDER BY issued_at DESC, rowid DESC LIMIT 1")
        return (r[0][0], r[0][1]) if r else None

    # ---- warnings received by an operator (masked categories) ----
    def warned_categories(self, receiver: str, now: int | None = None) -> set[str]:
        now = now or int(time.time())
        rows = self.s.q("SELECT category FROM warnings WHERE receiver=? AND status='active' AND exp>?",
                        (receiver, now))
        return {r[0] for r in rows}
