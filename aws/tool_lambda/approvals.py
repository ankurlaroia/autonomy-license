"""Human approvals: genuine, authorised, unexpired (10 min), single-use and bound to a digest of the
exact incident, action, cells and parameters. Never overrides a hard rule (spec 10.5)."""
from __future__ import annotations

import hashlib
import json
import time
import uuid

APPROVER_ROLES = {"noc-engineer"}
TTL_S = 600


def action_digest(incident_id: str, action: str, cells: list[str], params: dict | None = None) -> str:
    blob = json.dumps({"incident": incident_id, "action": action, "cells": sorted(set(cells)),
                       "params": params or {}}, sort_keys=True).encode()
    return "sha256:" + hashlib.sha256(blob).hexdigest()


def verify_approval(record: dict | None, *, digest: str, approver_roles: set[str] = APPROVER_ROLES,
                    consumed: set[str] | None = None, now: int | None = None) -> None:
    now = now or int(time.time())
    if not record:
        raise PermissionError("no approval record")
    if record.get("consumed") or (consumed is not None and record["approval_id"] in consumed):
        raise PermissionError("approval already used")
    if record["decision"] != "approved" or record["role"] not in approver_roles:
        raise PermissionError("approval not granted by an authorised engineer")
    if now > record["expires_at"]:
        raise PermissionError("approval expired")
    if record["action_digest"] != digest:
        raise PermissionError("approval does not match this exact action and parameters")


class Approvals:
    def __init__(self, store):
        self.s = store

    def request(self, incident_id, action, cells, reason, params=None) -> str:
        aid = "APR-" + uuid.uuid4().hex[:10]
        now = int(time.time())
        self.s.x("INSERT INTO approvals (approval_id, incident_id, action_digest, role, decided_by, decision, "
                 "expires_at, created_at, consumed, request) VALUES (?,?,?,?,?,?,?,?,?,?)",
                 (aid, incident_id, action_digest(incident_id, action, cells, params), "", "", "pending",
                  0, now, 0, json.dumps({"action": action, "cells": sorted(set(cells)), "reason": reason,
                                         "params": params or {}})))
        return aid

    def decide(self, approval_id, engineer, role="noc-engineer", decision="approved"):
        self.s.x("UPDATE approvals SET decision=?, decided_by=?, role=?, expires_at=? WHERE approval_id=?",
                 (decision, engineer, role, int(time.time()) + TTL_S, approval_id))

    def get(self, approval_id) -> dict | None:
        r = self.s.q("SELECT approval_id, incident_id, action_digest, role, decided_by, decision, expires_at, "
                     "created_at, consumed, request FROM approvals WHERE approval_id=?", (approval_id,))
        if not r:
            return None
        k = ["approval_id", "incident_id", "action_digest", "role", "decided_by", "decision", "expires_at",
             "created_at", "consumed", "request"]
        d = dict(zip(k, r[0]))
        d["request"] = json.loads(d["request"])
        return d

    def consume(self, approval_id):
        self.s.x("UPDATE approvals SET consumed=1 WHERE approval_id=?", (approval_id,))

    def pending(self):
        r = self.s.q("SELECT approval_id FROM approvals WHERE decision='pending' ORDER BY created_at")
        return [self.get(x[0]) for x in r]
