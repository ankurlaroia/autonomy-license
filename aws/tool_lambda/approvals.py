"""Human approvals: genuine, authorised, unexpired (10 min), single-use and bound to a digest of the
exact incident, action, cells and parameters. Never overrides a hard rule (spec 10.5).

Local: SQLite. On AWS: DynamoDB <prefix>-approvals, so the request, the decision and the change can land in
different Lambda containers. Both give the same guarantees: a request can be decided once, only while it is
fresh, and an approval can be spent once (conditional writes on AWS).
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid

APPROVER_ROLES = {"noc-engineer"}
DECISIONS = ("approved", "denied")
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


def _request_blob(action, cells, reason, params) -> str:
    return json.dumps({"action": action, "cells": sorted(set(cells)), "reason": reason, "params": params or {}})


class Approvals:
    def __init__(self, store):
        self.s = store

    def request(self, incident_id, action, cells, reason, params=None) -> str:
        aid = "APR-" + uuid.uuid4().hex[:10]
        now = int(time.time())
        self.s.x("INSERT INTO approvals (approval_id, incident_id, action_digest, role, decided_by, decision, "
                 "expires_at, created_at, consumed, request) VALUES (?,?,?,?,?,?,?,?,?,?)",
                 (aid, incident_id, action_digest(incident_id, action, cells, params), "", "", "pending",
                  0, now, 0, _request_blob(action, cells, reason, params)))
        return aid

    def decide(self, approval_id, engineer, role="noc-engineer", decision="approved"):
        now = int(time.time())
        with self.s._lock:
            n = self.s.db.execute("UPDATE approvals SET decision=?, decided_by=?, role=?, expires_at=? "
                                  "WHERE approval_id=? AND decision='pending' AND created_at>=?",
                                  (decision, engineer, role, now + TTL_S, approval_id, now - TTL_S)).rowcount
        if n != 1:
            raise PermissionError("approval is not waiting for a decision (unknown, already decided or stale)")

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
        with self.s._lock:
            n = self.s.db.execute("UPDATE approvals SET consumed=1 WHERE approval_id=? AND consumed=0",
                                  (approval_id,)).rowcount
        if n != 1:
            raise PermissionError("approval already used")

    def pending(self):
        r = self.s.q("SELECT approval_id FROM approvals WHERE decision='pending' ORDER BY created_at")
        return [self.get(x[0]) for x in r]


class DynamoApprovals:
    """The same record and the same rules in a table every Lambda shares (pk approval_id)."""

    def __init__(self, client, prefix: str = "al"):
        self.c, self.table = client, f"{prefix}-approvals"

    def request(self, incident_id, action, cells, reason, params=None) -> str:
        aid = "APR-" + uuid.uuid4().hex[:10]
        self.c.put_item(TableName=self.table, ConditionExpression="attribute_not_exists(approval_id)", Item={
            "approval_id": {"S": aid}, "incident_id": {"S": incident_id},
            "action_digest": {"S": action_digest(incident_id, action, cells, params)},
            "role": {"S": ""}, "decided_by": {"S": ""}, "decision": {"S": "pending"},
            "expires_at": {"N": "0"}, "created_at": {"N": str(int(time.time()))}, "consumed": {"N": "0"},
            "request": {"S": _request_blob(action, cells, reason, params)}})
        return aid

    def _update(self, approval_id, expr, cond, values, names, why):
        try:
            self.c.update_item(TableName=self.table, Key={"approval_id": {"S": approval_id}}, UpdateExpression=expr,
                               ConditionExpression=cond, ExpressionAttributeValues=values,
                               ExpressionAttributeNames=names)
        except Exception as e:
            if "ConditionalCheckFailed" in type(e).__name__ or "ConditionalCheckFailed" in str(e):
                raise PermissionError(why) from None
            raise

    def decide(self, approval_id, engineer, role="noc-engineer", decision="approved"):
        now = int(time.time())
        self._update(approval_id, "SET #d = :d, decided_by = :by, #r = :r, expires_at = :e",
                     "#d = :p AND created_at >= :oldest",
                     {":d": {"S": decision}, ":by": {"S": engineer}, ":r": {"S": role},
                      ":e": {"N": str(now + TTL_S)}, ":p": {"S": "pending"}, ":oldest": {"N": str(now - TTL_S)}},
                     {"#d": "decision", "#r": "role"},
                     "approval is not waiting for a decision (unknown, already decided or stale)")

    @staticmethod
    def _plain(item: dict) -> dict:
        d = {k: (int(v["N"]) if "N" in v else v["S"]) for k, v in item.items()}
        d["request"] = json.loads(d["request"])
        return d

    def get(self, approval_id) -> dict | None:
        if not approval_id:         # DynamoDB rejects an empty key; no id means no approval
            return None
        r = self.c.get_item(TableName=self.table, Key={"approval_id": {"S": approval_id}}, ConsistentRead=True)
        return self._plain(r["Item"]) if r.get("Item") else None

    def consume(self, approval_id):
        self._update(approval_id, "SET #c = :one", "#c = :zero AND #d = :a",      # consumed is a reserved word
                     {":one": {"N": "1"}, ":zero": {"N": "0"}, ":a": {"S": "approved"}},
                     {"#c": "consumed", "#d": "decision"}, "approval already used")

    def pending(self):
        out, kw = [], {"TableName": self.table, "FilterExpression": "#d = :p", "ConsistentRead": True,
                       "ExpressionAttributeNames": {"#d": "decision"},
                       "ExpressionAttributeValues": {":p": {"S": "pending"}}}
        while True:
            r = self.c.scan(**kw)
            out += [self._plain(i) for i in r.get("Items", [])]
            if "LastEvaluatedKey" not in r:
                return sorted(out, key=lambda d: d["created_at"])
            kw["ExclusiveStartKey"] = r["LastEvaluatedKey"]
