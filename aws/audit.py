"""Lasting audit records on AWS. Every decision is written to two places that must agree:

  DynamoDB  <prefix>-audit, pk run_id, sk "<UTC ISO time with ms>#<source>#<rec_id>"
  CloudWatch  one JSON line {"al_audit": 1, ...} in the writing Lambda's log group

so a judge can answer "show me the record for this item in this window" with read-only calls
(aws/infra/judge.py), and compare the two copies and their AWS timestamps.

The run id comes from the Lambda environment (AL_RUN_ID), which aws/infra/judged_run.py sets only after the
run's declaration is in S3; it is never taken from the caller. Calls outside a declared run are recorded under
"undeclared". The Lambda role may only PutItem on this table (append-only: no update, no delete), and a write
that fails raises, so a caller that cannot leave its record does not act (fail closed).

Records carry TL- incident ids (a SHA-256 of the question, no TeleLogs text) so a judge can name an item;
the local SQLite audit keeps its salted hashes (test T28).
"""
from __future__ import annotations

import json
import os
import time
import uuid

UNDECLARED = "undeclared"
MARK = "al_audit"


def iso_ms(t: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + f".{int(t * 1000) % 1000:03d}Z"


def audit_item(run_id: str, source: str, kind: str, record: dict, item: str | None = None,
               t: float | None = None, rec_id: str | None = None) -> dict:
    """One DynamoDB item (typed). The sort key starts with the time, so a window is a key range."""
    t = time.time() if t is None else t
    rec_id = rec_id or uuid.uuid4().hex[:12]
    it = {"run_id": {"S": run_id}, "sk": {"S": f"{iso_ms(t)}#{source}#{rec_id}"}, "ts": {"S": iso_ms(t)},
          "source": {"S": source}, "kind": {"S": kind}, "rec_id": {"S": rec_id},
          "record": {"S": json.dumps(record, sort_keys=True, default=str)}}
    if item:
        it["item"] = {"S": item}
    return it


def plain(it: dict) -> dict:
    """A typed item as plain strings, with the record parsed."""
    out = {k: v["S"] for k, v in it.items() if "S" in v}
    out["record"] = json.loads(out.get("record") or "{}")
    return out


def log_line(it: dict) -> str:
    return json.dumps({MARK: 1, **{k: v["S"] for k, v in it.items()}}, sort_keys=True)


class AuditWriter:
    def __init__(self, client, table: str, run_id: str, source: str, out=print):
        self.c, self.table, self.run_id, self.source, self.out = client, table, run_id, source, out

    def write(self, kind: str, record: dict, item: str | None = None) -> dict:
        it = audit_item(self.run_id, self.source, kind, record, item)
        self.c.put_item(TableName=self.table, Item=it, ConditionExpression="attribute_not_exists(sk)")
        self.out(log_line(it))
        return it


def writer_from_env(source: str, env=None, client=None) -> AuditWriter | None:
    """None when AL_AUDIT_TABLE is unset (local runs and tests keep SQLite only)."""
    env = os.environ if env is None else env
    table = env.get("AL_AUDIT_TABLE")
    if not table:
        return None
    if client is None:
        import boto3
        client = boto3.client("dynamodb")
    return AuditWriter(client, table, env.get("AL_RUN_ID") or UNDECLARED, source)


def attach(store, writer: AuditWriter | None, extra: dict | None = None):
    """Send every Store.audit() record to the lasting writer as well, with `extra` (the trace id) added."""
    if writer is None:
        store.sink = None
        return
    store.sink = lambda kind, record, operator, incident_id: writer.write(
        kind, {**{k: v for k, v in record.items() if k != "incident_id"}, "operator": operator, **(extra or {})},
        incident_id)
