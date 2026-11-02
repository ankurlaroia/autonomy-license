"""The console's Live view: real calls to the deployed AWS stack, and what each service recorded, as it happens.

Off unless AL_LIVE=1, because it acts with this machine's AWS sign-in: the hosted console never sets it. Live calls
are recorded under the run id "undeclared", so they can never be mistaken for a declared run. Only ids, decisions and
counts reach the browser, plus the specialist's note, which is model text about server facts: never tokens, and never
cell values (TeleLogs data). The network behind the tool is still the simulator.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import tempfile
import threading
import time
import uuid

from aws.audit import UNDECLARED, audit_item, iso_ms, plain
from aws.evidence import item_detail
from aws.infra.attacks_live import tamper, verdict
from aws.infra.deploy import AUDIT_TABLE, DDB_PREFIX, models_command
from aws.infra.judged_run import LOG_GROUPS, TracedClient
from aws.infra.pause import FUNCTIONS, status as stack_status
from aws.infra.smoke import outcome, pick_incidents
from aws.infra.team import TASK, pick_case
from aws.tool_lambda.approvals import DynamoApprovals
from aws.tool_lambda.ledger import DynamoLedger
from aws.tool_lambda.models import CLASSIFIER, DynamoModels
from common.catalogue import BLAST_RADIUS
from license.registry_ddb import DynamoRegistry

KINDS = ("small", "big", "split", "tampered")
TRACE = re.compile(r"^live-[0-9a-f]{12}$")
KEEP = 50       # traces remembered for polling

# What each hop may show. A whitelist: anything else in a record stays out of the browser.
HOP_FIELDS = {"gateway_request": ("mode", "action", "cell_count", "category", "score_ok", "licence_ok", "dropped"),
              "tool_call": ("tool", "role", "mode", "action"),
              "remediation_applied": ("action", "mode", "action_id", "licence_jti", "threshold", "resolved"),
              "tool_refused": ("action", "mode", "reason"),
              "agent_call": ("to_agent", "from_role", "model", "guardrail_input", "guardrail_output", "next"),
              "approval_requested": ("approval_id", "action"),
              "approval_decided": ("approval_id", "decision", "decided_by")}


def explain(e: Exception) -> str:
    """A sign-in or AWS failure in words a person can act on, without echoing request details."""
    name, text = type(e).__name__, str(e)
    if any(x in name + text for x in ("ExpiredToken", "NoCredentials", "SSOToken", "TokenRetrieval", "Unauthorized",
                                      "UnrecognizedClient", "InvalidClientTokenId", "expired", "reauthenticate")):
        return "AWS sign-in has expired or is missing. Run aws login, then try again."
    return f"AWS call failed ({name})."


def hop(it: dict) -> dict:
    """One audit record as the browser sees it."""
    p = plain(it)
    rec = p["record"]
    fields = {k: rec[k] for k in HOP_FIELDS.get(p.get("kind"), ()) if k in rec}
    if "cells" in rec:
        fields["cells"] = len(rec["cells"])
    return {"rec_id": p.get("rec_id"), "source": p.get("source"), "kind": p.get("kind"), "ts": p.get("ts"), "fields": fields}


def gate_decision(reply: dict, recorded: list[dict]) -> dict:
    """The Cedar step leaves no record of its own: a deny is in the Gateway's reply, a permit shows as the tool running.
    Says which, so the panel never presents an inference as a record."""
    http = (reply.get("error") or {}).get("http")
    if http in (401, 403):
        return {"decision": "NOT_REACHED", "basis": f"HTTP {http} from the Gateway, before policy"}
    o = outcome(reply)
    if o["decision"] == "DENY":
        m = re.search(r"\bF\d+\b|\b[A-Z]\d+-", str(o["detail"]))
        return {"decision": "FORBID", "policy": m.group(0).rstrip("-") if m else None, "basis": "the Gateway's reply"}
    if any(h["source"] == "tool" for h in recorded):
        return {"decision": "PERMIT", "basis": "inferred: the tool Lambda ran"}
    return {"decision": "UNKNOWN", "basis": "no tool record yet"}


def verdict_words(o: dict) -> str:
    return "the Gateway's rules refused it." if o["decision"] == "DENY" else f"the tool refused it ({item_detail(o)})."


def plan(kind: str, small: tuple, big: tuple) -> dict:
    """The arguments for one live call. `setup` is the allowed first part of a split change."""
    if kind == "small":
        inc, act = small
        return {"args": {"incident_id": inc["incident_id"], "action": act, "cells": [c["cell_id"] for c in inc["cells"]][:2],
                         "mode": "autonomous"}}
    inc, act = big
    cells = [c["cell_id"] for c in inc["cells"]]
    base = {"incident_id": inc["incident_id"], "action": act, "mode": "autonomous"}
    if kind == "big":
        return {"args": {**base, "cells": cells, "cell_count": 2}}      # the lie: all cells, claims two
    if kind == "split":
        return {"setup": {**base, "cells": cells[:BLAST_RADIUS]}, "args": {**base, "cells": cells[BLAST_RADIUS:BLAST_RADIUS + 2]}}
    if kind == "tampered":
        inc, act = small
        return {"token": "tampered", "args": {"incident_id": inc["incident_id"], "action": act,
                                              "cells": [c["cell_id"] for c in inc["cells"]][:2], "mode": "autonomous"}}
    raise ValueError(kind)


class Live:     # the AWS calls themselves are covered by the live check in GUIDE.md
    def __init__(self, root: str, profile: str | None = None, session=None, client=None):
        self.root, self.profile, self.s, self._client = root, profile, session, client
        self.lock = threading.Lock()
        self.traces: dict[str, float] = {}
        self.approval_traces: dict[str, str] = {}
        self._picked = None

    def state(self) -> dict | None:
        try:
            return json.load(open(os.path.join(self.root, "dist", "aws_state.json")))
        except (OSError, ValueError):
            return None

    def session(self, st: dict):
        if self.s is None:
            import boto3
            self.s = boto3.session.Session(profile_name=self.profile, region_name=st["region"])
        return self.s

    def status(self) -> dict:
        st = self.state()
        if not st or not st.get("gateway_url"):
            return {"ready": False, "reason": "No stack deployed from this machine yet."}
        out = {"ready": False, "account": st.get("account"), "region": st.get("region"), "policy_mode": st.get("policy_mode"),
               "checked_at": iso_ms(time.time())}
        try:
            s = self.session(st)
            fns = stack_status(s.client("lambda"))
            out["stack"] = "running" if all(v == "running" for v in fns.values()) else "paused"
            cur = DynamoRegistry(s.client("dynamodb"), DDB_PREFIX)
            top = cur.current()
            out["licence"] = {"jti": top[0], "status": cur.status(top[0])} if top else None
            out["models"] = DynamoModels(s.client("dynamodb"), DDB_PREFIX).status(CLASSIFIER)
            out["ready"] = True
        except Exception as e:      # the panel explains; it never pretends
            self.s = None
            out["reason"] = explain(e)
        return out

    def _need_running(self, st: dict):
        if stack_status(self.session(st).client("lambda")) != {f: "running" for f in FUNCTIONS}:
            raise LiveRefused("The stack is paused. Turn it on first.")

    def _incidents(self):
        if self._picked is None:
            bundle = os.path.join(self.root, "dist", "bundle")
            info = json.load(open(os.path.join(bundle, "stub_info.json")))
            self._picked = pick_incidents(bundle, info["threshold"])
        return self._picked

    def _gateway(self, st: dict):
        if self._client is None:
            self._client = TracedClient(st, self.profile)
        return self._client

    def _new_trace(self) -> tuple[str, float]:
        trace, t0 = f"live-{uuid.uuid4().hex[:12]}", time.time()
        self.traces[trace] = t0
        while len(self.traces) > KEEP:
            self.traces.pop(next(iter(self.traces)))
        return trace, t0

    def _approvals(self, st: dict):
        return DynamoApprovals(self.session(st).client("dynamodb"), DDB_PREFIX)

    def _case(self, st: dict) -> tuple[str, str, list[str]]:
        from model.scorer import ScoreCache
        try:
            order = json.load(open(os.path.join(self.root, "state", "data", "splits.json")))["heldout_order"]
        except (OSError, ValueError):
            raise LiveRefused("The frozen data is not on this machine.") from None
        bundle = os.path.join(self.root, "dist", "bundle")
        return pick_case(bundle, order, ScoreCache(os.path.join(bundle, "data", "scores.jsonl")),
                         DynamoLedger(self.session(st).client("dynamodb"), DDB_PREFIX))

    def team_ask(self) -> dict:
        """The lead asks the specialist for a note and queues the change for a person. Nothing changes until one decides."""
        st = self.state()
        if not st:
            raise LiveRefused("No stack deployed from this machine yet.")
        with self.lock:
            self._need_running(st)
            iid, action, cells = self._case(st)
            gw = self._gateway(st)
            trace, _ = self._new_trace()
            tok = gw.c.token("agent_client")
            o = outcome(gw.call_traced(tok, "ask_agent", {"incident_id": iid, "agent": "specialist", "task": TASK}, trace))
            if o["decision"] != "ALLOW":
                raise LiveRefused(f"The specialist was not asked: {verdict_words(o)}")
            note = o["detail"]["result"]["note"]
            o = outcome(gw.call_traced(tok, "request_human_approval", {"incident_id": iid, "proposed_action": action,
                                                                       "cells": cells, "reason": note[:300]}, trace))
            if o["decision"] != "ALLOW":
                raise LiveRefused(f"The change was not queued: {verdict_words(o)}")
            aid = o["detail"]["result"]["approval_id"]
            self.approval_traces[aid] = trace
        return {"trace_id": trace, "approval_id": aid, "incident": iid, "action": action, "cells": len(cells), "note": note}

    def team_pending(self) -> list[dict]:
        st = self.state()
        if not st:
            return []
        return [{"approval_id": p["approval_id"], "incident": p["incident_id"], "action": p["request"].get("action"),
                 "cells": len(p["request"].get("cells") or []), "note": p["request"].get("reason"),
                 "created_at": p.get("created_at")} for p in self._approvals(st).pending()]

    def team_decide(self, approval_id: str, decision: str) -> dict:
        """A person's decision, sent with the engineer's token so Cedar and the tool check it like any other call."""
        st = self.state()
        if not st or decision not in ("approved", "denied"):
            raise LiveRefused("Unknown decision.")
        with self.lock:
            self._need_running(st)
            rec = self._approvals(st).get(approval_id)
            if not rec:
                raise LiveRefused("There is no such approval.")
            gw = self._gateway(st)
            trace = self.approval_traces.get(approval_id)
            if trace not in self.traces:
                trace, _ = self._new_trace()
            tok = gw.c.token("engineer_client")
            iid = rec["incident_id"]
            o = outcome(gw.call_traced(tok, "decide_approval", {"incident_id": iid, "approval_id": approval_id,
                                                                "decision": decision}, trace))
            if o["decision"] != "ALLOW":
                raise LiveRefused(f"The decision was refused: {verdict_words(o)}")
            out = {"trace_id": trace, "approval_id": approval_id, "incident": iid, "decision": decision, "change": None}
            if decision == "approved":
                o = outcome(gw.call_traced(tok, "apply_remediation", {
                    "incident_id": iid, "action": rec["request"]["action"], "cells": rec["request"]["cells"],
                    "mode": "approved", "approval_id": approval_id}, trace))
                done = o["detail"]["result"] if o["decision"] == "ALLOW" else {}
                out["change"] = {"decision": o["decision"], "action_id": done.get("action_id"), "resolved": done.get("resolved"),
                                 "detail": verdict_words(o) if o["decision"] != "ALLOW" else None}
        return out

    def models(self, op: str) -> dict:
        st = self.state()
        if not st or op not in ("withdraw", "restore"):
            raise LiveRefused("Unknown action.")
        with self.lock:
            models_command(self.session(st).client("dynamodb"), op, "live console")
        return self.status()

    def call(self, kind: str) -> dict:
        if kind not in KINDS:
            raise LiveRefused("Unknown call.")
        st = self.state()
        if not st:
            raise LiveRefused("No stack deployed from this machine yet.")
        with self.lock:
            self._need_running(st)
            small, big = self._incidents()
            p = plan(kind, small, big)
            gw = self._gateway(st)
            trace, t0 = self._new_trace()
            tok = gw.c.token("agent_client")
            got_token = time.time()
            if "setup" in p:        # its own trace id, so the attack's trace shows only the attack
                gw.call_traced(tok, "apply_remediation", p["setup"], f"{trace}-setup")
            sent = time.time()
            reply = gw.call_traced(tamper(tok) if p.get("token") == "tampered" else tok, "apply_remediation", p["args"], trace)
            replied = time.time()
        o = outcome(reply)
        v = verdict(reply)
        return {"trace_id": trace, "kind": kind, "incident": p["args"]["incident_id"], "cells_sent": len(p["args"]["cells"]),
                "claimed_cells": p["args"].get("cell_count"), "setup_cells": len(p["setup"]["cells"]) if "setup" in p else None,
                "decision": o["decision"], "blocked_by": v["by"], "detail": item_detail(o) if o["decision"] != "ALLOW" else None,
                "token_ms": round((got_token - t0) * 1000), "gateway_ms": round((replied - sent) * 1000),
                "sent_at": iso_ms(sent), "replied_at": iso_ms(replied),
                "gate": gate_decision(reply, self.hops(trace, t0))}

    def hops(self, trace: str, t0: float) -> list[dict]:
        st = self.state()
        ddb = self.session(st).client("dynamodb")
        kw = {"TableName": AUDIT_TABLE, "ConsistentRead": True,
              "KeyConditionExpression": "run_id = :r AND sk >= :s",
              "ExpressionAttributeValues": {":r": {"S": UNDECLARED}, ":s": {"S": iso_ms(t0 - 5)}}}
        out = []
        while True:
            r = ddb.query(**kw)
            for it in r.get("Items", []):
                if plain(it)["record"].get("trace_id") == trace:
                    out.append(hop(it))
            if "LastEvaluatedKey" not in r:
                return out
            kw["ExclusiveStartKey"] = r["LastEvaluatedKey"]

    def logs(self, trace: str, t0: float) -> dict[str, str]:
        """rec_id -> the time CloudWatch stored that line. Lines arrive some seconds after the record."""
        logs = self.session(self.state()).client("logs")
        seen = {}
        for group in LOG_GROUPS:
            r = logs.filter_log_events(logGroupName=group, startTime=int((t0 - 5) * 1000), filterPattern=f'"{trace}"')
            for e in r.get("events", []):
                msg = e.get("message", "")
                try:
                    line = json.loads(msg[msg.index("{"):])
                except ValueError:
                    continue
                if line.get("al_audit") and line.get("rec_id"):
                    seen[line["rec_id"]] = iso_ms(e["timestamp"] / 1000)
        return seen

    def trace(self, trace: str) -> dict:
        if not TRACE.match(trace) or trace not in self.traces:
            raise LiveRefused("Unknown trace.")
        t0 = self.traces[trace]
        hops = self.hops(trace, t0)
        seen = self.logs(trace, t0)
        for h in hops:
            h["cloudwatch"] = seen.get(h["rec_id"])
        return {"trace_id": trace, "hops": sorted(hops, key=lambda h: h["ts"] or "")}

    def _note(self, kind: str, record: dict):
        st = self.state()
        self.session(st).client("dynamodb").put_item(TableName=AUDIT_TABLE, Item=audit_item(UNDECLARED, "live-console", kind, record))

    def stack(self, action: str) -> dict:
        from aws.infra.pause import pause, resume
        st = self.state()
        if not st or action not in ("pause", "resume"):
            raise LiveRefused("Unknown action.")
        with self.lock:
            (pause if action == "pause" else resume)(self.session(st).client("lambda"))
            self._client = None     # the next call fetches a fresh token
        return self.status()

    def withdraw(self) -> dict:
        st = self.state()
        if not st:
            raise LiveRefused("No stack deployed from this machine yet.")
        with self.lock:
            reg = DynamoRegistry(self.session(st).client("dynamodb"), DDB_PREFIX)
            cur = reg.current()
            if not cur or reg.status(cur[0]) != "active":
                raise LiveRefused("There is no active licence to withdraw.")
            reg.set_status(cur[0], "revoked", "live console")
            self._note("licence_withdrawn", {"jti": cur[0]})
        return self.status()

    def new_licence(self) -> dict:
        """Re-run the calibration on the frozen data and sign with the same KMS key. Revoked stays revoked: this is a
        new licence with a new id, which the Lambdas pick up from the registry without a deploy."""
        from aws.infra import stub_bundle
        st = self.state()
        env = self._lambda_env()
        kms = env.get("AL_ISSUER_KMS_KEY")
        data = os.path.join(self.root, "state", "data")
        if not st or not kms:
            raise LiveRefused("This stack has no KMS signing key, so it cannot issue a licence here.")
        if not os.path.exists(os.path.join(data, "scores.jsonl")):
            raise LiveRefused("The frozen data is not on this machine.")
        with self.lock:
            reg = DynamoRegistry(self.session(st).client("dynamodb"), DDB_PREFIX)
            cur = reg.current()
            if cur and reg.status(cur[0]) == "active":
                raise LiveRefused("A licence is already active.")
            work = tempfile.mkdtemp(prefix="al-live-")
            try:
                os.environ.setdefault("AWS_DEFAULT_REGION", st["region"])
                info = stub_bundle.build(os.path.join(work, "b"), data, kms)
                db = sqlite3.connect(os.path.join(work, "b", "al.db"))
                jti, token = db.execute("SELECT jti, token FROM licences WHERE jti=?", (info["licence_jti"],)).fetchone()
                db.close()
                reg.put(jti, token)
                self._note("licence_issued", {"jti": jti, "upper_bound": info["upper_bound"], "threshold": info["threshold"],
                                              "signer": info["signer"]})
            finally:
                shutil.rmtree(work, ignore_errors=True)
        return self.status()

    def _lambda_env(self) -> dict:
        try:
            return json.load(open(os.path.join(self.root, "dist", "bundle", "lambda_env.json")))
        except (OSError, ValueError):
            return {}


class LiveRefused(Exception):
    """A request the panel should explain rather than treat as a fault."""
