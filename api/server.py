"""JSON API over the demo engine for the Next.js console (web/).

    uvicorn api.server:app --port 8000

Same engine and local Gateway stack as console/app.py; every value the web UI shows comes from here.
Uses its own SQLite file so it never clobbers the Streamlit console's state.
"""
from __future__ import annotations

import json
import os
import threading

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import Response

from demo.engine import ROOT, Demo

app = FastAPI(title="Autonomy License API")
_lock = threading.Lock()
_demo: Demo | None = None
_last: dict = {}


def demo() -> Demo:
    global _demo
    if _demo is None:
        _demo = Demo(data_dir=os.environ.get("AL_DEMO_DATA"),   # unset: state/data (real once scored)
                     db=os.path.join(ROOT, "state", "web.db"), fresh=True)
    return _demo


def _json(obj) -> Response:
    def default(o):   # numpy scalars, tuples inside traces, sets
        if hasattr(o, "item"):
            return o.item()
        if isinstance(o, (set, frozenset)):
            return sorted(o)
        raise TypeError(type(o).__name__)
    return Response(json.dumps(obj, default=default), media_type="application/json")


MOMENTS = {
    "earn": lambda d: d.moment1_earn(),
    "act": lambda d: d.moment2_act(),
    "block": lambda d: d.moment3_block(),
    "revoke": lambda d: d.moment4_revoke(),
    "recertify": lambda d: {"licence": d.reinstate()["jti"]},
    "federation": lambda d: d.moment5_federation(),
    "warning": lambda d: d.moment6_warning(),
    "self_revoke": lambda d: d.moment7_self_revoke(),
}
NEEDS_LICENCE = {"act", "block", "revoke", "warning"}


def data_source(d: Demo) -> str:
    """From the prepared data itself (split_hashes.json), never assumed: "synthetic" or "telelogs"."""
    try:
        return json.load(open(os.path.join(d.data_dir, "split_hashes.json"))).get("source") or "unknown"
    except (OSError, ValueError):
        return "unknown"


def state_dict(d: Demo) -> dict:
    claims = d.licence_claims()
    jti = claims["jti"] if claims else None
    return {
        "data_source": data_source(d),
        "licence": None if not claims else {
            "jti": jti, "status": d.trusted.registry.status(jti), "exp": claims["exp"],
            "scope": claims["scope"], "risk": claims["risk"]},
        "warned_categories": sorted(d.trusted.registry.warned_categories("A")),
        "approvals": [{"id": p["approval_id"], "action": p["request"]["action"],
                       "cells": len(p["request"]["cells"]), "reason": p["request"]["reason"]}
                      for p in d.approvals.pending()],
        "audit": [_audit_row(a) for a in d.store.audit_tail(30)],
        # every licence issue and revocation, beyond the audit tail, so the console can show which licence a
        # re-issued one supersedes however much has happened since
        "licence_events": [_audit_row(a) for a in d.store.audit_tail(200, kinds=LICENCE_EVENTS)],
        "last": _last or None,
    }


LICENCE_EVENTS = ("licence_issued", "licence_revoked", "licence_auto_revoked")


def _audit_row(a: dict) -> dict:
    return {"seq": a["seq"], "ts": a["ts"], "operator": a["operator"], "kind": a["kind"],
            "incident": (a.get("incident_hash") or "")[:18],
            "detail": {k: v for k, v in a.items() if k not in ("seq", "ts", "operator", "kind", "incident_hash")}}


@app.get("/state")
def get_state():
    with _lock:
        return _json(state_dict(demo()))


UNITS_SHOWN = ("licence", "allow", "deny", "adversarial", "trace", "pause")


def _declared_runs(base: str, rehearsal: bool) -> dict | None:
    """The newest run of each unit under judging.json in `base`: its declaration and its own record file, the
    same files tools/rebuild.py checks. A unit whose files cannot be read is left out, never assumed passed."""
    try:
        doc = json.load(open(os.path.join(base, "judging.json")))
        runs = list(doc["reported_results"].items())
    except (OSError, ValueError, KeyError, AttributeError):
        return None
    units, latest = {}, None
    for rid, rep in runs:
        try:
            rec = json.load(open(os.path.join(base, "evidence", "runs", rid, "record.json")))
            decl = json.load(open(os.path.join(base, "evidence", "declared", f"{rid}.json")))
            res = rec["result"]
            unit = {"run_id": rid, "passed": res["pass"] is True, "value": res["value"], "items": len(decl["items"])}
            if rep["unit"] == "licence":
                unit["data_source"] = rec["licence"].get("data_source")
            units[rep["unit"]] = unit
            latest = decl
        except (OSError, ValueError, KeyError, TypeError):
            continue
    if latest is None:
        return None
    team = str(doc.get("team_code"))
    if rehearsal or team.upper().startswith("REHEARSAL"):
        scope = "rehearsal"
    else:
        bucket = str((doc.get("evidence") or {}).get("bucket"))
        scope = "personal" if bucket.startswith("al-evidence-") else "team"   # judged_run's fallback bucket
    return {"scope": scope, "team_code": team, "when": latest.get("declared_at"),
            "policy_mode": latest.get("policy_mode"), "signer": (latest.get("licence") or {}).get("signer"),
            "data_source": (units.get("licence") or {}).get("data_source"),
            "units": {u: units[u] for u in UNITS_SHOWN if u in units}}


def live_evidence(root: str) -> dict | None:
    """What the deployed AWS Gateway did, from the declared runs (decisions and ids only; never tokens or data).
    judging.json at the repository root first; otherwise the newest rehearsal in dist/, labelled as one."""
    found = _declared_runs(root, rehearsal=False)
    if found:
        return found
    dist = os.path.join(root, "dist")
    names = sorted((n for n in os.listdir(dist) if n.startswith("rehearsal")), reverse=True) if os.path.isdir(dist) else []
    for name in names:
        found = _declared_runs(os.path.join(dist, name), rehearsal=True)
        if found:
            return found
    return None


@app.get("/evidence")
def get_evidence():
    return _json({"live": live_evidence(ROOT)})


# ---------- the Live view (api/live.py): off unless AL_LIVE=1, and only ever from this machine ----------
_live_link = None
LOOPBACK = ("localhost", "127.0.0.1", "[::1]")


def _live_on() -> bool:
    return os.environ.get("AL_LIVE") == "1"


def _is_local(request: Request) -> bool:
    """The proxy in front (Next.js) forwards the browser's host; a device elsewhere on the network does not pass this."""
    def name(h):
        return h[:h.rindex("]") + 1] if h.startswith("[") and "]" in h else h.split(":")[0]
    hosts = [h for h in (request.headers.get("x-forwarded-host"), request.headers.get("host")) if h]
    return bool(hosts) and all(name(h) in LOOPBACK for h in hosts)


def _link(request: Request, write: bool = False):
    """Live calls act with this machine's AWS sign-in. The custom header makes a browser ask first, and this API
    allows no other origin, so another site open in the same browser cannot trigger one."""
    global _live_link
    if not _live_on() or not _is_local(request) or (write and request.headers.get("x-al-live") != "1"):
        raise HTTPException(403, "The live view is off")
    from api import live
    if _live_link is None:
        _live_link = live.Live(ROOT, os.environ.get("AWS_PROFILE"))
    return _live_link


def _live_do(fn, *args):
    from api import live
    try:
        return _json(fn(*args))
    except live.LiveRefused as e:
        raise HTTPException(409, str(e)) from None
    except HTTPException:
        raise
    except Exception as e:      # never a stack trace or request details in the browser
        raise HTTPException(502, live.explain(e)) from None


@app.get("/live/status")
def live_status(request: Request):
    if not _live_on() or not _is_local(request):
        return _json({"enabled": False})
    return _json({"enabled": True, **_link(request).status()})


@app.post("/live/call/{kind}")
def live_call(kind: str, request: Request):
    return _live_do(_link(request, write=True).call, kind)


@app.get("/live/trace/{trace}")
def live_trace(trace: str, request: Request):
    return _live_do(_link(request).trace, trace)


@app.post("/live/stack/{action}")
def live_stack(action: str, request: Request):
    return _live_do(_link(request, write=True).stack, action)


@app.post("/live/licence/withdraw")
def live_withdraw(request: Request):
    return _live_do(_link(request, write=True).withdraw)


@app.post("/live/licence/new")
def live_new_licence(request: Request):
    return _live_do(_link(request, write=True).new_licence)


@app.get("/alphas")
def get_alphas():
    with _lock:
        d = demo()
        return _json({"official_alpha": d.alpha, "alphas": d.exploratory_alphas()})


@app.get("/policies")
def get_policies():
    """The Cedar statements the gateway evaluates, by name (the text deployed to AgentCore Policy)."""
    from aws.cedar.gen_policies import policy_statements
    return _json({"policies": dict(policy_statements())})


@app.post("/moment/{name}")
def run_moment(name: str):
    if name not in MOMENTS:
        raise HTTPException(404, f"unknown moment {name}")
    with _lock:
        d = demo()
        claims = d.licence_claims()
        status = d.trusted.registry.status(claims["jti"]) if claims else None
        if name in NEEDS_LICENCE and status != "active":
            raise HTTPException(409, "No active licence. Run Earn, or Re-certify after a revoke.")
        if name == "recertify" and not claims:
            raise HTTPException(409, "Nothing to re-certify yet. Run Earn first.")
        _last.clear()
        _last.update(name=name, result=MOMENTS[name](d))
        return _json(state_dict(d))


@app.post("/reset")
def reset():
    """Start the demo over, exactly as restarting the API does: a fresh engine on the same data and database,
    with licences, warnings, approvals, audit and simulator cleared. Local demo only; nothing on AWS changes."""
    global _demo
    with _lock:
        old = demo()
        data_dir, db = old.data_dir, old.store.path
        old.store.db.close()
        _demo = Demo(data_dir=data_dir, db=db, fresh=True)
        _last.clear()
        return _json(state_dict(_demo))
