"""Drive the deployed Gateway (S1, S2, S4) and record evidence in dist/smoke_evidence.json.

  python -m aws.infra.smoke                 # tools/list, then the agent's 2-cell ALLOW and 5-cell DENY

Tokens: Cognito client-credentials for the agent app client; the client secret is read from Cognito at run
time and never printed or written. Incidents come from the local stub bundle (dist/bundle), the same data
the Lambdas carry, so ids line up. Evidence holds decisions and ids, never tokens.
"""
from __future__ import annotations

import base64
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

from common.catalogue import BLAST_RADIUS, CATALOGUE

DENIED = "Tool Execution Denied"   # docs: isError + AuthorizeActionException; live 2026-10-31: JSON-RPC -32002


def parse_mcp(raw: bytes, content_type: str) -> dict:
    """A JSON-RPC reply, sent either as plain JSON or as server-sent events (last `data:` line wins)."""
    text = raw.decode("utf-8", "replace")
    if "text/event-stream" in (content_type or ""):
        data = [ln[5:].strip() for ln in text.splitlines() if ln.startswith("data:")]
        text = data[-1] if data else "{}"
    return json.loads(text or "{}")


def outcome(reply: dict) -> dict:
    """ALLOW / DENY / ERROR from a tools/call reply. The docs say a policy deny is isError with the
    AuthorizeActionException text; the live Gateway returned a JSON-RPC error -32002 instead. Both count."""
    if "error" in reply:
        msg = json.dumps(reply["error"])
        return {"decision": "DENY" if DENIED in msg else "ERROR", "detail": msg[:300]}
    res = reply.get("result", {})
    text = " ".join(c.get("text", "") for c in res.get("content", []) if isinstance(c, dict))
    if res.get("isError"):
        return {"decision": "DENY" if DENIED in text else "ERROR", "detail": text[:300]}
    try:
        body = json.loads(text)
    except ValueError:
        body = {"raw": text[:300]}
    if isinstance(body, dict) and body.get("ok") is False:     # Path B refusal inside the tool Lambda
        return {"decision": "REFUSED_BY_TOOL", "detail": str(body.get("error"))[:300]}
    return {"decision": "ALLOW", "detail": body}


def evidence_header(state: dict, info: dict) -> dict:
    """Where the licence came from, read from the bundle (stub_info.json), never assumed."""
    source = info.get("data_source", "synthetic")
    return {"when": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "gateway": state["gateway_url"],
            "policy_mode": state.get("policy_mode"),
            "data_source": source if source != "synthetic" else "synthetic (stub licence)",
            "signer": info.get("signer", "local"), "licence_jti": info.get("licence_jti"),
            "threshold": info.get("threshold"), "upper_bound": info.get("upper_bound")}


def pick_incidents(bundle: str, threshold: float):
    from model.scorer import ScoreCache
    scores = ScoreCache(os.path.join(bundle, "data", "scores.jsonl"))
    small = big = None
    for line in open(os.path.join(bundle, "data", "incidents.jsonl")):
        inc = json.loads(line)
        s = scores.get(inc["incident_id"])
        if s["score"] < threshold or CATALOGUE[s["pred"]]["cls"] != "AUTO":
            continue
        act = CATALOGUE[s["pred"]]["action"]
        if small is None and len(inc["cells"]) >= 2:
            small = (inc, act)
        if big is None and len(inc["cells"]) > BLAST_RADIUS:
            big = (inc, act)
    if not (small and big):
        raise SystemExit("stub bundle has no suitable incidents; rebuild it")
    return small, big


class Client:   # pragma: no cover - needs AWS
    def __init__(self, state: dict, profile: str | None = None):
        import boto3
        self.st = state
        cog = boto3.session.Session(profile_name=profile, region_name=state["region"]).client("cognito-idp")
        self._secret = {k: cog.describe_user_pool_client(UserPoolId=state["pool_id"], ClientId=state[k])
                        ["UserPoolClient"]["ClientSecret"]
                        for k in ("agent_client", "engineer_client", "specialist_client") if k in state}
        self.ids = 0

    def token(self, who: str) -> str:
        cid = self.st[who]
        auth = base64.b64encode(f"{cid}:{self._secret[who]}".encode()).decode()
        req = urllib.request.Request(self.st["token_url"], method="POST",
                                     data=urllib.parse.urlencode({"grant_type": "client_credentials",
                                                                  "scope": self.st["scope"]}).encode(),
                                     headers={"Authorization": f"Basic {auth}",
                                              "Content-Type": "application/x-www-form-urlencoded"})
        return json.loads(urllib.request.urlopen(req, timeout=20).read())["access_token"]

    def rpc(self, tok: str, method: str, params: dict | None = None) -> dict:
        self.ids += 1
        body = {"jsonrpc": "2.0", "id": self.ids, "method": method, **({"params": params} if params else {})}
        req = urllib.request.Request(self.st["gateway_url"], data=json.dumps(body).encode(), method="POST",
                                     headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json",
                                              "Accept": "application/json, text/event-stream"})
        try:
            r = urllib.request.urlopen(req, timeout=60)
            return parse_mcp(r.read(), r.headers.get("Content-Type", ""))
        except urllib.error.HTTPError as e:
            return {"error": {"http": e.code, "body": e.read().decode("utf-8", "replace")[:500]}}

    def call(self, tok: str, tool: str, args: dict) -> dict:
        return self.rpc(tok, "tools/call", {"name": f"NetOps___{tool}", "arguments": args})


def main():   # pragma: no cover - needs AWS
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile")
    ap.add_argument("--bundle", default="dist/bundle")
    a = ap.parse_args()
    state = json.load(open(os.path.join("dist", "aws_state.json")))
    info = json.load(open(os.path.join(a.bundle, "stub_info.json")))
    threshold = info["threshold"]
    c = Client(state, a.profile)
    agent = c.token("agent_client")
    ev = evidence_header(state, info)
    c.rpc(agent, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                "clientInfo": {"name": "al-smoke", "version": "1"}})
    tools = c.rpc(agent, "tools/list")
    ev["S1_tools"] = sorted(t["name"] for t in tools.get("result", {}).get("tools", []))
    (small, s_act), (big, b_act) = pick_incidents(a.bundle, threshold)
    ev["S4_get_incident"] = outcome(c.call(agent, "get_incident", {"incident_id": small["incident_id"]}))["decision"]
    two = [x["cell_id"] for x in small["cells"]][:2]
    ev["S4_allow_2_cells"] = {"incident": small["incident_id"], **outcome(c.call(agent, "apply_remediation", {
        "incident_id": small["incident_id"], "action": s_act, "cells": two, "mode": "autonomous"}))}
    many = [x["cell_id"] for x in big["cells"]]
    ev["S4_deny_over_blast_radius"] = {"incident": big["incident_id"], "cells": len(many), "claimed_cell_count": 2,
                                       **outcome(c.call(agent, "apply_remediation", {
                                           "incident_id": big["incident_id"], "action": b_act, "cells": many,
                                           "mode": "autonomous", "cell_count": 2}))}
    os.makedirs("dist", exist_ok=True)
    json.dump(ev, open(os.path.join("dist", "smoke_evidence.json"), "w"), indent=1, default=str)
    print(json.dumps(ev, indent=1, default=str))


if __name__ == "__main__":
    main()
