"""Local stand-in for Amazon Bedrock AgentCore Gateway + Policy, so the full enforcement path runs
and is testable before AWS is set up. Order per request:

  access token (IdP, Path A tags) -> request interceptor (Path C) -> Cedar (real policy text,
  evaluated with cedarpy) -> tool Lambda (Path B) -> simulator -> audit

A denied call returns what AgentCore returns: a normal result with isError=true and text
"AuthorizeActionException - Tool Execution Denied". In LOG_ONLY mode the decision is logged but
not enforced (release gate T25 fails if the gateway is left in LOG_ONLY).
"""
from __future__ import annotations

from aws.cedar.engine import PolicyEngine
from aws.interceptor.handler import intercept
from aws.tool_lambda.tools import NetOpsTools

DENIED = "AuthorizeActionException - Tool Execution Denied"


class LocalGateway:
    def __init__(self, trusted, idp, operator: str = "A", mode: str = "ENFORCE"):
        self.t, self.idp, self.operator = trusted, idp, operator
        self.engine = PolicyEngine(mode=mode)
        self.tools = NetOpsTools(trusted, operator)

    def call(self, access_token: str, tool: str, args: dict) -> dict:
        try:
            principal = self.idp.decode(access_token)
        except Exception as e:
            return {"isError": True, "content": [{"type": "text", "text": f"Unauthorized: {e}"}]}
        tags = {k: v for k, v in principal.items() if k not in ("sub", "aud", "iss", "iat", "exp")}
        ic = intercept(tool, args, tags, self.t, self.operator)
        pol = self.engine.evaluate(principal["sub"], tags, tool, ic["input"])
        rec = {"tool": tool, "role": tags.get("role"), "decision": pol["decision"], "policies": pol["policies"],
               "mode": ic["input"].get("mode"), "action": ic["input"].get("action"),
               "cell_count": ic["input"].get("cell_count"), "category": ic["input"].get("category"),
               "score_ok": ic["input"].get("score_ok"), "licence_ok": ic["input"].get("licence_ok"),
               "interceptor_notes": ic["notes"]}
        if "incident_id" in ic["input"]:
            rec["incident_id"] = ic["input"]["incident_id"]
        if tool != "get_incident":
            self.t.store.audit("policy_decision", rec, self.operator)
        if pol["decision"] == "DENY" and self.engine.mode == "ENFORCE":
            return {"isError": True, "content": [{"type": "text", "text": DENIED}], "policy": pol,
                    "interceptor": ic}
        try:
            result = self.tools.dispatch(tool, tags, ic["input"])
        except Exception as e:
            return {"isError": True, "content": [{"type": "text", "text": str(e)}], "policy": pol,
                    "interceptor": ic}
        return {"isError": False, "result": result, "policy": pol, "interceptor": ic}
