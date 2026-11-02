"""Local Cedar evaluation with cedarpy, mirroring AgentCore Policy semantics, so the exact policy
text deployed to AWS is the text tested here (tests/test_policy_cases.py).

Differences from AgentCore to keep in mind: AgentCore builds principal tags from the JWT and
context.input from the MCP tool arguments; here we pass both explicitly.
"""
from __future__ import annotations

import cedarpy

from aws.cedar.gen_policies import TARGET, policies, policy_names


class PolicyEngine:
    def __init__(self, gateway: str = "GW", mode: str = "ENFORCE"):
        assert mode in ("LOG_ONLY", "ENFORCE")
        self.gateway, self.mode = gateway, mode
        self.text = policies(gateway)

    def evaluate(self, principal_id: str, tags: dict, tool: str, tool_input: dict) -> dict:
        ents = [{"uid": {"type": "AgentCore::OAuthUser", "id": principal_id}, "attrs": {}, "parents": [],
                 "tags": {k: str(v) for k, v in tags.items()}},          # AgentCore: every tag is a string
                {"uid": {"type": "AgentCore::Gateway", "id": self.gateway}, "attrs": {}, "parents": []}]
        req = {"principal": f'AgentCore::OAuthUser::"{principal_id}"',
               "action": f'AgentCore::Action::"{TARGET}___{tool}"',
               "resource": f'AgentCore::Gateway::"{self.gateway}"',
               "context": {"input": tool_input}}
        r = cedarpy.is_authorized(req, self.text, ents)
        allow = r.decision == cedarpy.Decision.Allow
        names = policy_names()
        nm = lambda pid: names[int(pid[6:])] if pid.startswith("policy") and pid[6:].isdigit() else pid  # noqa: E731
        return {"decision": "ALLOW" if allow else "DENY",
                "enforced": self.mode == "ENFORCE",
                "policies": [nm(p) for p in r.diagnostics.reasons],
                "errors": [str(e) for e in r.diagnostics.errors]}
