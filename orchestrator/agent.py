"""P0 agent: a deterministic orchestrator (MCP client with an OAuth access token).

It reads the incident, reads the model's prediction from the scorer service, compares the score
with the licensed threshold, maps the predicted cause to its catalogue action and calls tools.
It is UNTRUSTED by design: the interceptor and tool Lambda recompute score, category and cell
count, so nothing it claims can widen its permissions. A Strands planner LLM can replace it later
(spec 10.1 upgrade rule) without changing enforcement.
"""
from __future__ import annotations

from aws.interceptor.handler import AGENT_TRUST_FIELDS
from common.catalogue import CATALOGUE

SERVER_FIELDS = ("cell_count", "category", "score_ok", "licence_ok")   # what Cedar decides on


def checked(args: dict, res: dict) -> dict | None:
    """For the console: what the agent sent next to what the interceptor computed, read from the gateway's
    response. Display only, after the fact; Cedar already decided on the server values. None when the gateway
    does not return the interceptor's output (AgentCore on AWS)."""
    ic = res.get("interceptor")
    if not ic:
        return None
    return {"claimed": {k: args[k] for k in AGENT_TRUST_FIELDS if k in args},
            "listed_cells": len(args.get("cells", [])),
            "server": {k: ic["input"][k] for k in SERVER_FIELDS if k in ic["input"]},
            "dropped": [n for n in ic["notes"] if n in args],
            "notes": [n for n in ic["notes"] if n not in args]}


DEFAULT_CELLS = {  # which cells each action touches by default
    "adjust_tilt": ("serving", "cosite"), "reassign_pci": ("serving",), "set_handover_params": ("serving",),
    "annotate_close": ("serving",), "adjust_neighbour_power": ("neighbour",), "rebalance_scheduler": ("serving",),
    "plan_new_site": ("serving",),
}


class Orchestrator:
    def __init__(self, gateway, idp, scorer_service, operator: str = "A", sub: str = "netops-agent-01"):
        self.gw, self.idp, self.scores, self.operator, self.sub = gateway, idp, scorer_service, operator, sub
        self.threshold = None    # read from the licence's public claims at token time

    def token(self):
        return self.idp.mint_access_token(self.sub, "netops-agent", self.operator)

    def cells_for(self, incident: dict, action: str, n_override: int | None = None) -> list[str]:
        if n_override:
            return [c["cell_id"] for c in incident["cells"]][:n_override]
        roles = DEFAULT_CELLS.get(action, ("serving",))
        out = [c["cell_id"] for c in incident["cells"] if c["role"] in roles]
        return out[:1] if roles == ("neighbour",) else out

    def handle(self, incident_id: str, threshold: float | None, *, force_cells: int | None = None,
               claim_cell_count: int | None = None, extra_args: dict | None = None) -> dict:
        tok = self.token()
        r = self.gw.call(tok, "get_incident", {"incident_id": incident_id})
        if r["isError"]:
            return {"incident_id": incident_id, "outcome": "ERROR", "detail": r}
        inc = r["result"]
        pred = self.scores.get(incident_id)
        action = CATALOGUE[pred["pred"]]["action"]
        cls = CATALOGUE[pred["pred"]]["cls"]
        cells = self.cells_for(inc, action, force_cells)
        trace = {"incident_id": incident_id, "category": inc["category"], "pred": pred["pred"],
                 "score": pred["score"], "threshold": threshold, "action": action, "cells": cells, "steps": []}
        auto = threshold is not None and pred["score"] >= threshold and cls == "AUTO"
        if auto or force_cells:
            args = {"incident_id": incident_id, "action": action, "cells": cells, "mode": "autonomous"}
            if claim_cell_count is not None:
                args["cell_count"] = claim_cell_count          # an agent lie; the interceptor overwrites it
            args.update(extra_args or {})
            res = self.gw.call(tok, "apply_remediation", args)
            trace["steps"].append({"call": "apply_remediation", "isError": res["isError"],
                                   "policy": res.get("policy"), "checked": checked(args, res),
                                   "text": res["content"][0]["text"] if res["isError"] else None,
                                   "result": res.get("result")})
            if not res["isError"]:
                trace["outcome"] = "AUTO_APPLIED"
                return trace
            reason = "denied: " + res["content"][0]["text"]
        else:
            reason = ("below licensed threshold" if cls == "AUTO" else f"catalogue class {cls}")
        ap = self.gw.call(tok, "request_human_approval", {"incident_id": incident_id, "proposed_action": action,
                                                          "cells": cells, "reason": reason})
        trace["steps"].append({"call": "request_human_approval", "isError": ap["isError"],
                               "result": ap.get("result"), "reason": reason})
        trace["outcome"] = "HUMAN"
        trace["approval_id"] = (ap.get("result") or {}).get("approval_id")
        return trace


class Engineer:
    """A human engineer acting through the same Gateway (P3 permit + approval check)."""

    def __init__(self, gateway, idp, approvals, sub: str = "eng-ana", operator: str = "A"):
        self.gw, self.idp, self.approvals, self.sub, self.operator = gateway, idp, approvals, sub, operator

    def approve_and_execute(self, approval_id: str, cells_override: list[str] | None = None) -> dict:
        rec = self.approvals.get(approval_id)
        if rec["decision"] == "pending":    # a replay goes on to the tool, which refuses and records it
            self.approvals.decide(approval_id, self.sub)
        cells = cells_override or rec["request"]["cells"]
        tok = self.idp.mint_access_token(self.sub, "noc-engineer", self.operator)
        return self.gw.call(tok, "apply_remediation", {"incident_id": rec["incident_id"],
                                                       "action": rec["request"]["action"], "cells": cells,
                                                       "mode": "approved", "approval_id": approval_id})
