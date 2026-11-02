"""NetOps tools behind the Gateway (Lambda target). Path B: re-checks everything server-side and
refuses on any mismatch BEFORE any state change, even if Cedar allowed the call (spec 10.3).

Tools: get_incident, apply_remediation, request_human_approval.
"""
from __future__ import annotations

from aws.tool_lambda.approvals import Approvals, action_digest, verify_approval
from aws.tool_lambda.ledger import LedgerError, SqliteLedger
from aws.tool_lambda.simulator import Simulator
from common.catalogue import BLAST_RADIUS, CATALOGUE, NEVER_AUTONOMOUS
from license.verifier import verify_licence


class ToolError(Exception):
    pass


class NetOpsTools:
    def __init__(self, trusted, operator: str = "A"):
        self.t = trusted
        self.operator = operator
        self.sim = Simulator(trusted.store)
        self.approvals = Approvals(trusted.store)
        self.ledger = getattr(trusted, "ledger", None) or SqliteLedger(trusted.store)

    def dispatch(self, tool: str, principal: dict, args: dict) -> dict:
        fn = {"get_incident": self.get_incident, "apply_remediation": self.apply_remediation,
              "request_human_approval": self.request_human_approval}.get(tool)
        if fn is None:
            raise ToolError(f"unknown tool {tool}")
        return fn(principal, args)

    # ------------------------------------------------------------------
    def get_incident(self, principal, args):
        iid = args["incident_id"]
        inc = self.t.public_incident(iid)
        self.sim.ensure(self.t.incidents[iid])
        return inc

    def request_human_approval(self, principal, args):
        iid = args["incident_id"]
        cells = sorted(set(args.get("cells", [])))
        aid = self.approvals.request(iid, args["proposed_action"], cells, args.get("reason", ""),
                                     args.get("params"))
        self.t.store.audit("approval_requested", {"incident_id": iid, "approval_id": aid,
                                                  "action": args["proposed_action"], "cells": cells,
                                                  "reason": args.get("reason", "")}, self.operator)
        return {"approval_id": aid, "status": "pending"}

    # ------------------------------------------------------------------
    def _path_b_checks(self, principal, args) -> dict:
        iid = args["incident_id"]
        if iid not in self.t.incidents:
            raise ToolError("unknown incident")
        cells = sorted(set(args.get("cells", [])))
        if not cells or not set(cells) <= self.t.cell_ids(iid):
            raise ToolError("cells do not belong to this incident")
        if len(cells) > BLAST_RADIUS:
            raise ToolError("hard rule: blast radius exceeded")
        action, mode = args["action"], args["mode"]
        if mode == "autonomous":
            if principal.get("role") != "netops-agent":
                raise ToolError("autonomous mode is for the agent role only")
            if action in NEVER_AUTONOMOUS:
                raise ToolError("hard rule: never-autonomous action")
            cat = self.t.category(iid)
            tok = self.t.registry.current()
            if tok is None:
                raise ToolError("no licence")
            claims = verify_licence(tok[1], self.t.issuer_public_key, issuer=self.t.issuer,
                                    audience=self.t.audience, expected_fingerprint=self.t.expected_fingerprint,
                                    status_lookup=self.t.registry.status, operator=self.operator,
                                    requested_category=cat, requested_action=action,
                                    warned_categories=self.t.registry.warned_categories(self.operator))
            sc = self.t.score(iid)
            if sc["score"] < claims["risk"]["threshold"]:
                raise ToolError("score below licensed threshold")
            if CATALOGUE[sc["pred"]]["action"] != action:
                raise ToolError("action is not the catalogue action for the trusted diagnosis")
            return {"cells": cells, "licence_jti": claims["jti"], "score": sc["score"],
                    "threshold": claims["risk"]["threshold"], "pred": sc["pred"], "category": cat}
        if mode == "approved":
            if principal.get("role") != "noc-engineer":
                raise ToolError("approved mode is for engineers only")
            rec = self.approvals.get(args.get("approval_id", ""))
            verify_approval(rec, digest=action_digest(iid, action, cells, args.get("params")))
            return {"cells": cells, "approval_id": rec["approval_id"]}
        raise ToolError("unknown mode")

    def apply_remediation(self, principal, args):
        try:
            ctx = self._path_b_checks(principal, args)
        except Exception as e:   # fail closed, no side effect
            self.t.store.audit("tool_refused", {"incident_id": args.get("incident_id", "?"),
                                                "action": args.get("action"), "reason": str(e),
                                                "mode": args.get("mode")}, self.operator)
            raise ToolError(f"refused by tool (Path B): {e}") from None
        try:        # F1 across calls: the cells already changed for this incident count too
            self.ledger.claim(args["incident_id"], ctx["cells"])
        except LedgerError as e:
            self.t.store.audit("tool_refused", {"incident_id": args["incident_id"], "action": args.get("action"),
                                                "reason": str(e), "mode": args.get("mode")}, self.operator)
            raise ToolError(f"refused by tool (Path B): {e}") from None
        if args["mode"] == "approved":
            self.approvals.consume(ctx["approval_id"])
        inc = self.t.incidents[args["incident_id"]]
        res = self.sim.apply(inc, args["action"], ctx["cells"])
        self.t.store.audit("remediation_applied", {"incident_id": inc["incident_id"], "action": args["action"],
                                                   "mode": args["mode"], **{k: v for k, v in ctx.items() if k != "cells"},
                                                   "cells": ctx["cells"], "action_id": res["action_id"],
                                                   "resolved": res["resolved"]}, self.operator)
        return res
