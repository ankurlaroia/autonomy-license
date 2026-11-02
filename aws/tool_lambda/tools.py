"""NetOps tools behind the Gateway (Lambda target). Path B: re-checks everything server-side and
refuses on any mismatch BEFORE any state change, even if Cedar allowed the call (spec 10.3).

Tools: get_incident, apply_remediation, request_human_approval, decide_approval, ask_agent.
"""
from __future__ import annotations

from aws.tool_lambda.approvals import APPROVER_ROLES, DECISIONS, Approvals, action_digest, verify_approval
from aws.tool_lambda.ledger import LedgerError, SqliteLedger
from aws.tool_lambda.simulator import Simulator
from aws.tool_lambda.team import AGENTS, LEAD_ROLE, MAX_TASK, facts
from common.catalogue import BLAST_RADIUS, CATALOGUE, NEVER_AUTONOMOUS
from license.verifier import verify_licence


class ToolError(Exception):
    pass


class NetOpsTools:
    def __init__(self, trusted, operator: str = "A"):
        self.t = trusted
        self.operator = operator
        self.sim = Simulator(trusted.store)
        self.approvals = getattr(trusted, "approvals", None) or Approvals(trusted.store)
        self.ledger = getattr(trusted, "ledger", None) or SqliteLedger(trusted.store)

    def dispatch(self, tool: str, principal: dict, args: dict) -> dict:
        fn = {"get_incident": self.get_incident, "apply_remediation": self.apply_remediation,
              "request_human_approval": self.request_human_approval,
              "decide_approval": self.decide_approval, "ask_agent": self.ask_agent}.get(tool)
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
        if iid not in self.t.incidents:
            raise ToolError("unknown incident")
        cells = sorted(set(args.get("cells", [])))
        aid = self.approvals.request(iid, args["proposed_action"], cells, args.get("reason", ""),
                                     args.get("params"))
        self.t.store.audit("approval_requested", {"incident_id": iid, "approval_id": aid,
                                                  "action": args["proposed_action"], "cells": cells,
                                                  "reason": args.get("reason", "")}, self.operator)
        return {"approval_id": aid, "status": "pending"}

    def decide_approval(self, principal, args):
        """A person's decision. The approver is the verified role of the caller, never a name in the arguments."""
        iid, aid, decision = args.get("incident_id"), args.get("approval_id"), args.get("decision")
        role = principal.get("role")
        try:
            if role not in APPROVER_ROLES:
                raise ToolError("only a NOC engineer may decide an approval")
            if decision not in DECISIONS:
                raise ToolError("decision must be approved or denied")
            rec = self.approvals.get(aid)
            if not rec or rec["incident_id"] != iid:
                raise ToolError("no such approval for this incident")
            self.approvals.decide(aid, role, role, decision)
        except Exception as e:   # fail closed, nothing decided
            self.t.store.audit("tool_refused", {"incident_id": iid or "?", "approval_id": aid, "reason": str(e),
                                                "role": role}, self.operator)
            raise ToolError(f"refused by tool (Path B): {e}") from None
        self.t.store.audit("approval_decided", {"incident_id": iid, "approval_id": aid, "decision": decision,
                                                "decided_by": role}, self.operator)
        return {"approval_id": aid, "decision": decision}

    def ask_agent(self, principal, args):
        """The lead asks the specialist for a handover note. Advice only: this tool changes nothing."""
        iid, agent, task = args.get("incident_id"), args.get("agent"), args.get("task")
        role = principal.get("role")
        try:
            if role != LEAD_ROLE:
                raise ToolError("only the lead agent may ask another agent")
            if agent not in AGENTS:
                raise ToolError("unknown agent")
            if iid not in self.t.incidents:
                raise ToolError("unknown incident")
            if not isinstance(task, str) or not task.strip() or len(task) > MAX_TASK:
                raise ToolError(f"task must be text of at most {MAX_TASK} characters")
            specialist = getattr(self.t, "specialist", None)
            if specialist is None:
                raise ToolError("no guardrail configured, so no model call")
            note = specialist.note(task, facts(self.t, iid, len(self.t.cell_ids(iid))))
        except Exception as e:   # fail closed: no note
            self.t.store.audit("tool_refused", {"incident_id": iid or "?", "agent": agent, "reason": str(e)[:200],
                                                "role": role}, self.operator)
            raise ToolError(f"refused by tool (Path B): {e}") from None
        self.t.store.audit("agent_call", {"incident_id": iid, "from_role": role, "to_agent": agent,
                                          "model": specialist.model, "guardrail_input": "NONE",
                                          "guardrail_output": "NONE", "task_chars": len(task),
                                          "note_chars": len(note)}, self.operator)
        return {"agent": agent, "note": note, "advisory": True}

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
            try:    # one approval, one change: of two racing calls, only one spends it
                self.approvals.consume(ctx["approval_id"])
            except Exception as e:   # spent already, or the store failed: either way, no change and a record of why
                self.t.store.audit("tool_refused", {"incident_id": args["incident_id"], "action": args.get("action"),
                                                    "reason": str(e)[:200], "mode": "approved"}, self.operator)
                raise ToolError(f"refused by tool (Path B): {e}") from None
        inc = self.t.incidents[args["incident_id"]]
        res = self.sim.apply(inc, args["action"], ctx["cells"])
        self.t.store.audit("remediation_applied", {"incident_id": inc["incident_id"], "action": args["action"],
                                                   "mode": args["mode"], **{k: v for k, v in ctx.items() if k != "cells"},
                                                   "cells": ctx["cells"], "action_id": res["action_id"],
                                                   "resolved": res["resolved"]}, self.operator)
        return res
