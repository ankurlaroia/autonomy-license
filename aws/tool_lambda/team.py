"""The team behind the tool ask_agent, reached only through the Gateway.

specialist: writes a short handover note for the engineer who will decide an approval.
planner:    chooses the lead's next step from a fixed list (aws/infra/team.py runs the step through the Gateway).

Both are advice in words. The planner's reply yields one word from NEXT_STEPS, or "stop"; the arguments of every step
come from server facts, and no score, category, cell count or licence decision ever comes from a model. A step the
planner chooses still has to pass Cedar and the tool's checks. The model sees server-computed facts and the lead's
task, never incident values or the ground truth.

Bedrock Guardrails check the model's input and its output. Fail closed: an intervention, a missing guardrail, an
API error or an empty reply all mean no answer, and the call is refused.
"""
from __future__ import annotations

import re

from common.catalogue import BLAST_RADIUS, CATALOGUE

LEAD_ROLE = "netops-agent"
AGENTS = ("specialist", "planner")
NEXT_STEPS = ("read_incident", "ask_specialist", "act_under_licence", "request_approval", "stop")
MAX_TASK = 1000
DEFAULT_MODEL = "amazon.nova-lite-v1:0"
SYSTEM = ("You write handover notes for a telecom network engineer. Use only the facts given. In at most three "
          "sentences say what change is proposed and what the engineer should check before approving it. "
          "Never claim the change is approved, safe or already done.")
PLANNER = ("You choose the next step for a network operations agent handling one incident. Reply with exactly one word "
           f"from this list and nothing else: {', '.join(NEXT_STEPS)}. "
           "The request says which steps are finished and which are still open. Reply with the first step still open. "
           "The server decides whether any step is allowed.")


class GuardrailBlocked(Exception):
    pass


def facts(trusted, incident_id: str, cells_available: int) -> dict:
    """Server-computed only. The score stays out: no model has a use for it and none must appear to judge it."""
    pred = trusted.score(incident_id)["pred"]
    return {"category": trusted.category(incident_id), "diagnosed_cause_code": pred,
            "catalogue_action": CATALOGUE[pred]["action"], "cells_in_incident": cells_available,
            "most_cells_one_incident_may_change": BLAST_RADIUS}


def next_step(reply: str) -> str:
    """The one allowed word in a reply. Anything else, including two different steps, is stop."""
    found = set(re.findall("|".join(NEXT_STEPS), reply.lower()))
    return found.pop() if len(found) == 1 else "stop"


class Specialist:
    def __init__(self, runtime, guardrail_id: str, guardrail_version: str, model_id: str = DEFAULT_MODEL):
        if not guardrail_id or not guardrail_version:
            raise ValueError("the specialist needs a guardrail")
        self.rt, self.gid, self.ver, self.model = runtime, guardrail_id, guardrail_version, model_id

    def guard(self, text: str, source: str):
        r = self.rt.apply_guardrail(guardrailIdentifier=self.gid, guardrailVersion=self.ver, source=source,
                                    content=[{"text": {"text": text}}])
        if r.get("action") != "NONE":
            raise GuardrailBlocked(f"guardrail stopped the model {source.lower()}")

    def _ask(self, system: str, task: str, known: dict, max_tokens: int) -> str:
        prompt = f"Facts: {known}\nRequest from the lead agent: {task}"
        self.guard(prompt, "INPUT")
        r = self.rt.converse(modelId=self.model, system=[{"text": system}],
                             messages=[{"role": "user", "content": [{"text": prompt}]}],
                             inferenceConfig={"maxTokens": max_tokens, "temperature": 0})
        text = "".join(c.get("text", "") for c in r["output"]["message"]["content"]).strip()
        if not text:
            raise GuardrailBlocked("the model returned no text")
        self.guard(text, "OUTPUT")
        return text

    def note(self, task: str, known: dict) -> str:
        return self._ask(SYSTEM, task, known, 200)

    def plan(self, task: str, known: dict) -> str:
        return next_step(self._ask(PLANNER, task, known, 20))
