"""The specialist agent: the second member of the team, reached only through the Gateway (tool ask_agent).

It writes a short handover note for the engineer who will decide an approval. The note is advice in words: nothing
parses it, and no score, category, cell count or licence decision ever comes from it (those stay server-computed).
The model sees server-computed facts and the lead's task, never incident values or the ground truth.

Bedrock Guardrails check the model's input and its output. Fail closed: an intervention, a missing guardrail, an
API error or an empty reply all mean no note, and the call is refused.
"""
from __future__ import annotations

from common.catalogue import BLAST_RADIUS, CATALOGUE

LEAD_ROLE = "netops-agent"
AGENTS = ("specialist",)
MAX_TASK = 1000
DEFAULT_MODEL = "amazon.nova-lite-v1:0"
SYSTEM = ("You write handover notes for a telecom network engineer. Use only the facts given. In at most three "
          "sentences say what change is proposed and what the engineer should check before approving it. "
          "Never claim the change is approved, safe or already done.")


class GuardrailBlocked(Exception):
    pass


def facts(trusted, incident_id: str, cells_available: int) -> dict:
    """Server-computed only. The score stays out: the note has no use for it and must not appear to judge it."""
    pred = trusted.score(incident_id)["pred"]
    return {"category": trusted.category(incident_id), "diagnosed_cause_code": pred,
            "catalogue_action": CATALOGUE[pred]["action"], "cells_in_incident": cells_available,
            "most_cells_one_incident_may_change": BLAST_RADIUS}


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

    def note(self, task: str, known: dict) -> str:
        prompt = f"Facts: {known}\nRequest from the lead agent: {task}"
        self.guard(prompt, "INPUT")
        r = self.rt.converse(modelId=self.model, system=[{"text": SYSTEM}],
                             messages=[{"role": "user", "content": [{"text": prompt}]}],
                             inferenceConfig={"maxTokens": 200, "temperature": 0})
        text = "".join(c.get("text", "") for c in r["output"]["message"]["content"]).strip()
        if not text:
            raise GuardrailBlocked("the model returned no text")
        self.guard(text, "OUTPUT")
        return text
