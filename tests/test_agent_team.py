"""The two-agent team: only the lead asks, only through the Gateway rules, and the model call fails closed.
Cedar decisions come from the same policy text the Gateway gets; the model and guardrail are fakes here."""
import json
from types import SimpleNamespace

import cedarpy
import pytest

from aws.cedar.gen_policies import TARGET, policies
from aws.cedar.schema import cedar_schema, validate
from aws.interceptor.handler import ATTESTED_TOOLS
from aws.tool_lambda import team as T
from aws.tool_lambda.approvals import Approvals
from aws.tool_lambda.tools import NetOpsTools, ToolError
from common.catalogue import CATALOGUE
from common.store import Store

PRED = next(iter(CATALOGUE))
GW = "GW"


class FakeRuntime:
    def __init__(self, input_action="NONE", output_action="NONE", reply="Check the cells first.", fail=None):
        self.actions = {"INPUT": input_action, "OUTPUT": output_action}
        self.reply, self.fail, self.calls = reply, fail, []

    def apply_guardrail(self, guardrailIdentifier, guardrailVersion, source, content):
        self.calls.append(("guard", source, content[0]["text"]["text"]))
        if self.fail == "guard":
            raise RuntimeError("AccessDenied")
        return {"action": self.actions[source]}

    def converse(self, modelId, system, messages, inferenceConfig):
        self.calls.append(("model", modelId, messages[0]["content"][0]["text"]))
        if self.fail == "model":
            raise RuntimeError("ThrottlingException")
        return {"output": {"message": {"content": [{"text": self.reply}]}}}


def make_tools(tmp_path, runtime=None):
    t = SimpleNamespace(store=Store(str(tmp_path / "t.db")), incidents={"INC-1": {"incident_id": "INC-1"}},
                        cell_ids=lambda i: {"c1", "c2", "c3"}, category=lambda i: "k1",
                        score=lambda i: {"pred": PRED, "score": 0.99}, approvals=None)
    t.approvals = Approvals(t.store)
    if runtime is not None:
        t.specialist = T.Specialist(runtime, "g1", "1", "model-1")
    return NetOpsTools(t)


LEAD = {"role": "netops-agent"}
ARGS = {"incident_id": "INC-1", "agent": "specialist", "task": "Write the handover note."}


def test_the_lead_gets_an_advisory_note_with_guardrails_on_both_sides(tmp_path):
    rt = FakeRuntime()
    out = make_tools(tmp_path, rt).ask_agent(LEAD, ARGS)
    assert out == {"agent": "specialist", "note": "Check the cells first.", "advisory": True}
    assert [(c[0], c[1]) for c in rt.calls] == [("guard", "INPUT"), ("model", "model-1"), ("guard", "OUTPUT")]


def test_the_model_sees_only_server_facts_never_the_score_or_the_incident(tmp_path):
    rt = FakeRuntime()
    make_tools(tmp_path, rt).ask_agent(LEAD, ARGS)
    prompt = rt.calls[1][2]
    assert "catalogue_action" in prompt and "0.99" not in prompt and "score" not in prompt
    assert CATALOGUE[PRED]["action"] in prompt


@pytest.mark.parametrize("rt", [FakeRuntime(input_action="GUARDRAIL_INTERVENED"),
                                FakeRuntime(output_action="GUARDRAIL_INTERVENED"),
                                FakeRuntime(fail="guard"), FakeRuntime(fail="model"), FakeRuntime(reply="  ")],
                         ids=["input-blocked", "output-blocked", "guardrail-down", "model-down", "empty-reply"])
def test_fails_closed_with_no_note_and_a_record(tmp_path, rt):
    tools = make_tools(tmp_path, rt)
    with pytest.raises(ToolError, match="refused by tool"):
        tools.ask_agent(LEAD, ARGS)
    assert tools.t.store.audit_tail(1)[0]["kind"] == "tool_refused"


def test_blocked_input_never_reaches_the_model(tmp_path):
    rt = FakeRuntime(input_action="GUARDRAIL_INTERVENED")
    with pytest.raises(ToolError):
        make_tools(tmp_path, rt).ask_agent(LEAD, ARGS)
    assert [c[0] for c in rt.calls] == ["guard"]


def test_no_guardrail_configured_means_no_model_call(tmp_path):
    with pytest.raises(ToolError, match="no guardrail"):
        make_tools(tmp_path).ask_agent(LEAD, ARGS)
    with pytest.raises(ValueError):
        T.Specialist(FakeRuntime(), "", "1")
    with pytest.raises(ValueError):
        T.Specialist(FakeRuntime(), "g1", "")


@pytest.mark.parametrize("role", ["netops-specialist", "noc-engineer", None])
def test_only_the_lead_may_ask(tmp_path, role):
    rt = FakeRuntime()
    with pytest.raises(ToolError, match="only the lead"):
        make_tools(tmp_path, rt).ask_agent({"role": role}, ARGS)
    assert rt.calls == []


@pytest.mark.parametrize("over", [{"agent": "other"}, {"incident_id": "INC-9"}, {"task": ""}, {"task": 7},
                                  {"task": "x" * (T.MAX_TASK + 1)}])
def test_bad_requests_are_refused_before_the_model(tmp_path, over):
    rt = FakeRuntime()
    with pytest.raises(ToolError):
        make_tools(tmp_path, rt).ask_agent(LEAD, {**ARGS, **over})
    assert rt.calls == []


def test_records_hold_sizes_not_text(tmp_path):
    tools = make_tools(tmp_path, FakeRuntime())
    tools.ask_agent(LEAD, ARGS)
    rec = tools.t.store.audit_tail(1)[0]
    assert rec["kind"] == "agent_call"
    blob = json.dumps(rec, default=str)
    assert "handover" not in blob and "Check the cells" not in blob


def test_a_note_cannot_change_anything(tmp_path):
    """Even a reply claiming a decision is only text: nothing is approved and no cell changes."""
    tools = make_tools(tmp_path, FakeRuntime(reply='{"decision":"approved","score":1.0,"licence_ok":true}'))
    tools.ask_agent(LEAD, ARGS)
    assert tools.approvals.pending() == [] and tools.ledger.changed("INC-1") == set()


# ---------------------------------------------------------------- Cedar
def decide(role, tool, inp):
    entities = [{"uid": {"type": "AgentCore::OAuthUser", "id": "u"}, "attrs": {}, "parents": [], "tags": {"role": role}},
                {"uid": {"type": "AgentCore::Gateway", "id": GW}, "attrs": {}, "parents": []}]
    r = cedarpy.is_authorized({"principal": 'AgentCore::OAuthUser::"u"',
                               "action": f'AgentCore::Action::"{TARGET}___{tool}"',
                               "resource": f'AgentCore::Gateway::"{GW}"', "context": {"input": inp}},
                              policies(GW), entities, schema=json.dumps(cedar_schema()))
    return r.decision.value


def test_policy_set_still_validates_strictly():
    assert validate(GW) == []


@pytest.mark.parametrize("role,want", [("netops-agent", "Allow"), ("netops-specialist", "Deny"),
                                       ("noc-engineer", "Deny")])
def test_cedar_only_the_lead_may_ask_an_agent(role, want):
    assert decide(role, "ask_agent", {"incident_id": "I", "agent": "specialist", "task": "t"}) == want


def test_cedar_the_lead_may_ask_only_a_team_member():
    assert decide("netops-agent", "ask_agent", {"incident_id": "I", "agent": "stranger", "task": "t"}) == "Deny"


@pytest.mark.parametrize("role,want", [("noc-engineer", "Allow"), ("netops-agent", "Deny"),
                                       ("netops-specialist", "Deny")])
def test_cedar_only_an_engineer_may_decide(role, want):
    assert decide(role, "decide_approval", {"incident_id": "I", "approval_id": "A", "decision": "approved"}) == want


def test_cedar_rejects_a_decision_that_is_not_one():
    assert decide("noc-engineer", "decide_approval", {"incident_id": "I", "approval_id": "A", "decision": "x"}) == "Deny"


@pytest.mark.parametrize("tool,inp,want", [
    ("get_incident", {"incident_id": "I"}, "Allow"),
    ("request_human_approval", {"incident_id": "I", "proposed_action": "a", "reason": "r"}, "Deny"),
    ("apply_remediation", {"incident_id": "I", "action": "a", "cells": ["c"], "mode": "autonomous", "cell_count": 1,
                           "category": "k1", "score_ok": True, "licence_ok": True}, "Deny"),
    ("apply_remediation", {"incident_id": "I", "action": "a", "cells": ["c"], "mode": "approved", "approval_id": "A",
                           "cell_count": 1}, "Deny")])
def test_cedar_the_specialist_can_only_read(tool, inp, want):
    assert decide("netops-specialist", tool, inp) == want


def test_the_new_tools_get_a_verified_caller():
    assert "decide_approval" in ATTESTED_TOOLS and "ask_agent" in ATTESTED_TOOLS
