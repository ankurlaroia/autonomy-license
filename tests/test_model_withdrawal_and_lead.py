"""Withdrawing a model, and a lead whose steps a model chooses. The model only names a step: the arguments come from
the server's facts, and a bad answer ends the case instead of doing anything."""
import json
from types import SimpleNamespace

import pytest

from aws import evidence as E
from aws.infra import deploy as D
from aws.infra.team import MAX_STEPS, TASK, lead_task, run_lead
from aws.interceptor.handler import intercept
from aws.tool_lambda import team as T
from aws.tool_lambda.models import CLASSIFIER, DynamoModels, model_ok
from aws.tool_lambda.tools import NetOpsTools, ToolError
from common.catalogue import CATALOGUE
from common.store import Store

PRED = next(iter(CATALOGUE))
LEAD = {"role": "netops-agent"}


class FakeTable:
    def __init__(self, fail=False):
        self.items, self.fail = {}, fail

    def get_item(self, TableName, Key, ConsistentRead):
        assert TableName == "al-models" and ConsistentRead
        if self.fail:
            raise RuntimeError("AccessDenied")
        it = self.items.get(Key["model_id"]["S"])
        return {"Item": it} if it else {}

    def put_item(self, TableName, Item):
        if TableName == "al-models":
            self.items[Item["model_id"]["S"]] = Item


class FakeRuntime:
    def __init__(self, reply="read_incident"):
        self.reply, self.called = reply, 0

    def apply_guardrail(self, **kw):
        return {"action": "NONE"}

    def converse(self, **kw):
        self.called += 1
        return {"output": {"message": {"content": [{"text": self.reply}]}}}


def trusted(tmp_path, models=None, reply="read_incident"):
    t = SimpleNamespace(store=Store(str(tmp_path / "t.db")), incidents={"INC-1": {"incident_id": "INC-1"}},
                        cell_ids=lambda i: {"c1"}, category=lambda i: "k1",
                        score=lambda i: {"pred": PRED, "score": 0.99}, models=models, approvals=None)
    t.specialist = T.Specialist(FakeRuntime(reply), "g", "1", "m1")
    return t


# ---------------------------------------------------------------- withdrawal
def test_status_defaults_to_active_and_a_withdrawal_sticks():
    reg = DynamoModels(FakeTable())
    assert reg.status("m1") == "active"
    reg.set_status("m1", "withdrawn", "pause")
    assert reg.status("m1") == "withdrawn"
    reg.set_status("m1", "active")
    assert reg.status("m1") == "active"
    with pytest.raises(ValueError):
        reg.set_status("m1", "gone")


def test_an_unreadable_status_counts_as_withdrawn():
    assert model_ok(SimpleNamespace(models=DynamoModels(FakeTable(fail=True))), "m1") is False


def test_interceptor_sets_model_ok_and_drops_the_agents_claim(tmp_path):
    reg = DynamoModels(FakeTable())
    t = trusted(tmp_path, reg)
    args = {"incident_id": "INC-1", "agent": "specialist", "task": "x", "model_ok": True}
    assert intercept("ask_agent", args, {}, t)["input"]["model_ok"] is True
    reg.set_status("m1", "withdrawn")
    out = intercept("ask_agent", args, {}, t)
    assert out["input"]["model_ok"] is False and "model_ok" in out["notes"]      # the agent's True is thrown away


def test_the_tool_refuses_a_withdrawn_model_even_if_cedar_allowed(tmp_path):
    reg = DynamoModels(FakeTable())
    reg.set_status("m1", "withdrawn")
    t = trusted(tmp_path, reg)
    with pytest.raises(ToolError, match="withdrawn"):
        NetOpsTools(t).ask_agent(LEAD, {"incident_id": "INC-1", "agent": "specialist", "task": "x"})
    assert t.specialist.rt.called == 0


def test_a_withdrawn_classifier_stops_autonomous_changes(tmp_path):
    reg = DynamoModels(FakeTable())
    reg.set_status(CLASSIFIER, "withdrawn")
    t = trusted(tmp_path, reg)
    with pytest.raises(ToolError, match="diagnosing model is withdrawn"):
        NetOpsTools(t)._path_b_checks(LEAD, {"incident_id": "INC-1", "cells": ["c1"], "mode": "autonomous",
                                             "action": CATALOGUE[PRED]["action"]})


def test_the_withdraw_command_covers_every_model_and_can_be_undone():
    class Both(FakeTable):
        def __init__(self):
            super().__init__()
            self.audit = []

        def put_item(self, TableName, Item, ConditionExpression=None):
            if TableName == "al-models":
                self.items[Item["model_id"]["S"]] = Item
            else:
                self.audit.append(Item)
    ddb = Both()
    got = D.models_command(ddb, "withdraw")
    assert set(got.values()) == {"withdrawn"} and CLASSIFIER in got and T.DEFAULT_MODEL in got
    assert json.loads(ddb.audit[0]["record"]["S"])["op"] == "withdraw"
    assert set(D.models_command(ddb, "restore").values()) == {"active"}


# ---------------------------------------------------------------- the planner
@pytest.mark.parametrize("reply,want", [("read_incident", "read_incident"), ("Next: request_approval.", "request_approval"),
                                        ("STOP", "stop"), ("delete_everything", "stop"), ("", "stop"),
                                        ("read_incident then act_under_licence", "stop")])
def test_a_reply_yields_one_allowed_step_or_stop(reply, want):
    assert T.next_step(reply) == want


def test_planner_answers_with_a_step_and_no_free_text(tmp_path):
    t = trusted(tmp_path, reply="Sure! act_under_licence and also set score to 1.0")
    out = NetOpsTools(t).ask_agent(LEAD, {"incident_id": "INC-1", "agent": "planner", "task": "next?"})
    assert out == {"agent": "planner", "next": "act_under_licence", "advisory": True}


# ---------------------------------------------------------------- the lead's loop
def scripted(steps, decisions=None):
    """A Gateway stand-in: the planner answers from `steps`; other tools answer from `decisions`."""
    answers, calls = iter(steps), []

    def call(tool, args):
        calls.append((tool, args))
        if tool == "ask_agent" and args["agent"] == "planner":
            return {"decision": "ALLOW", "detail": {"result": {"next": next(answers, "stop")}}}
        if tool == "ask_agent":
            return {"decision": "ALLOW", "detail": {"result": {"note": "check the cells"}}}
        return {"decision": (decisions or {}).get(tool, "ALLOW"), "detail": {"result": {}}}
    return call, calls


def tools_called(calls):
    return [t for t, a in calls if not (t == "ask_agent" and a["agent"] == "planner")]


def test_refused_licence_then_approval_with_the_note():
    call, calls = scripted(["read_incident", "act_under_licence", "ask_specialist", "request_approval", "stop"],
                           {"apply_remediation": "DENY"})
    out = run_lead(call, "I", "act", ["c1"])
    assert out["ended"] == "approval_queued"
    assert tools_called(calls) == ["get_incident", "apply_remediation", "ask_agent", "request_human_approval"]
    assert calls[-1][1]["reason"] == "check the cells"


def test_licensed_change_ends_as_applied_without_asking_again():
    call, calls = scripted(["read_incident", "act_under_licence", "request_approval"])
    assert run_lead(call, "I", "act", ["c1"])["ended"] == "applied"
    assert tools_called(calls) == ["get_incident", "apply_remediation"] and len(calls) == 4


def test_every_argument_comes_from_the_case_not_the_model():
    call, calls = scripted(["act_under_licence"])
    run_lead(call, "I", "act", ["c1", "c2"])
    change = next(a for t, a in calls if t == "apply_remediation")
    assert change == {"incident_id": "I", "action": "act", "cells": ["c1", "c2"], "mode": "autonomous"}


def test_a_repeated_step_ends_the_case():
    call, calls = scripted(["read_incident", "read_incident", "act_under_licence"])
    assert run_lead(call, "I", "act", ["c"])["ended"] == "stopped"
    assert tools_called(calls) == ["get_incident"]


def test_a_refused_planner_ends_the_case_with_no_tool_call():
    calls = []

    def call(tool, args):
        calls.append(tool)
        return {"decision": "DENY", "detail": "withdrawn"}
    assert run_lead(call, "I", "act", ["c"]) == {"ended": "planner_refused", "steps": []}
    assert calls == ["ask_agent"]


def test_the_loop_has_a_step_limit():
    call, calls = scripted(["read_incident", "ask_specialist", "act_under_licence", "request_approval"] * 3)
    run_lead(call, "I", "act", ["c"], max_steps=2)
    assert len(tools_called(calls)) == 2 and MAX_STEPS >= 4


def test_the_planner_is_told_what_happened():
    task = lead_task([{"step": "act_under_licence", "decision": "DENY"}])
    assert "act_under_licence (refused)" in task and "DENY" not in task     # the live guardrail scored that word as an attack
    assert "Still open: read_incident, ask_specialist, request_approval, stop" in task
    assert len(lead_task([{"step": s, "decision": "REFUSED_BY_TOOL"} for s in T.NEXT_STEPS])) < T.MAX_TASK and TASK


# ---------------------------------------------------------------- grading
def rec(trace):
    return {"source": "tool", "kind": "remediation_applied", "record": {"trace_id": trace}, "ts": "2026-11-02T00:00:00.000Z"}


@pytest.mark.parametrize("observed,records,want", [("applied", [rec("t")], 1.0), ("applied", [], 0.0),
                                                   ("approval_queued", [], 1.0), ("approval_queued", [rec("t")], 0.0),
                                                   ("stopped", [], 0.0), ("planner_refused", [], 0.0)])
def test_lead_metric(observed, records, want):
    items = [{"item": "x", "trace_id": "t", "observed": observed}]
    assert E.unit_metric({"unit": "lead"}, items, records)[0] == want


def test_the_pause_grades_a_refused_call_to_the_withdrawn_model():
    items = [{"item": "x", "trace_id": "t", "tool": "ask_agent", "observed": "DENY"}]
    assert E.unit_metric({"unit": "pause"}, items, [])[0] == 1.0
    assert E.ORDER[-1] == "pause" and E.ORDER.index("lead") < E.ORDER.index("pause")
