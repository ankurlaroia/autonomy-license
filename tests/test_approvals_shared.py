"""Approvals on AWS: the request, the decision and the change can land in different Lambda containers, so they share
a table. Both stores keep the same rules: decided once, only while fresh, spent once, and only an engineer decides."""
import re
import time
from types import SimpleNamespace

import pytest

from aws.tool_lambda import approvals as A
from aws.tool_lambda.tools import NetOpsTools, ToolError
from common.store import Store


class ConditionalCheckFailedException(Exception):
    pass


RESERVED = {"consumed", "decision", "role"}      # from DynamoDB's reserved words, the ones this table's fields hit


def assert_no_reserved(*expressions):
    """Live run 2026-11-02: an unaliased `consumed` failed every UpdateItem with a ValidationException."""
    words = set(re.findall(r"(?<![#:\w])[a-z_]+", " ".join(expressions).lower()))
    assert not words & RESERVED, words & RESERVED


class FakeDdb:
    """Just enough of DynamoDB: the condition expressions the store uses, evaluated on the stored item."""

    def __init__(self):
        self.items = {}

    def put_item(self, TableName, Item, ConditionExpression):
        assert TableName == "al-approvals" and ConditionExpression == "attribute_not_exists(approval_id)"
        self.items[Item["approval_id"]["S"]] = dict(Item)

    def get_item(self, TableName, Key, ConsistentRead):
        assert ConsistentRead
        it = self.items.get(Key["approval_id"]["S"])
        return {"Item": it} if it else {}

    def update_item(self, TableName, Key, UpdateExpression, ConditionExpression, ExpressionAttributeValues,
                    ExpressionAttributeNames):
        assert_no_reserved(UpdateExpression, ConditionExpression)
        it = self.items.get(Key["approval_id"]["S"])
        v = ExpressionAttributeValues
        if ":one" in v:
            ok =it and it["consumed"]["N"] == "0" and it["decision"]["S"] == "approved"
            new = {"consumed": v[":one"]}
        else:
            ok = it and it["decision"]["S"] == "pending" and int(it["created_at"]["N"]) >= int(v[":oldest"]["N"])
            new = {"decision": v[":d"], "decided_by": v[":by"], "role": v[":r"], "expires_at": v[":e"]}
        if not ok:
            raise ConditionalCheckFailedException()
        it.update(new)

    def scan(self, TableName, FilterExpression, ConsistentRead, ExpressionAttributeNames, ExpressionAttributeValues):
        return {"Items": [i for i in self.items.values() if i["decision"]["S"] == "pending"]}


@pytest.fixture(params=["sqlite", "dynamo"])
def store(request, tmp_path):
    if request.param == "sqlite":
        return A.Approvals(Store(str(tmp_path / "t.db")))
    return A.DynamoApprovals(FakeDdb(), "al")


def req(s):
    return s.request("INC-1", "act", ["c2", "c1"], "why")


def test_request_is_pending_and_bound_to_the_exact_action(store):
    aid = req(store)
    rec = store.get(aid)
    assert rec["decision"] == "pending" and rec["incident_id"] == "INC-1" and not rec["consumed"]
    assert rec["action_digest"] == A.action_digest("INC-1", "act", ["c1", "c2"])
    assert rec["request"]["cells"] == ["c1", "c2"] and [p["approval_id"] for p in store.pending()] == [aid]


def test_a_decision_is_final(store):
    aid = req(store)
    store.decide(aid, "noc-engineer", decision="denied")
    with pytest.raises(PermissionError, match="not waiting"):
        store.decide(aid, "noc-engineer", decision="approved")
    assert store.get(aid)["decision"] == "denied" and store.pending() == []


def test_unknown_approval_cannot_be_decided_or_spent(store):
    with pytest.raises(PermissionError):
        store.decide("APR-none", "noc-engineer")
    with pytest.raises(PermissionError):
        store.consume("APR-none")
    assert store.get("APR-none") is None


def test_stale_request_cannot_be_approved(store, monkeypatch):
    aid = req(store)
    t = time.time() + A.TTL_S + 5
    monkeypatch.setattr(A.time, "time", lambda: t)
    with pytest.raises(PermissionError, match="stale"):
        store.decide(aid, "noc-engineer")


def test_an_approval_is_spent_once(store):
    aid = req(store)
    store.decide(aid, "noc-engineer")
    store.consume(aid)
    with pytest.raises(PermissionError, match="already used"):
        store.consume(aid)
    with pytest.raises(PermissionError, match="already used"):
        A.verify_approval(store.get(aid), digest=store.get(aid)["action_digest"])


def test_dynamo_cannot_spend_an_undecided_approval():
    s = A.DynamoApprovals(FakeDdb(), "al")
    with pytest.raises(PermissionError):
        s.consume(req(s))


def test_dynamo_errors_other_than_the_condition_are_not_hidden():
    class Broken(FakeDdb):
        def update_item(self, **kw):
            raise RuntimeError("AccessDenied")
    s = A.DynamoApprovals(Broken(), "al")
    with pytest.raises(RuntimeError):
        s.decide(req(s), "noc-engineer")


# ---------------------------------------------------------------- the decide tool
@pytest.fixture
def tools(tmp_path):
    t = SimpleNamespace(store=Store(str(tmp_path / "t.db")), incidents={"INC-1": {"incident_id": "INC-1"}},
                        approvals=A.DynamoApprovals(FakeDdb(), "al"))
    return NetOpsTools(t)


def kinds(tools):
    return [r["kind"] for r in tools.t.store.audit_tail(20)]


ENGINEER = {"role": "noc-engineer"}


def ask(tools):
    return tools.request_human_approval({"role": "netops-agent"}, {"incident_id": "INC-1", "proposed_action": "act",
                                                                   "cells": ["c1"], "reason": "why"})["approval_id"]


@pytest.mark.parametrize("role", ["netops-agent", "netops-specialist", None, "admin"])
def test_only_an_engineer_may_decide(tools, role):
    aid = ask(tools)
    with pytest.raises(ToolError, match="only a NOC engineer"):
        tools.decide_approval({"role": role}, {"incident_id": "INC-1", "approval_id": aid, "decision": "approved"})
    assert tools.approvals.get(aid)["decision"] == "pending" and kinds(tools)[0] == "tool_refused"


def test_the_approver_is_the_verified_role_not_a_name_in_the_arguments(tools):
    aid = ask(tools)
    tools.decide_approval(ENGINEER, {"incident_id": "INC-1", "approval_id": aid, "decision": "approved",
                                     "decided_by": "someone-else", "role": "admin"})
    rec = tools.approvals.get(aid)
    assert rec["decided_by"] == "noc-engineer" and rec["role"] == "noc-engineer"
    assert kinds(tools)[0] == "approval_decided"


@pytest.mark.parametrize("args", [{"incident_id": "INC-2", "decision": "approved"},     # another incident's approval
                                  {"incident_id": "INC-1", "decision": "maybe"},
                                  {"incident_id": "INC-1"}])
def test_bad_decisions_change_nothing(tools, args):
    aid = ask(tools)
    with pytest.raises(ToolError):
        tools.decide_approval(ENGINEER, {"approval_id": aid, **args})
    assert tools.approvals.get(aid)["decision"] == "pending"


def test_the_fake_catches_an_unaliased_reserved_word():
    with pytest.raises(AssertionError):
        assert_no_reserved("SET consumed = :one")
    assert_no_reserved("SET #c = :one", "#c = :zero AND #d = :a AND created_at >= :o")


def test_a_failing_approval_store_means_no_change_and_a_record(tools, monkeypatch):
    """Live run 2026-11-02: the store errored while spending an approval. Refused, but it left no refusal record."""
    tools.t.cell_ids = lambda i: {"c1"}
    aid = ask(tools)
    tools.decide_approval(ENGINEER, {"incident_id": "INC-1", "approval_id": aid, "decision": "approved"})

    def broken(_):
        raise RuntimeError("ValidationException")
    monkeypatch.setattr(tools.approvals, "consume", broken)
    with pytest.raises(ToolError, match="refused by tool"):
        tools.apply_remediation(ENGINEER, {"incident_id": "INC-1", "action": "act", "cells": ["c1"], "mode": "approved",
                                           "approval_id": aid})
    assert kinds(tools)[0] == "tool_refused" and "remediation_applied" not in kinds(tools)


def test_an_empty_approval_id_is_no_approval(tools):
    with pytest.raises(ToolError, match="no such approval"):
        tools.decide_approval(ENGINEER, {"incident_id": "INC-1", "approval_id": "", "decision": "approved"})


def test_approval_for_an_unknown_incident_is_refused(tools):
    with pytest.raises(ToolError, match="unknown incident"):
        tools.request_human_approval({"role": "netops-agent"}, {"incident_id": "INC-9", "proposed_action": "act",
                                                                "reason": "why"})
