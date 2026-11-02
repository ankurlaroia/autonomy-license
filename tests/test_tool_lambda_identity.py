"""Path B caller identity: the role comes only from the Gateway-controlled Lambda context, never from
tool arguments; missing or unknown identity fails closed."""
from types import SimpleNamespace

import pytest

from aws.interceptor.handler import intercept
from aws.tool_lambda import handler as H

KEY = "test-caller-role"


def mutations(d):
    return d.store.q("SELECT COUNT(*) FROM sim_actions")[0][0]


def ctx(role=None, tool="apply_remediation"):
    custom = {"bedrockAgentCoreToolName": f"NetOps___{tool}"}
    if role is not None:
        custom[KEY] = role
    return SimpleNamespace(client_context=SimpleNamespace(custom=custom))


@pytest.fixture
def lam(demo, monkeypatch):
    monkeypatch.setattr(H, "trusted_from_env", lambda: demo.trusted)
    monkeypatch.setenv("AL_ROLE_CONTEXT_KEY", KEY)
    return H.lambda_handler


def auto_call(d):
    t = d.threshold()
    iid = d.heldout_where(lambda i: d.scores.get(i)["pred"] == "C2" and d.scores.get(i)["score"] >= t)
    cell = d.trusted.public_incident(iid)["cells"][0]["cell_id"]
    return {"incident_id": iid, "action": "adjust_tilt", "cells": [cell], "mode": "autonomous"}


def test_agent_role_from_context_allows_licensed_autonomous_call(demo, lam):
    before = mutations(demo)
    r = lam(auto_call(demo), ctx("netops-agent"))
    assert r["ok"], r
    assert mutations(demo) == before + 1


def test_caller_role_in_arguments_is_ignored(demo, lam):
    before = mutations(demo)
    args = {**auto_call(demo), "mode": "approved", "approval_id": "APR-x", "_caller_role": "noc-engineer"}
    r = lam(args, ctx("netops-agent"))
    assert not r["ok"] and "engineers only" in r["error"]
    assert mutations(demo) == before


@pytest.mark.parametrize("role", [None, "admin", ""])
def test_missing_or_unknown_identity_fails_closed(demo, lam, role):
    before = mutations(demo)
    r = lam({**auto_call(demo), "_caller_role": "netops-agent"}, ctx(role))
    assert not r["ok"] and "agent role only" in r["error"]
    assert mutations(demo) == before


def test_unset_role_key_fails_closed(demo, lam, monkeypatch):
    monkeypatch.delenv("AL_ROLE_CONTEXT_KEY")
    assert H.caller_role(ctx("netops-agent")) is None
    assert not lam(auto_call(demo), ctx("netops-agent"))["ok"]


def test_interceptor_drops_underscore_identity_fields(demo):
    out = intercept("apply_remediation", {**auto_call(demo), "_caller_role": "noc-engineer"}, {}, demo.trusted)
    assert "_caller_role" not in out["input"] and "_caller_role" in out["notes"]
