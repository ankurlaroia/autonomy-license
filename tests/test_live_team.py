"""The console's approval buttons: the lead's token queues, the engineer's token decides, and every step is a Gateway call."""
import json

import pytest
from fastapi.testclient import TestClient

from api import live as L
from api import server

HOME = {"host": "127.0.0.1:8000", "x-forwarded-host": "localhost:3000", "x-al-live": "1"}
REC = {"approval_id": "APR-1", "incident_id": "I", "request": {"action": "act", "cells": ["secret-cell-1", "c2"],
                                                               "reason": "Check the cells."}, "created_at": "t"}


def ok(result):
    return {"result": {"content": [{"type": "text", "text": json.dumps({"ok": True, "result": result})}], "isError": False}}


class Tokens:
    def token(self, who):
        return who


class Gateway:
    """Answers by tool; `refuse` names tools that get Cedar's deny."""
    c = Tokens()

    def __init__(self, refuse=()):
        self.calls, self.refuse = [], refuse

    def call_traced(self, token, tool, args, trace):
        self.calls.append((token, tool, args, trace))
        if tool in self.refuse:
            return {"error": {"message": "Tool Execution Denied: not allowed by policy"}}
        return ok({"ask_agent": {"note": "Check the cells."}, "request_human_approval": {"approval_id": "APR-1"},
                   "decide_approval": {"decision": args.get("decision")},
                   "apply_remediation": {"action_id": "A1", "resolved": True}}[tool])


class Queue:
    def __init__(self, recs=(REC,)):
        self.recs = list(recs)

    def get(self, aid):
        return next((r for r in self.recs if r["approval_id"] == aid), None)

    def pending(self):
        return self.recs


@pytest.fixture
def make(tmp_path, monkeypatch):
    def _make(gateway=None, queue=None):
        (tmp_path / "dist").mkdir(exist_ok=True)
        (tmp_path / "dist" / "aws_state.json").write_text(json.dumps({"region": "us-east-1", "gateway_url": "u"}))
        link = L.Live(str(tmp_path), session=object(), client=gateway or Gateway())
        monkeypatch.setattr(link, "_need_running", lambda st: None)
        monkeypatch.setattr(link, "_case", lambda st: ("I", "act", ["c1", "c2"]))
        monkeypatch.setattr(link, "_approvals", lambda st: queue or Queue())
        return link
    return _make


def test_ask_uses_the_leads_token_and_changes_nothing(make):
    link = make()
    out = link.team_ask()
    assert [(c[0], c[1]) for c in link._client.calls] == [("agent_client", "ask_agent"),
                                                          ("agent_client", "request_human_approval")]
    assert out["approval_id"] == "APR-1" and out["note"] == "Check the cells." and out["cells"] == 2
    assert L.TRACE.match(out["trace_id"])
    assert "c1" not in json.dumps({k: v for k, v in out.items() if k != "trace_id"})     # the trace id is random hex


def test_a_withdrawn_model_stops_the_ask_and_queues_nothing(make):
    link = make(Gateway(refuse=("ask_agent",)))
    with pytest.raises(L.LiveRefused, match="rules refused"):
        link.team_ask()
    assert [c[1] for c in link._client.calls] == ["ask_agent"]


def test_approve_uses_the_engineers_token_then_applies_with_the_stored_request(make):
    link = make()
    out = link.team_decide("APR-1", "approved")
    assert [(c[0], c[1]) for c in link._client.calls] == [("engineer_client", "decide_approval"),
                                                          ("engineer_client", "apply_remediation")]
    change = link._client.calls[1][2]
    assert change["mode"] == "approved" and change["approval_id"] == "APR-1" and change["cells"] == REC["request"]["cells"]
    assert out["change"]["decision"] == "ALLOW" and out["change"]["action_id"] == "A1"


def test_deny_applies_nothing(make):
    link = make()
    out = link.team_decide("APR-1", "denied")
    assert [c[1] for c in link._client.calls] == ["decide_approval"] and out["change"] is None


def test_a_refused_decision_applies_nothing(make):
    link = make(Gateway(refuse=("decide_approval",)))
    with pytest.raises(L.LiveRefused, match="decision was refused"):
        link.team_decide("APR-1", "approved")
    assert [c[1] for c in link._client.calls] == ["decide_approval"]


@pytest.mark.parametrize("aid,decision", [("APR-1", "maybe"), ("APR-9", "approved")])
def test_unknown_decisions_and_approvals_make_no_call(make, aid, decision):
    link = make()
    with pytest.raises(L.LiveRefused):
        link.team_decide(aid, decision)
    assert link._client.calls == []


def test_the_queue_shown_in_the_browser_has_a_count_not_cell_ids(make):
    got = make().team_pending()
    assert got[0]["cells"] == 2 and got[0]["note"] == "Check the cells." and "secret-cell-1" not in json.dumps(got)


def test_new_records_show_only_whitelisted_fields():
    assert "note" not in L.HOP_FIELDS["agent_call"] and "reason" not in L.HOP_FIELDS["approval_requested"]
    assert "decision" in L.HOP_FIELDS["approval_decided"]


# ---------------------------------------------------------------- routes
class Link:
    def __init__(self):
        self.done = []

    def team_ask(self):
        self.done.append("ask")
        return {}

    def team_decide(self, aid, d):
        self.done.append((aid, d))
        return {}

    def models(self, op):
        self.done.append(op)
        return {}


@pytest.mark.parametrize("path", ["/live/team/ask", "/live/team/decide/APR-1/approved", "/live/models/withdraw"])
def test_routes_need_the_header_and_this_machine(monkeypatch, path):
    client, link = TestClient(server.app), Link()
    monkeypatch.setenv("AL_LIVE", "1")
    monkeypatch.setattr(server, "_live_link", link)
    assert client.post(path, headers={k: v for k, v in HOME.items() if k != "x-al-live"}).status_code == 403
    assert client.post(path, headers={**HOME, "x-forwarded-host": "192.168.1.20:3000"}).status_code == 403
    assert link.done == []
    assert client.post(path, headers=HOME).status_code == 200 and len(link.done) == 1


def test_routes_are_off_by_default(monkeypatch):
    monkeypatch.delenv("AL_LIVE", raising=False)
    client = TestClient(server.app)
    assert client.post("/live/team/decide/APR-1/approved", headers=HOME).status_code == 403
    assert client.get("/live/team/pending", headers=HOME).status_code == 403
