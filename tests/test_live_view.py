"""The console's Live view: off by default, local only, and nothing but ids, decisions and counts reach the browser."""
import json

import pytest
from fastapi.testclient import TestClient

from api import live as L
from api import server
from aws.audit import audit_item

HOME = {"host": "127.0.0.1:8000", "x-forwarded-host": "localhost:3000", "x-al-live": "1"}


@pytest.fixture
def client():
    return TestClient(server.app)


def test_live_view_is_off_by_default(client, monkeypatch):
    monkeypatch.delenv("AL_LIVE", raising=False)
    assert client.get("/live/status", headers=HOME).json() == {"enabled": False}
    assert client.post("/live/call/small", headers=HOME).status_code == 403
    assert client.post("/live/stack/resume", headers=HOME).status_code == 403
    assert client.post("/live/licence/withdraw", headers=HOME).status_code == 403


class FakeLink:
    def __init__(self):
        self.calls = []

    def call(self, kind):
        self.calls.append(kind)
        return {"trace_id": "t"}

    def status(self):
        return {"ready": False}


@pytest.fixture
def on(monkeypatch):
    monkeypatch.setenv("AL_LIVE", "1")
    link = FakeLink()
    monkeypatch.setattr(server, "_live_link", link)
    return link


@pytest.mark.parametrize("headers", [
    {"host": "127.0.0.1:8000", "x-forwarded-host": "192.168.1.20:3000", "x-al-live": "1"},   # a device on the venue wifi
    {"host": "d2cs0n7le40uju.cloudfront.net", "x-al-live": "1"},
    {"host": "localhost.evil.example", "x-al-live": "1"},
    {"host": "127.0.0.1:8000", "x-forwarded-host": "localhost:3000"},                         # no header: a form on another site
])
def test_only_this_machine_can_act(client, on, headers):
    assert client.post("/live/call/small", headers=headers).status_code == 403
    assert on.calls == []


def test_this_machine_can_act(client, on):
    assert client.post("/live/call/small", headers=HOME).json() == {"trace_id": "t"}
    assert on.calls == ["small"]
    assert client.get("/live/status", headers=HOME).json()["enabled"] is True
    assert client.post("/live/call/small", headers={**HOME, "x-forwarded-host": "[::1]:3000"}).status_code == 200


def test_failures_reach_the_browser_as_words_only(client, on, monkeypatch):
    def boom(kind):
        raise RuntimeError("secret-token-abc at https://internal")
    monkeypatch.setattr(on, "call", boom)
    r = client.post("/live/call/small", headers=HOME)
    assert r.status_code == 502 and "secret" not in r.text and "internal" not in r.text

    def no(kind):
        raise L.LiveRefused("The stack is paused. Turn it on first.")
    monkeypatch.setattr(on, "call", no)
    r = client.post("/live/call/small", headers=HOME)
    assert r.status_code == 409 and "paused" in r.json()["detail"]


def test_an_expired_sign_in_says_what_to_do():
    assert "aws login" in L.explain(RuntimeError("Your session has expired. Please reauthenticate"))
    assert "aws login" not in L.explain(ValueError("x"))


def test_a_hop_shows_counts_and_decisions_never_cell_values():
    rec = {"trace_id": "live-1", "tool": "apply_remediation", "action": "adjust_tilt", "mode": "autonomous",
           "cells": ["c1", "c2"], "before": {"c1": {"downtilt_deg": 19.0}}, "after": {"c1": {"pci": 440}}, "action_id": "ACT-1",
           "resolved": True}
    h = L.hop(audit_item("undeclared", "tool", "remediation_applied", rec))
    assert h["fields"]["cells"] == 2 and h["fields"]["action_id"] == "ACT-1"
    blob = json.dumps(h)
    assert "downtilt" not in blob and "pci" not in blob and "c1" not in blob


def test_an_unknown_record_kind_shows_nothing_of_its_record():
    h = L.hop(audit_item("undeclared", "tool", "something_new", {"token": "abc", "secret": "x"}))
    assert h["fields"] == {}


def test_the_cedar_step_says_how_it_is_known():
    deny = {"error": {"code": -32002, "message": "Tool Execution Denied: denied due to F1-1z0axkyl_0"}}
    g = L.gate_decision(deny, [])
    assert g["decision"] == "FORBID" and g["policy"] == "F1" and "reply" in g["basis"]
    ok = {"result": {"content": [{"type": "text", "text": json.dumps({"ok": True})}]}}
    assert L.gate_decision(ok, [{"source": "tool"}])["basis"].startswith("inferred")
    assert L.gate_decision(ok, [])["decision"] == "UNKNOWN"            # no tool record: not claimed as a permit
    assert L.gate_decision({"error": {"http": 403}}, [])["decision"] == "NOT_REACHED"


def _inc(iid, n):
    return {"incident_id": iid, "cells": [{"cell_id": f"{iid}-{i}"} for i in range(n)]}


def test_call_plans():
    small, big = (_inc("S", 4), "a"), (_inc("B", 6), "b")
    assert len(L.plan("small", small, big)["args"]["cells"]) == 2
    lie = L.plan("big", small, big)["args"]
    assert len(lie["cells"]) == 6 and lie["cell_count"] == 2
    split = L.plan("split", small, big)
    assert len(split["setup"]["cells"]) == 3 and len(split["args"]["cells"]) == 2
    assert not set(split["setup"]["cells"]) & set(split["args"]["cells"])
    assert L.plan("tampered", small, big)["token"] == "tampered"
    with pytest.raises(ValueError):
        L.plan("other", small, big)


def test_status_without_a_stack_says_so(tmp_path):
    s = L.Live(str(tmp_path)).status()
    assert s["ready"] is False and "No stack" in s["reason"]


def test_an_unknown_trace_or_call_is_refused(tmp_path):
    link = L.Live(str(tmp_path))
    with pytest.raises(L.LiveRefused):
        link.trace("../../etc")
    with pytest.raises(L.LiveRefused):
        link.trace("live-000000000000")
    with pytest.raises(L.LiveRefused):
        link.call("drop-everything")
