"""Lasting audit records (aws/audit.py): two copies per decision, bound to the run id from the environment,
written before anything acts, and never carrying identity the agent supplied. All offline."""
import json
from types import SimpleNamespace

import pytest

from aws import audit as A
from aws import lambda_bootstrap as B
from aws.infra import stub_bundle
from common.catalogue import BLAST_RADIUS, CATALOGUE
from common.store import Store
from model.scorer import ScoreCache


class FakeDDB:
    def __init__(self, fail=False):
        self.items, self.fail = [], fail

    def put_item(self, TableName, Item, ConditionExpression=None):
        if self.fail:
            raise RuntimeError("AccessDenied")
        assert ConditionExpression == "attribute_not_exists(sk)"      # never overwrites a record
        self.items.append((TableName, Item))


def writer(source, fail=False, run="run-1"):
    lines = []
    w = A.AuditWriter(FakeDDB(fail), "al-audit", run, source, out=lines.append)
    return w, lines


def test_item_and_log_line_are_the_same_record():
    w, lines = writer("tool")
    it = w.write("tool_call", {"trace_id": "t1", "cells": ["c1"]}, "TL-abc")
    (line,) = lines
    got = json.loads(line)
    assert got[A.MARK] == 1 and got["rec_id"] == it["rec_id"]["S"] and got["item"] == "TL-abc"
    assert got["run_id"] == "run-1" and got["sk"].startswith(got["ts"]) and "#tool#" in got["sk"]
    assert A.plain(it)["record"] == {"trace_id": "t1", "cells": ["c1"]}


def test_sort_key_orders_by_time():
    a = A.audit_item("r", "tool", "k", {}, t=1_700_000_000.123)
    b = A.audit_item("r", "interceptor", "k", {}, t=1_700_000_000.124)
    assert a["sk"]["S"] < b["sk"]["S"] and a["ts"]["S"] == "2023-11-14T22:13:20.123Z"


def test_run_id_comes_from_the_environment_only():
    assert A.writer_from_env("tool", env={}) is None                      # local runs: SQLite only
    w = A.writer_from_env("tool", env={"AL_AUDIT_TABLE": "al-audit"}, client=FakeDDB())
    assert w.run_id == A.UNDECLARED
    w = A.writer_from_env("tool", env={"AL_AUDIT_TABLE": "al-audit", "AL_RUN_ID": "r9"}, client=FakeDDB())
    assert w.run_id == "r9" and w.source == "tool"


def test_store_sends_raw_item_to_the_lasting_copy_but_keeps_hashes_locally(tmp_path):
    s = Store(str(tmp_path / "a.db"))
    w, _ = writer("tool")
    A.attach(s, w, {"trace_id": "t7"})
    s.audit("remediation_applied", {"incident_id": "TL-x", "action": "a1"}, "A")
    (_, item), = w.c.items
    assert item["item"]["S"] == "TL-x" and A.plain(item)["record"] == {"action": "a1", "operator": "A",
                                                                       "trace_id": "t7"}
    assert "TL-x" not in json.dumps(s.audit_tail())                       # T28 still holds locally


def test_a_failed_lasting_write_raises():
    w, _ = writer("tool", fail=True)
    with pytest.raises(RuntimeError):
        w.write("tool_call", {})


# ---------------------------------------------------------------- the two Lambdas
@pytest.fixture(scope="module")
def bundle(tmp_path_factory):
    out = tmp_path_factory.mktemp("bundle")
    return out, stub_bundle.build(str(out))


@pytest.fixture
def env(bundle, tmp_path, monkeypatch):
    out, _ = bundle
    e = json.load(open(out / "lambda_env.json"))
    e.update(AL_DATA_DIR=str(out / "data"), AL_DB_SEED=str(out / "al.db"), AL_DB=str(tmp_path / "al.db"),
             AL_LOG_EVENT_SHAPE="0", AL_ROLE_CONTEXT_KEY="role")
    for k, v in e.items():
        monkeypatch.setenv(k, v)
    B.trusted_from_env.cache_clear()
    yield
    B.trusted_from_env.cache_clear()


def pick(out, threshold, min_cells):
    scores = ScoreCache(str(out / "data" / "scores.jsonl"))
    for line in open(out / "data" / "incidents.jsonl"):
        inc = json.loads(line)
        s = scores.get(inc["incident_id"])
        if s["score"] >= threshold and CATALOGUE[s["pred"]]["cls"] == "AUTO" and len(inc["cells"]) >= min_cells:
            return inc, CATALOGUE[s["pred"]]["action"]
    pytest.skip("no suitable stub incident")


def ctx(tool, role="netops-agent"):
    return SimpleNamespace(client_context=SimpleNamespace(custom={"bedrockAgentCoreToolName": f"NetOps___{tool}",
                                                                  "role": role}))


def test_tool_lambda_records_the_call_then_the_change_under_one_trace(bundle, env):
    from aws.tool_lambda import handler
    out, info = bundle
    inc, action = pick(out, info["threshold"], 2)
    w, _ = writer("tool")
    r = handler.lambda_handler({"incident_id": inc["incident_id"], "action": action, "mode": "autonomous",
                                "cells": [c["cell_id"] for c in inc["cells"]][:2], "trace_id": "run-1/3"},
                               ctx("apply_remediation"), writer=w)
    assert r["ok"], r
    kinds = [(i["kind"]["S"], A.plain(i)["record"]["trace_id"]) for _, i in w.c.items]
    assert kinds == [("tool_call", "run-1/3"), ("remediation_applied", "run-1/3")]


def test_tool_lambda_acts_on_nothing_when_its_record_cannot_be_written(bundle, env):
    from aws.tool_lambda import handler
    out, info = bundle
    inc, action = pick(out, info["threshold"], 2)
    w, _ = writer("tool", fail=True)
    r = handler.lambda_handler({"incident_id": inc["incident_id"], "action": action, "mode": "autonomous",
                                "cells": [c["cell_id"] for c in inc["cells"]][:2]}, ctx("apply_remediation"), writer=w)
    assert not r["ok"]
    sim = B.trusted_from_env().store.q("SELECT COUNT(*) FROM sim_actions")[0][0]
    assert sim == 0                                                       # no record, no action


def _gateway_event(args, rpc_id="run-1/5"):
    return {"mcp": {"gatewayRequest": {"headers": {}, "body": {
        "jsonrpc": "2.0", "id": rpc_id, "method": "tools/call",
        "params": {"name": "NetOps___apply_remediation", "arguments": args}}}}}


def test_interceptor_records_server_facts_and_replaces_the_agents_trace_id(bundle, env):
    from aws.interceptor import handler as I
    out, info = bundle
    inc, action = pick(out, info["threshold"], BLAST_RADIUS + 1)
    w, _ = writer("interceptor")
    cells = [c["cell_id"] for c in inc["cells"]]
    res = I.lambda_handler(_gateway_event({"incident_id": inc["incident_id"], "action": action, "cells": cells,
                                           "mode": "autonomous", "cell_count": 2, "trace_id": "forged"}),
                           None, role_from_headers=lambda h: "netops-agent", writer=w)
    sent = res["mcp"]["transformedGatewayRequest"]["body"]["params"]["arguments"]
    assert sent["trace_id"] == "run-1/5" and sent["cell_count"] == len(cells)
    (_, item), = w.c.items
    rec = A.plain(item)["record"]
    assert item["kind"]["S"] == "gateway_request" and item["item"]["S"] == inc["incident_id"]
    assert rec["trace_id"] == "run-1/5" and rec["cell_count"] == len(cells) and "cell_count" in rec["dropped"]


def test_interceptor_fails_closed_when_its_record_cannot_be_written(bundle, env):
    from aws.interceptor import handler as I
    out, info = bundle
    inc, action = pick(out, info["threshold"], 2)
    w, _ = writer("interceptor", fail=True)
    with pytest.raises(RuntimeError):
        I.lambda_handler(_gateway_event({"incident_id": inc["incident_id"], "action": action,
                                         "cells": [inc["cells"][0]["cell_id"]], "mode": "autonomous"}),
                         None, role_from_headers=lambda h: "netops-agent", writer=w)
