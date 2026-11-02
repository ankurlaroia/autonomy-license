"""Smoke-test preparation (S1-S4) without AWS: key bootstrap fails closed, event-shape logs carry no values,
the package carries no secrets, and the stub bundle drives the real tool Lambda handler to one ALLOW and one DENY."""
import json
import os
from types import SimpleNamespace

import pytest

from aws import lambda_bootstrap as B
from aws.infra import package, stub_bundle
from common.catalogue import BLAST_RADIUS, CATALOGUE
from model.scorer import ScoreCache


def test_issuer_key_needs_exactly_one_source():
    with pytest.raises(RuntimeError):
        B.issuer_public_key_from_env({})
    with pytest.raises(RuntimeError):
        B.issuer_public_key_from_env({"AL_ISSUER_KMS_KEY": "k", "AL_ISSUER_PUBLIC_KEY_PEM": "p"})


def test_shape_never_logs_values(capsys, monkeypatch):
    monkeypatch.setenv("AL_LOG_EVENT_SHAPE", "1")
    ctx = SimpleNamespace(client_context=SimpleNamespace(custom={"bedrockAgentCoreToolName": "NetOps___x"}, env=None))
    B.log_shape("t", {"incident_id": "INC-SECRET", "cells": ["gNB-SECRET"], "n": 3}, ctx)
    out = capsys.readouterr().out
    assert "SECRET" not in out and "NetOps___x" not in out
    assert json.loads(out)["event"] == {"incident_id": "str", "cells": ["str", "len=1"], "n": "int"}


def test_shape_silent_by_default(capsys, monkeypatch):
    monkeypatch.delenv("AL_LOG_EVENT_SHAPE", raising=False)
    B.log_shape("t", {"a": 1}, None)
    assert capsys.readouterr().out == ""


def test_package_has_handlers_and_no_secrets():
    arcs = [a for _, a in package.collect()]
    assert "aws/tool_lambda/handler.py" in arcs and "aws/interceptor/handler.py" in arcs
    assert not any(a.endswith((".pem", ".env")) or a.startswith(("state/", "data/", "tests/")) for a in arcs)


def test_package_refuses_missing_bundle(tmp_path):
    with pytest.raises(SystemExit):
        package.collect(bundle=str(tmp_path))


@pytest.fixture(scope="module")
def bundle(tmp_path_factory):
    out = tmp_path_factory.mktemp("bundle")
    info = stub_bundle.build(str(out))
    return out, info


@pytest.fixture
def lam(bundle, tmp_path, monkeypatch):
    out, _ = bundle
    env = json.load(open(out / "lambda_env.json"))
    env.update(AL_DATA_DIR=str(out / "data"), AL_DB_SEED=str(out / "al.db"), AL_DB=str(tmp_path / "al.db"),
               AL_LOG_EVENT_SHAPE="0", AL_ROLE_CONTEXT_KEY="role")
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    B.trusted_from_env.cache_clear()
    from aws.tool_lambda import handler
    yield handler.lambda_handler
    B.trusted_from_env.cache_clear()


def ctx(tool, role="netops-agent"):
    return SimpleNamespace(client_context=SimpleNamespace(custom={"bedrockAgentCoreToolName": f"NetOps___{tool}",
                                                                  "role": role}))


def pick(out, threshold, min_cells):
    scores = ScoreCache(str(out / "data" / "scores.jsonl"))
    for line in open(out / "data" / "incidents.jsonl"):
        inc = json.loads(line)
        s = scores.get(inc["incident_id"])
        if (s["score"] >= threshold and CATALOGUE[s["pred"]]["cls"] == "AUTO"
                and len(inc["cells"]) >= min_cells):
            return inc, CATALOGUE[s["pred"]]["action"]
    pytest.skip(f"no stub incident with >= {min_cells} cells")


def test_bundle_is_synthetic_and_keeps_private_key_out(bundle):
    out, info = bundle
    assert info["data_source"] == "synthetic"
    env = json.load(open(out / "lambda_env.json"))
    assert "PRIVATE" not in env["AL_ISSUER_PUBLIC_KEY_PEM"] and "AL_ISSUER_KMS_KEY" not in env
    assert sorted(os.listdir(out)) == ["al.db", "data", "lambda_env.json", "stub_info.json"]


def test_S4_rehearsal_allow_two_cells(bundle, lam):
    out, info = bundle
    inc, action = pick(out, info["threshold"], 2)
    cells = [c["cell_id"] for c in inc["cells"]][:2]
    assert lam({"incident_id": inc["incident_id"]}, ctx("get_incident"))["ok"]
    r = lam({"incident_id": inc["incident_id"], "action": action, "cells": cells, "mode": "autonomous"},
            ctx("apply_remediation"))
    assert r["ok"], r


def test_S4_rehearsal_deny_over_blast_radius_even_with_lie(bundle, lam):
    out, info = bundle
    inc, action = pick(out, info["threshold"], BLAST_RADIUS + 1)
    cells = [c["cell_id"] for c in inc["cells"]]
    r = lam({"incident_id": inc["incident_id"], "action": action, "cells": cells, "mode": "autonomous",
             "cell_count": 2}, ctx("apply_remediation"))
    assert not r["ok"] and "blast radius" in r["error"]
