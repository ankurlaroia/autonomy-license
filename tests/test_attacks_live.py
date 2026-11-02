"""Live attack scorecard, offline parts: verdicts never count an ALLOW or an ERROR as blocked; the picked
incidents really are over the blast radius / under the threshold; tampering changes only the signature."""
import json

import pytest

from aws.infra import attacks_live as L
from aws.infra import stub_bundle
from common.catalogue import BLAST_RADIUS
from model.scorer import ScoreCache


def test_verdicts():
    deny = {"error": {"code": -32002, "message": "Tool Execution Denied: Tool call not allowed due to policy"}}
    assert L.verdict(deny)["verdict"] == "BLOCKED" and "Cedar" in L.verdict(deny)["by"]
    refused = {"result": {"content": [{"type": "text", "text": json.dumps({"ok": False, "error": "nope"})}]}}
    assert L.verdict(refused) == {"verdict": "BLOCKED", "by": "tool Lambda recheck (Path B)", "detail": "nope"}
    assert L.verdict({"error": {"http": 401, "body": ""}})["verdict"] == "BLOCKED"
    ok = {"result": {"content": [{"type": "text", "text": json.dumps({"ok": True})}]}}
    assert L.verdict(ok)["verdict"] == "GOT_THROUGH"
    assert L.verdict({"error": {"http": 500, "body": "boom"}})["verdict"] == "ERROR"


def test_tamper_changes_only_the_signature():
    t = "aGVhZA.Ym9keQ.c2ln"
    h, b, s = L.tamper(t).split(".")
    assert (h, b) == ("aGVhZA", "Ym9keQ") and s != "c2ln" and len(s) == 4


@pytest.fixture(scope="module")
def bundle(tmp_path_factory):
    out = tmp_path_factory.mktemp("b")
    info = stub_bundle.build(str(out))
    return str(out), info["threshold"]


def test_picked_incidents_fit_each_attack(bundle):
    path, lam = bundle
    inc = L.pick(path, lam)
    sc = ScoreCache(f"{path}/data/scores.jsonl")
    assert len(inc["big"]["cells"]) > BLAST_RADIUS and sc.get(inc["big"]["incident_id"])["score"] >= lam
    assert sc.get(inc["low"]["incident_id"])["score"] < lam
    rows = L.attacks(inc)
    assert len(rows) == 7 and {k for _, k, _ in rows} == {"agent", "none", "tampered"}
    assert all(a["mode"] in ("autonomous", "approved") for _, _, a in rows)


def test_split_attack_is_the_rest_of_the_big_incident_after_an_allowed_first_part(bundle):
    path, lam = bundle
    inc = L.pick(path, lam)
    setup = L.split_setup(inc)
    _, _, attack = [r for r in L.attacks(inc) if r[0] == L.SPLIT][0]
    assert setup["incident_id"] == attack["incident_id"] == inc["big"]["incident_id"]
    assert len(setup["cells"]) == BLAST_RADIUS and 0 < len(attack["cells"]) <= BLAST_RADIUS   # each call fits
    assert not set(setup["cells"]) & set(attack["cells"])                                     # together they do not
