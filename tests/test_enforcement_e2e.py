"""End-to-end release-checklist rows through the local Gateway stack:
IdP tags -> interceptor -> Cedar -> tool Lambda (Path B) -> simulator -> audit."""
import json

import pytest

from aws.cedar.engine import PolicyEngine
from common.catalogue import BLAST_RADIUS, CATALOGUE
from federation import warnings as W
from gateway.local_gateway import DENIED


def mutations(d):
    return d.store.q("SELECT COUNT(*) FROM sim_actions")[0][0]


def auto_c2(d, skip=0):
    lam = d.threshold()
    return d.heldout_where(lambda i: d.scores.get(i)["pred"] == "C2" and d.scores.get(i)["score"] >= lam, skip)


def test_T01_allow_changes_state(demo):
    t = demo.agent["A"].handle(auto_c2(demo), demo.threshold())
    assert t["outcome"] == "AUTO_APPLIED"
    r = t["steps"][0]["result"]
    assert all(r["after"][c]["downtilt_deg"] == round(r["before"][c]["downtilt_deg"] - 2, 2) for c in r["before"])


def test_T02_below_threshold_goes_to_human_without_autonomous_call(demo):
    lam = demo.threshold()
    iid = demo.heldout_where(lambda i: demo.scores.get(i)["score"] < lam)
    t = demo.agent["A"].handle(iid, lam)
    assert t["outcome"] == "HUMAN" and [s["call"] for s in t["steps"]] == ["request_human_approval"]


def test_T11_T29_five_cells_with_lie_denied_no_mutation(demo):
    before = mutations(demo)
    t = demo.agent["A"].handle(auto_c2(demo, 1), demo.threshold(), force_cells=5, claim_cell_count=2)
    st = t["steps"][0]
    assert st["isError"] and st["text"] == DENIED and "F1" in st["policy"]["policies"]
    assert mutations(demo) == before


def test_T12_engineer_approval_cannot_override_blast_radius(demo):
    t = demo.agent["A"].handle(auto_c2(demo, 1), demo.threshold(), force_cells=5)
    before = mutations(demo)
    r = demo.engineer["A"].approve_and_execute(t["approval_id"])
    assert r["isError"] and "F1" in r["policy"]["policies"] and mutations(demo) == before


def test_T26_agent_trust_claims_are_dropped(demo):
    lam = demo.threshold()
    iid = demo.heldout_where(lambda i: demo.scores.get(i)["score"] < lam
                             and CATALOGUE[demo.scores.get(i)["pred"]]["cls"] == "AUTO")
    tok = demo.agent["A"].token()
    inc = demo.trusted.public_incident(iid)
    action = CATALOGUE[demo.scores.get(iid)["pred"]]["action"]
    r = demo.gw["A"].call(tok, "apply_remediation", {
        "incident_id": iid, "action": action, "cells": [inc["cells"][0]["cell_id"]], "mode": "autonomous",
        "licence_valid": True, "score": 0.999, "score_ok": True, "category": "k1"})
    assert r["isError"] and r["interceptor"]["input"]["score_ok"] is False
    assert set(r["interceptor"]["notes"]) >= {"licence_valid", "score", "score_ok", "category"}


def test_T14_category_recomputed_server_side(demo):
    iid = auto_c2(demo)
    tok = demo.agent["A"].token()
    inc = demo.trusted.public_incident(iid)
    r = demo.gw["A"].call(tok, "apply_remediation", {"incident_id": iid, "action": "adjust_tilt",
                                                     "cells": [inc["cells"][0]["cell_id"]], "mode": "autonomous",
                                                     "category": "k9"})
    assert r["interceptor"]["input"]["category"] == demo.trusted.category(iid)


def test_T08_revoked_denies_next_call(demo):
    jti, _ = demo.trusted.registry.current()
    demo.trusted.registry.set_status(jti, "revoked")
    t = demo.agent["A"].handle(auto_c2(demo), demo.threshold())
    assert t["outcome"] == "HUMAN" and t["steps"][0]["isError"]


def test_T06_fingerprint_change_denies(demo):
    demo.trusted.expected_fingerprint = "sha256:new-model"
    t = demo.agent["A"].handle(auto_c2(demo), demo.threshold())
    assert t["outcome"] == "HUMAN"


def test_T15_approval_single_use_and_bound(demo):
    lam = demo.threshold()
    iid = demo.heldout_where(lambda i: demo.scores.get(i)["score"] < lam
                             and CATALOGUE[demo.scores.get(i)["pred"]]["cls"] == "AUTO")
    t = demo.agent["A"].handle(iid, lam)
    first = demo.engineer["A"].approve_and_execute(t["approval_id"])
    assert not first["isError"]
    again = demo.engineer["A"].approve_and_execute(t["approval_id"])          # reuse
    assert again["isError"] and "already used" in again["content"][0]["text"]
    t2 = demo.agent["A"].handle(demo.heldout_where(lambda i: demo.scores.get(i)["score"] < lam
                                                   and CATALOGUE[demo.scores.get(i)["pred"]]["cls"] == "AUTO", 1), lam)
    inc = demo.trusted.public_incident(t2["incident_id"])
    other = [c["cell_id"] for c in inc["cells"]][-1:]                          # different cells
    r = demo.engineer["A"].approve_and_execute(t2["approval_id"], cells_override=other)
    assert r["isError"] and "does not match" in r["content"][0]["text"]


def test_T25_log_only_is_not_enforcement():
    assert PolicyEngine(mode="LOG_ONLY").evaluate("p", {"role": "netops-agent"}, "apply_remediation",
                                                  {"cell_count": 9})["enforced"] is False


def test_T28_audit_has_no_raw_incident_ids(demo):
    demo.moment2_act()
    raw = json.dumps(demo.store.audit_tail(500))
    assert "INC-" not in raw


def test_warnings_rules_T16_T17_T18_T20(demo):
    keyreg = {o: k.public_key() for o, k in demo.op_keys.items()}
    with pytest.raises(W.WarningError):          # hard-rule warnings need a reviewer
        W.make_warning(demo.op_keys["B"], "B", "k1", "hard_rule_deny", "ref")
    tok = W.make_warning(demo.op_keys["B"], "B", "k1", "hard_rule_deny", "ref", reviewer="sec")
    W.receive_warning(demo.store, tok, "A", keyreg)
    with pytest.raises(W.WarningError, match="replayed"):                      # T16
        W.receive_warning(demo.store, tok, "A", keyreg)
    forged = W.make_warning(demo.op_keys["C"], "B", "k2", "drift", "ref")      # signed by C, claims B
    with pytest.raises(W.WarningError):                                        # T17
        W.receive_warning(demo.store, forged, "A", keyreg)
    with pytest.raises(W.WarningError, match="rate limit"):                    # T18
        W.receive_warning(demo.store, W.make_warning(demo.op_keys["B"], "B", "k1", "drift", "r"), "A", keyreg)
    assert demo.trusted.registry.warned_categories("A") == {"k1"}             # T20: only k1 masked


def test_T19_expired_warning_restores_category(demo):
    keyreg = {o: k.public_key() for o, k in demo.op_keys.items()}
    import time
    tok = W.make_warning(demo.op_keys["B"], "B", "k3", "drift", "ref", ttl_s=1, now=int(time.time()) - 5)
    with pytest.raises(W.WarningError):          # already expired on arrival -> rejected, nothing masked
        W.receive_warning(demo.store, tok, "A", keyreg)
    assert "k3" not in demo.trusted.registry.warned_categories("A")


def test_P1_federation_small_operator(demo):
    m5 = demo.moment5_federation()
    assert m5["sum_correct"] and m5["pooled"]["licensed"] and not m5["alone"]["C"]["licensed"]


def test_moment2_shows_a_licensed_fix_and_one_engineer_fix(demo):
    """Moment 2 picks cases the hard rules allow, so the licence (not F1) decides: real C2 faults above the
    threshold span 4-6 cells and were denied by F1 when moment 2 was C2-only (2026-10-31)."""
    m = demo.moment2_act()
    for t in (m["auto"], m["human"]):
        assert len(t["cells"]) <= BLAST_RADIUS
    assert m["auto"]["outcome"] == "AUTO_APPLIED" and m["auto"]["score"] >= demo.threshold()
    assert m["human"]["outcome"] == "HUMAN" and not m["engineer_execution"]["isError"]
