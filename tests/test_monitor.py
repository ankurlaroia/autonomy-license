"""Self-revoking licence: false revocations stay under delta when the error rate is <= alpha (Ville), real
drift revokes, outcomes are idempotent, and the agent goes to a human after an automatic revoke."""
import json
import os
import random

import pytest

from common.store import Store
from demo.engine import Demo, drift_dir_for
from license.monitor import RiskMonitor
from license.registry import Registry

ALPHA, DELTA = 0.05, 0.05


class MemStore:
    def __init__(self):
        self.kv, self.audits = {}, []

    def kv_get(self, k, default=None):
        return self.kv.get(k, default)

    def kv_set(self, k, v):
        self.kv[k] = v

    def audit(self, kind, record):
        self.audits.append(kind)


class MemReg:
    def __init__(self):
        self.st = {"L": "active"}

    def status(self, jti):
        return self.st[jti]

    def set_status(self, jti, status, note=""):
        self.st[jti] = status


@pytest.fixture
def reg(tmp_path):
    s = Store(str(tmp_path / "m.db"))
    r = Registry(s)
    r.put("L1", "tok")
    return s, r


def test_false_revocation_rate_under_delta_at_alpha():
    """Monte Carlo at the boundary p = alpha, checked after every outcome (the anytime case)."""
    rng = random.Random(7)
    fired = 0
    runs = 300
    for _ in range(runs):
        r = MemReg()
        m = RiskMonitor(MemStore(), r, ALPHA, DELTA)
        for t in range(400):
            m.record("L", f"i{t}", rng.random() < ALPHA)
            if r.status("L") == "revoked":
                fired += 1
                break
    assert fired / runs <= DELTA + 0.02     # Ville bound delta; slack for Monte Carlo noise


def test_high_error_rate_revokes_with_audit(reg):
    s, r = reg
    m = RiskMonitor(s, r, ALPHA, DELTA)
    rng = random.Random(1)
    t = 0
    while r.status("L1") == "active" and t < 500:
        st = m.record("L1", f"i{t}", rng.random() < 0.3)
        t += 1
    assert r.status("L1") == "revoked" and st["revoked_at"] == t and st["e_value"] >= 1 / DELTA
    assert any(a["kind"] == "licence_auto_revoked" for a in s.audit_tail(10))


def test_duplicate_outcome_is_ignored(reg):
    s, r = reg
    m = RiskMonitor(s, r, ALPHA, DELTA)
    m.record("L1", "i1", True)
    st = m.record("L1", "i1", True)
    assert st.get("duplicate") and st["n"] == 1 and st["errors"] == 1


def test_never_reactivates_or_rewrites_a_revoked_licence(reg):
    s, r = reg
    r.set_status("L1", "revoked", "manual")
    m = RiskMonitor(s, r, ALPHA, DELTA)
    for t in range(20):
        m.record("L1", f"i{t}", True)
    assert r.status("L1") == "revoked" and s.q("SELECT note FROM licences WHERE jti='L1'")[0][0] == "manual"


def test_moment7_stays_active_in_distribution_and_revokes_on_drift(tmp_path):
    d = Demo(data_dir=str(tmp_path / "data"), db=str(tmp_path / "al.db"), fresh=True)
    d.moment1_earn()
    m = d.moment7_self_revoke()
    assert m["in_distribution"]["revoked_after"] is None and m["in_distribution"]["peak_e"] < m["revoke_at_e"]
    assert m["synthetic_drift"]["revoked_after"] and m["status"] == "revoked"
    assert m["next_call"]["outcome"] == "HUMAN"


def test_moment7_drift_revokes_a_fresh_licence_and_leaves_the_proven_one_alone(tmp_path):
    d = Demo(data_dir=str(tmp_path / "data"), db=str(tmp_path / "al.db"), fresh=True)
    d.moment1_earn()
    m = d.moment7_self_revoke()
    a = m["in_distribution"]
    assert a["jti"] != m["jti"] and a["status"] == "active" and d.trusted.registry.status(a["jti"]) != "revoked"
    assert _seen(d, m["jti"])[:1] and len(_seen(d, m["jti"])) == m["synthetic_drift"]["outcomes"]   # starts from zero


def test_moment7_drift_from_a_stand_in_never_touches_this_datas_outcomes(tmp_path):
    Demo(data_dir=str(tmp_path / "stand_in"), db=str(tmp_path / "s.db"), fresh=True)   # builds a synthetic set
    d = Demo(data_dir=str(tmp_path / "data"), db=str(tmp_path / "al.db"), fresh=True)
    d.moment1_earn()
    m = d.moment7_self_revoke(drift_dir=str(tmp_path / "stand_in"))
    assert m["synthetic_drift"]["incidents"] == "synthetic stand-in"
    assert m["synthetic_drift"]["revoked_after"] and m["status"] == "revoked"
    seen = _seen(d, m["jti"])
    assert seen and all(i.startswith("synthetic:") for i in seen[-m["synthetic_drift"]["outcomes"]:])


def test_real_data_takes_its_drift_stream_from_the_synthetic_stand_in(tmp_path):
    (tmp_path / "split_hashes.json").write_text(json.dumps({"source": "telelogs"}))
    assert drift_dir_for(str(tmp_path)).endswith(os.path.join("state", "data.synthetic"))
    (tmp_path / "split_hashes.json").write_text(json.dumps({"source": "synthetic"}))
    assert drift_dir_for(str(tmp_path)) == str(tmp_path)


def _seen(d, jti):
    return RiskMonitor(d.store, d.trusted.registry, d.alpha).state(jti)["seen"]
