"""Demo engine: one object drives the whole P0/P1 story; the CLI (scripts/demo.py) and the Streamlit
console both call it. Moments follow spec 14.5:

  1 Earn   2 Act   3 Block   4 Revoke   (P0)        5 Federation   6 Warning   (P1)

Demo incidents are picked by the pre-registered rule: the first held-out incident, in the
pre-registered order, meeting each moment's condition. No hand-picked examples.
"""
from __future__ import annotations

import json
import os
import time

from aws.trusted import Trusted
from aws.tool_lambda.approvals import Approvals
from calibration.prereg import choose_grid, load_prereg, write_prereg
from calibration.selective_risk import fixed_sequence_calibrate, local_counts
from common.catalogue import AUTO_ACTIONS, BLAST_RADIUS, CATALOGUE, CATEGORIES
from common.store import Store
from evaluation.metrics import per_operator, selective_report
from federation import warnings as W
from federation.operators import run_round
from gateway.idp import LocalIdP
from gateway.local_gateway import LocalGateway
from license.issuer import issue_licence
from license.signer import LocalSigner
from model.scorer import ScoreCache, SyntheticScorer
from orchestrator.agent import Engineer, Orchestrator

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Demo:
    def __init__(self, data_dir=None, db=None, alpha=0.05, delta=0.10, fresh=False):
        self.data_dir = data_dir or os.path.join(ROOT, "state", "data")
        self.keys = os.path.join(ROOT, "state", "keys")
        self.alpha, self.delta = alpha, delta
        self.store = Store(db or os.path.join(ROOT, "state", "al.db"))
        if fresh:
            self.store.reset()
        self._prepare_data()
        self.issuer = LocalSigner.load_or_create(os.path.join(self.keys, "issuer.pem"), "al-licence-issuer")
        self.op_keys = {o: LocalSigner.load_or_create(os.path.join(self.keys, f"operator-{o}.pem"), f"op-{o}")
                        for o in "ABC"}
        self.splits = json.load(open(os.path.join(self.data_dir, "splits.json")))
        self.scores = ScoreCache(os.path.join(self.data_dir, "scores.jsonl"))
        self.trusted = Trusted.from_dir(self.data_dir, self.store, self.issuer.public_key(), self.scores.fingerprint)
        self.idp = LocalIdP(self.trusted, LocalSigner.load_or_create(os.path.join(self.keys, "idp.pem"), "idp"))
        self.gw = {o: LocalGateway(self.trusted, self.idp, operator=o) for o in "ABC"}
        self.agent = {o: Orchestrator(self.gw[o], self.idp, self.scores, operator=o) for o in "ABC"}
        self.approvals = Approvals(self.store)
        self.engineer = {o: Engineer(self.gw[o], self.idp, self.approvals, operator=o) for o in "ABC"}
        self._prereg()

    # ------------------------------------------------------------------ setup
    def _prepare_data(self):
        if not os.path.exists(os.path.join(self.data_dir, "incidents.jsonl")):
            import subprocess
            import sys
            subprocess.check_call([sys.executable, "-m", "data.prepare_telelogs", "--source", "synthetic",
                                   "--out", self.data_dir], cwd=ROOT)
        sp = os.path.join(self.data_dir, "scores.jsonl")
        if not os.path.exists(sp):
            source = json.load(open(os.path.join(self.data_dir, "split_hashes.json"))).get("source")
            if source != "synthetic":   # never put synthetic scores on real incidents
                raise SystemExit(f"{self.data_dir} holds {source} incidents but no scores.jsonl; score them with "
                                 "python -m aws.infra.score_job run (or model.score_cache --scorer hf)")
            inc = [json.loads(line) for line in open(os.path.join(self.data_dir, "incidents.jsonl"))]
            ScoreCache(sp).build(inc, SyntheticScorer())

    def _prereg(self):
        path = os.path.join(self.data_dir, "PREREG.yaml")
        if not os.path.exists(path):
            pilot = [self.scores.get(i)["score"] for i in self.splits["pilot"]]
            n_cal = sum(len(v) for v in self.splits["operators"].values())
            grid = choose_grid(pilot, n_cal, self.alpha, self.delta)
            hashes = json.load(open(os.path.join(self.data_dir, "split_hashes.json")))
            write_prereg(path, grid=grid, alpha=self.alpha, delta=self.delta, split_hashes=hashes,
                         fingerprint=self.scores.fingerprint)
        self.prereg_sha, self.prereg = load_prereg(path)
        self.grid = self.prereg["grid"]

    @property
    def calibration_ids(self):
        return sum((self.splits["operators"][o] for o in "ABC"), [])

    def heldout_where(self, cond, skip=0):
        hits = [i for i in self.splits["heldout_order"] if cond(i)]
        return hits[skip] if len(hits) > skip else None

    # ------------------------------------------------------------------ calibration + licence
    def calibrate_central(self):
        rows = [self.scores.get(i) for i in self.calibration_ids]
        n, k = local_counts([r["score"] for r in rows], [r["correct"] for r in rows], self.grid)
        return fixed_sequence_calibrate(n, k, self.grid, self.alpha, self.delta)

    def issue(self, calib, aggregation="central", round_id="r-central-01"):
        tok, claims = issue_licence(self.issuer, issuer=self.trusted.issuer, audience=self.trusted.audience,
                                    agent_id="netops-agent-01", fingerprint=self.scores.fingerprint, calib=calib,
                                    categories=CATEGORIES, actions=AUTO_ACTIONS, operators=["A", "B", "C"],
                                    round_id=round_id, prereg_sha=self.prereg_sha, aggregation=aggregation)
        self.trusted.registry.put(claims["jti"], tok)
        self.store.audit("licence_issued", {"jti": claims["jti"], "threshold": calib.threshold,
                                            "n": calib.n_accepted, "k": calib.k_errors,
                                            "upper_bound": calib.upper_bound, "aggregation": aggregation})
        self.store.kv_set("licence_claims", claims)
        return claims

    def licence_claims(self):
        return self.store.kv_get("licence_claims")

    def threshold(self):
        c = self.licence_claims()
        return c["risk"]["threshold"] if c else None

    # ------------------------------------------------------------------ moments
    def moment1_earn(self):
        calib = self.calibrate_central()
        out = {"calibration": {"licensed": calib.licensed, "threshold": calib.threshold, "n": calib.n_accepted,
                               "k": calib.k_errors, "upper_bound": calib.upper_bound, "alpha": self.alpha,
                               "delta": self.delta, "trace": calib.trace, "prereg": self.prereg_sha}}
        if calib.licensed:
            claims = self.issue(calib)
            out["licence"] = {"jti": claims["jti"], "exp": claims["exp"], "scope": claims["scope"],
                              "risk": claims["risk"]}
        out["heldout"] = selective_report(self.scores, self.splits["heldout"], calib.threshold)
        return out

    def _auto_c2(self, i):
        s = self.scores.get(i)
        return s["pred"] == "C2" and s["score"] >= self.threshold()

    def _actionable(self, i):
        """An auto-class diagnosis whose action touches cells within the blast radius: the licence decides, not the hard rule F1.
        Real TeleLogs C2 faults above the threshold span 4-6 cells, so moment 2 is not restricted to C2."""
        action = CATALOGUE[self.scores.get(i)["pred"]]
        cells = self.agent["A"].cells_for(self.trusted.public_incident(i), action["action"])
        return action["cls"] == "AUTO" and len(cells) <= BLAST_RADIUS

    def moment2_act(self):
        lam = self.threshold()
        iid = self.heldout_where(lambda i: self._actionable(i) and self.scores.get(i)["score"] >= lam)
        auto = self.agent["A"].handle(iid, lam)
        low = self.heldout_where(lambda i: self._actionable(i) and self.scores.get(i)["score"] < lam)
        human = self.agent["A"].handle(low, lam)
        exec_res = self.engineer["A"].approve_and_execute(human["approval_id"]) if human.get("approval_id") else None
        return {"auto": auto, "human": human, "engineer_execution": _brief(exec_res)}

    def moment3_block(self):
        lam = self.threshold()
        before = self.trusted.store.q("SELECT COUNT(*) FROM sim_actions")[0][0]
        iid = self.heldout_where(self._auto_c2, skip=1)
        agent_try = self.agent["A"].handle(iid, lam, force_cells=5, claim_cell_count=2)
        appr = agent_try.get("approval_id")
        eng = self.engineer["A"].approve_and_execute(appr) if appr else None
        after = self.trusted.store.q("SELECT COUNT(*) FROM sim_actions")[0][0]
        return {"agent": agent_try, "engineer_with_approval": _brief(eng), "state_changes": after - before}

    def moment4_revoke(self):
        lam = self.threshold()
        jti, _ = self.trusted.registry.current()
        self.trusted.registry.set_status(jti, "revoked", "demo: manual revoke")
        self.store.audit("licence_revoked", {"jti": jti})
        iid = self.heldout_where(self._auto_c2, skip=2)
        return {"revoked_jti": jti, "next_call": self.agent["A"].handle(iid, lam)}

    def exploratory_alphas(self, alphas=(0.02, 0.05, 0.10)):
        """Slider values. Only the pre-registered alpha is certified; the rest are labelled exploratory."""
        rows = [self.scores.get(i) for i in self.calibration_ids]
        n, k = local_counts([r["score"] for r in rows], [r["correct"] for r in rows], self.grid)
        out = []
        for a in alphas:
            c = fixed_sequence_calibrate(n, k, self.grid, a, self.delta)
            h = selective_report(self.scores, self.splits["heldout"], c.threshold)
            out.append({"alpha": a, "official": abs(a - self.alpha) < 1e-12, "licensed": c.licensed,
                        "threshold": c.threshold, "heldout_autonomy": h["autonomy_rate"],
                        "heldout_error": h["selective_error"]})
        return out

    def reinstate(self):
        """New calibration round -> new licence (a revoked licence is never re-activated)."""
        return self.issue(self.calibrate_central(), round_id="r-central-02")

    def moment5_federation(self, mode="masking"):
        ops = self.splits["operators"]
        r = run_round(self.scores, ops, self.grid, self.alpha, self.delta, mode=mode)
        thr = r["pooled"].threshold
        per_op = per_operator(self.scores, self.splits["heldout"], self.splits["heldout_operator"], thr)
        return {"mode": mode, "sum_correct": r["direct_sum_matches"],
                "alone": {o: _cal(c) for o, c in r["alone"].items()}, "pooled": _cal(r["pooled"]),
                "per_operator_heldout": per_op,
                "claim": "federation-mixture licence; per-operator results are measurements, not guarantees"}

    def moment6_warning(self):
        lam = self.threshold()
        # B: the agent requests an oversized change -> Cedar F1 deny -> reviewer confirms -> signed warning
        b_iid = self.heldout_where(lambda i: self.scores.get(i)["score"] >= lam
                                   and CATALOGUE[self.scores.get(i)["pred"]]["cls"] == "AUTO")
        b_try = self.agent["B"].handle(b_iid, lam, force_cells=5)
        cat = self.trusted.category(b_iid)
        # Run again within the warning's life, B's earlier warning is still in force and the receiver's rate
        # limit (one active warning per issuer and category) would refuse a second: show the one in force.
        held = self.store.q("SELECT raw FROM warnings WHERE issuer='B' AND receiver='A' AND category=? "
                            "AND status='active' AND exp>?", (cat, int(time.time())))
        if held:
            rec = {**json.loads(held[0][0]), "already_active": True}
        else:
            tok = W.make_warning(self.op_keys["B"], "B", cat, "hard_rule_deny",
                                 evidence_ref=self.store.hash_incident(b_iid), reviewer="sec-reviewer-1")
            keyreg = {o: k.public_key() for o, k in self.op_keys.items()}
            rec = {**W.receive_warning(self.store, tok, "A", keyreg), "already_active": False}
        # A: same category -> HUMAN; another category -> still autonomous
        same = self.heldout_where(lambda i: self.trusted.category(i) == cat and self.scores.get(i)["score"] >= lam
                                  and CATALOGUE[self.scores.get(i)["pred"]]["cls"] == "AUTO", skip=1)
        other = self.heldout_where(lambda i: self.trusted.category(i) != cat and self.scores.get(i)["score"] >= lam
                                   and CATALOGUE[self.scores.get(i)["pred"]]["cls"] == "AUTO", skip=3)
        return {"B_attempt": b_try,
                "warning": {k: rec[k] for k in ("issuer", "category", "signal", "exp", "already_active")},
                "A_same_category": self.agent["A"].handle(same, lam),
                "A_other_category": self.agent["A"].handle(other, lam)}

    def moment7_self_revoke(self, drift=0.3, drift_dir=None):
        """Self-revoking licence (license/monitor.py). Outcomes come from held-out ground truth in the
        pre-registered order, never from the agent. Phase 1: the licensed population as calibrated.
        Phase 2: a fresh licence is issued and SYNTHETIC drift starts right away: the score service reads
        `drift` too high, so incidents just under the threshold are handled autonomously. The fresh licence
        revokes itself once the anytime-valid test fires. Phase 2 needs its own licence because a long good
        record (phase 1) is evidence the old one is sound, and the test rightly needs far more to overturn it."""
        from license.monitor import RiskMonitor
        cur = self.trusted.registry.current()
        if not cur or self.trusted.registry.status(cur[0]) != "active":
            self.reinstate()
        lam = self.threshold()
        jti, _ = self.trusted.registry.current()
        mon = RiskMonitor(self.store, self.trusted.registry, self.alpha)

        def auto(i):
            return CATALOGUE[self.scores.get(i)["pred"]]["cls"] == "AUTO"

        def replay(jti, outcomes):
            peak, st = 0.0, mon.state(jti)
            n0, k0 = st["n"], st["errors"]        # counts below are for this phase only
            for i, wrong in outcomes:
                st = mon.record(jti, i, wrong)
                peak = max(peak, st["e_value"])
                if st["revoked_at"]:
                    break
            return {"outcomes": st["n"] - n0, "errors": st["errors"] - k0, "peak_e": round(peak, 3),
                    "e_value": round(st["e_value"], 3),
                    "revoked_after": st["revoked_at"] - n0 if st["revoked_at"] else None}

        ho = self.splits["heldout_order"]
        p1 = replay(jti, [(i, not self.scores.get(i)["correct"]) for i in ho
                     if auto(i) and self.scores.get(i)["score"] >= lam])
        # The drift stream is synthetic by construction. On real data it comes from the synthetic stand-in,
        # so no real incident's outcome is ever altered; its ids are prefixed so they cannot pass for real ones.
        src = drift_dir or drift_dir_for(self.data_dir)
        own = os.path.abspath(src) == os.path.abspath(self.data_dir)
        sp = self.splits if own else json.load(open(os.path.join(src, "splits.json")))
        sc = self.scores if own else ScoreCache(os.path.join(src, "scores.jsonl"))
        held = self.trusted.registry.status(jti)
        fresh = self.reinstate()["jti"]
        p2 = replay(fresh, [(i if own else f"synthetic:{i}", not sc.get(i)["correct"]) for i in sp["heldout_order"]
                     if CATALOGUE[sc.get(i)["pred"]]["cls"] == "AUTO" and lam - drift <= sc.get(i)["score"] < lam])
        nxt = self.heldout_where(self._auto_c2, skip=3)
        return {"jti": fresh, "alpha": self.alpha, "delta": mon.delta, "revoke_at_e": 1 / mon.delta,
                "in_distribution": p1 | {"jti": jti, "status": held},
                "synthetic_drift": p2 | {"score_offset": drift, "incidents": "this data" if own else "synthetic stand-in"},
                "status": self.trusted.registry.status(fresh), "next_call": self.agent["A"].handle(nxt, lam),
                "claim": "P(false revocation, ever) <= delta if the wrong-autonomous-diagnosis rate stays <= alpha; "
                         "drift is injected (synthetic stress test)"}


def drift_dir_for(data_dir):
    """Where moment 7's synthetic drift incidents come from: the data itself if it is synthetic, else the
    synthetic stand-in (real TeleLogs scores sit almost entirely above the threshold and are never altered)."""
    try:
        source = json.load(open(os.path.join(data_dir, "split_hashes.json"))).get("source")
    except (OSError, ValueError):
        source = None
    return data_dir if source == "synthetic" else os.path.join(ROOT, "state", "data.synthetic")


def _cal(c):
    first = c.trace[0] if c.trace else None
    return {"licensed": c.licensed, "threshold": c.threshold, "n": c.n_accepted, "k": c.k_errors,
            "upper_bound": c.upper_bound,
            "first_test": {"threshold": first[0], "n": first[1], "k": first[2], "U": round(first[3], 4)} if first else None}


def _brief(res):
    if res is None:
        return None
    return {"isError": res["isError"], "text": res["content"][0]["text"] if res["isError"] else None,
            "policies": (res.get("policy") or {}).get("policies"), "result": res.get("result")}
