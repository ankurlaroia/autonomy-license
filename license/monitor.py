"""Self-revoking licence: an anytime-valid test on the outcomes of autonomous actions.

After a licence is issued, every autonomous diagnosis gets an outcome from the trusted side (ground truth /
post-incident review; never the agent): X = 1 if the diagnosis was wrong. Under H0 "the wrong-diagnosis rate
is <= alpha" each wealth process

    W_t(lam) = prod_s (1 + lam * (X_s - alpha)),   0 < lam < 1/alpha,

is a non-negative supermartingale, and so is any fixed mixture E_t = mean_j W_t(lam_j). By Ville's
inequality P(sup_t E_t >= 1/delta) <= delta, so revoking when E_t first reaches 1/delta has false-revocation
probability <= delta at ANY stopping time: the monitor may be checked after every action with no
multiple-testing penalty. It holds for adaptive streams too, as long as each outcome's conditional error
rate is <= alpha.

Scope (claims discipline): the test covers wrong autonomous diagnoses of the licensed population, the same
quantity the calibration bounds; it says nothing about action safety. A revoked licence is never
re-activated; a new calibration round issues a new one.
"""
from __future__ import annotations

import math

from common.store import Store

FRACTIONS = (0.05, 0.1, 0.2, 0.35, 0.5)    # lam_j = f / alpha: from cautious to aggressive bets


class RiskMonitor:
    def __init__(self, store: Store, registry, alpha: float, delta: float = 0.05, fractions=FRACTIONS):
        assert 0 < alpha < 1 and 0 < delta < 1 and all(0 < f < 1 for f in fractions)
        self.s, self.reg, self.alpha, self.delta = store, registry, alpha, delta
        self.lams = [f / alpha for f in fractions]

    def _key(self, jti):
        return f"monitor:{jti}"

    def state(self, jti: str) -> dict:
        st = self.s.kv_get(self._key(jti)) or {"n": 0, "errors": 0, "log_w": [0.0] * len(self.lams), "seen": [],
                                                 "revoked_at": None}
        return st | {"e_value": self.e_value(st), "threshold": 1 / self.delta}

    @staticmethod
    def e_value(st) -> float:
        return sum(math.exp(x) for x in st["log_w"]) / len(st["log_w"])

    def record(self, jti: str, incident_id: str, wrong: bool) -> dict:
        """One outcome. Idempotent per incident; revokes the licence the first time E_t >= 1/delta."""
        st = self.state(jti)
        if incident_id in st["seen"]:
            return st | {"duplicate": True}
        x = 1.0 if wrong else 0.0
        st["log_w"] = [lw + math.log1p(lam * (x - self.alpha)) for lw, lam in zip(st["log_w"], self.lams)]
        st["n"] += 1
        st["errors"] += int(wrong)
        st["seen"].append(incident_id)
        e = self.e_value(st)
        if e >= 1 / self.delta and st["revoked_at"] is None and self.reg.status(jti) == "active":
            st["revoked_at"] = st["n"]
            note = f"auto: anytime-valid test E={e:.1f} >= {1 / self.delta:.0f} after {st['n']} outcomes"
            self.reg.set_status(jti, "revoked", note)
            self.s.audit("licence_auto_revoked", {"jti": jti, "e_value": round(e, 2), "n": st["n"],
                                                  "errors": st["errors"], "alpha": self.alpha, "delta": self.delta})
        self.s.kv_set(self._key(jti), {k: st[k] for k in ("n", "errors", "log_w", "seen", "revoked_at")})
        return st | {"e_value": e, "threshold": 1 / self.delta}
