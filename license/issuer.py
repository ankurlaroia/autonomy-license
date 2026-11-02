"""Issue an AACP-style autonomy licence from a calibration result (spec 9.1).

A licence is issued per evaluated configuration, never per incident. It never authorises
anything by itself: the verifier turns it into tags, and Cedar + hard rules decide.
"""
from __future__ import annotations

import time
import uuid

PROFILE = "telelogs-rca-selective-risk/v1"
TYP = "autonomy-licence+jwt"


def issue_licence(signer, *, issuer: str, audience: str, agent_id: str, fingerprint: str, calib,
                  categories: list[str], actions: list[str], operators: list[str], round_id: str,
                  prereg_sha: str, aggregation: str = "central", ttl_s: int = 4 * 3600) -> tuple[str, dict]:
    if not calib.licensed:
        raise ValueError("calibration refused: no licence may be issued")
    now = int(time.time())
    claims = {
        "iss": issuer, "aud": audience, "sub": agent_id,
        "iat": now, "nbf": now, "exp": now + ttl_s, "jti": str(uuid.uuid4()),
        "cfg": fingerprint, "profile": PROFILE,
        "scope": {"categories": sorted(categories), "actions": sorted(actions), "operators": sorted(operators)},
        "risk": {"alpha": calib.alpha, "delta": calib.delta, "threshold": calib.threshold,
                 "n": calib.n_accepted, "k": calib.k_errors, "upper_bound": round(calib.upper_bound, 6),
                 "method": "fixed-sequence Clopper-Pearson (LTT)",
                 "calibration_scope": "central" if aggregation == "central" else "federation-mixture",
                 "population": "TeleLogs single-cause (filtered benchmark population)"},
        "evidence": {"aggregation_round": round_id, "aggregation": aggregation, "prereg": prereg_sha},
        "status": {"uri": "registry://licences"},
    }
    return signer.sign({"alg": "ES256", "typ": TYP}, claims), claims
