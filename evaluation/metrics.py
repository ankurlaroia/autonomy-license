"""Held-out evaluation (spec 13.1). Report selective error, autonomy and enforcement SEPARATELY;
never combine them into one 'safety %'."""
from __future__ import annotations

from scipy.stats import beta


def cp_two_sided(k: int, n: int, conf: float = 0.90):
    if n == 0:
        return (0.0, 1.0)
    a = 1 - conf
    lo = 0.0 if k == 0 else float(beta.ppf(a / 2, k, n - k + 1))
    hi = 1.0 if k == n else float(beta.ppf(1 - a / 2, k + 1, n - k))
    return lo, hi


def selective_report(score_cache, ids, threshold: float | None) -> dict:
    rows = [score_cache.get(i) for i in ids]
    if threshold is None:
        return {"n_eligible": len(rows), "n_auto": 0, "autonomy_rate": 0.0, "errors": 0,
                "selective_error": None, "ci90": None, "accuracy_all": _acc(rows)}
    auto = [r for r in rows if r["score"] >= threshold]
    k = sum(not r["correct"] for r in auto)
    n = len(auto)
    return {"n_eligible": len(rows), "n_auto": n, "autonomy_rate": n / max(1, len(rows)), "errors": k,
            "selective_error": (k / n) if n else None, "ci90": cp_two_sided(k, n),
            "accuracy_all": _acc(rows)}


def _acc(rows):
    return sum(r["correct"] for r in rows) / max(1, len(rows))


def per_operator(score_cache, heldout_ids, heldout_operator: dict, threshold):
    out = {}
    for op in sorted(set(heldout_operator.values())):
        ids = [i for i in heldout_ids if heldout_operator[i] == op]
        out[op] = selective_report(score_cache, ids, threshold)
    return out
