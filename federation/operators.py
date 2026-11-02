"""P1 federation: each operator computes integer count vectors locally; only masked vectors leave it.
The pooled licence is a federation-mixture licence: never claim a per-operator guarantee (spec 7.4).
"""
from __future__ import annotations

import numpy as np

from calibration.selective_risk import fixed_sequence_calibrate, local_counts
from federation.aggregation import P, aggregate, mask_vector


def operator_vector(score_cache, incident_ids, grid):
    rows = [score_cache.get(i) for i in incident_ids]
    n, k = local_counts([r["score"] for r in rows], [r["correct"] for r in rows], grid)
    return [int(x) for x in n] + [int(x) for x in k]


def validate_vector(v, m):
    n, k = v[:m], v[m:]
    if len(v) != 2 * m or any(x < 0 for x in v) or any(kk > nn for nn, kk in zip(n, k)):
        raise ValueError("malformed count vector (k > n or negative)")      # test T21/T23
    if any(n[j] < n[j - 1] for j in range(1, m)):
        raise ValueError("accepted counts must be non-decreasing as the threshold loosens")


def run_round(score_cache, operator_ids: dict, grid, alpha, delta, round_id="r-local-01",
              seeds: dict | None = None, mode: str = "masking"):
    """mode: 'masking' (pairwise, honest-but-curious, no dropout) or 'plain' (disclosed non-private)."""
    names = sorted(operator_ids)
    m = len(grid)
    vecs = {o: operator_vector(score_cache, operator_ids[o], grid) for o in names}
    for v in vecs.values():
        validate_vector(v, m)
    if mode == "masking":
        seeds = seeds or {(a, b): f"seed-{a}{b}-demo".encode() for i, a in enumerate(names) for b in names[i + 1:]}
        masked = []
        for o in names:
            peers = {p: seeds[tuple(sorted((o, p)))] for p in names if p != o}
            masked.append(mask_vector(o, vecs[o], peers, round_id))
        total = aggregate(masked)
        total = [x if x < P // 2 else x - P for x in total]
    else:
        total = [int(x) for x in np.sum([vecs[o] for o in names], axis=0)]
    n, k = total[:m], total[m:]
    pooled = fixed_sequence_calibrate(n, k, grid, alpha, delta)
    alone = {o: fixed_sequence_calibrate(vecs[o][:m], vecs[o][m:], grid, alpha, delta) for o in names}
    return {"pooled": pooled, "alone": alone, "mode": mode, "round_id": round_id,
            "direct_sum_matches": total == [int(x) for x in np.sum([vecs[o] for o in names], axis=0)],
            "vectors_seen_by_aggregator": "masked" if mode == "masking" else "plain"}
