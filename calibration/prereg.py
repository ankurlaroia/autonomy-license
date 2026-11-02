"""Pre-registration (spec 5.4): grid, alpha, delta, splits and demo rules fixed and hashed BEFORE
the first calibration run. The grid start is chosen on the pilot set only (spec 6.4)."""
from __future__ import annotations

import hashlib
import json

import yaml

from calibration.selective_risk import min_samples_zero_errors

FULL_GRID = [0.999, 0.998, 0.995, 0.99, 0.985, 0.98, 0.97, 0.96, 0.95, 0.94, 0.92, 0.90, 0.88, 0.85, 0.80, 0.75, 0.70]


def choose_grid(pilot_scores, n_calibration: int, alpha: float, delta: float, safety: float = 1.5):
    """Strictest start whose expected accepted count on calibration >= safety * zero-error minimum."""
    need = safety * min_samples_zero_errors(alpha, delta)
    for i, t in enumerate(FULL_GRID):
        rate = sum(s >= t for s in pilot_scores) / max(1, len(pilot_scores))
        if rate * n_calibration >= need:
            return FULL_GRID[i:]
    return FULL_GRID[-3:]


def write_prereg(path, *, grid, alpha, delta, split_hashes, fingerprint, heldout_order_seed=20261102):
    doc = {
        "project": "autonomy-license", "version": "v1.2.1",
        "data": {"source": split_hashes.get("source"), "eligibility": "single-cause",
                 "seed": split_hashes.get("seed"),
                 "split_hashes": {k: split_hashes[k] for k in ("pilot", "calibration", "heldout")}},
        "model_fingerprint": fingerprint,
        "score": "max_softmax_over_C1_C8",
        "grid": [float(g) for g in grid], "grid_start_chosen_on": "pilot",
        "alpha": alpha, "delta": delta,
        "method": "fixed-sequence Clopper-Pearson (Learn-then-Test), stop at first failure",
        "calibration_p0": "central",
        "demo": {"official_alpha": alpha, "exploratory_alphas": [0.02, 0.10],
                 "heldout_order_seed": heldout_order_seed,
                 "incident_rule": "first held-out incident, in pre-registered order, meeting each moment's condition"},
        "claims_scope": "filtered single-cause population; central (P0) or federation mixture (P1); no per-operator guarantee",
    }
    text = yaml.safe_dump(doc, sort_keys=False)
    open(path, "w").write(text)
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest(), doc


def load_prereg(path):
    text = open(path).read()
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest(), yaml.safe_load(text)


if __name__ == "__main__":
    print(json.dumps(FULL_GRID))
