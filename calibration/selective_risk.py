"""Selective-risk calibration for Autonomy License.

Controls the error rate among the decisions the agent takes autonomously
(selective risk), not conformal coverage over all incidents.

Procedure (Learn-then-Test with fixed-sequence testing):
  * thresholds lambda_1 > lambda_2 > ... > lambda_m are fixed BEFORE calibration
    data is seen (pre-registered), ordered strict -> loose;
  * H_j : R(lambda_j) > alpha, where R(l) = P(wrong | score >= l);
  * reject H_j when the one-sided Clopper-Pearson upper bound U_j <= alpha;
  * walk j = 1..m, stop at the FIRST non-rejection; the licence uses the last
    rejected threshold. If H_1 is not rejected, no licence is issued.

Guarantee (exchangeability, frozen model, pre-registered grid):
  P( R(lambda_hat) <= alpha ) >= 1 - delta
"""
from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
from scipy.stats import beta


def cp_upper(k: int, n: int, delta: float) -> float:
    """One-sided (1 - delta) Clopper-Pearson upper bound for a binomial rate."""
    if n <= 0 or k >= n:
        return 1.0
    return float(beta.ppf(1.0 - delta, k + 1, n - k))


def cp_lower(k: int, n: int, delta: float) -> float:
    """One-sided (1 - delta) Clopper-Pearson lower bound (used by local monitors)."""
    if n <= 0 or k <= 0:
        return 0.0
    return float(beta.ppf(delta, k, n - k + 1))


def local_counts(scores, correct, grid):
    """Per-operator statistics. Only these integers ever leave the operator.

    Returns (n, k): n[j] = incidents with score >= grid[j];
                    k[j] = wrong diagnoses among them.
    """
    s = np.asarray(scores, dtype=float)
    c = np.asarray(correct, dtype=bool)
    n = np.array([int((s >= t).sum()) for t in grid], dtype=np.int64)
    k = np.array([int(((s >= t) & ~c).sum()) for t in grid], dtype=np.int64)
    return n, k


@dataclass
class CalibrationResult:
    licensed: bool
    index: int | None            # index into grid of chosen threshold
    threshold: float | None
    alpha: float
    delta: float
    n_accepted: int
    k_errors: int
    upper_bound: float | None
    trace: list = field(default_factory=list)  # (threshold, n, k, U, rejected)


def fixed_sequence_calibrate(n, k, grid, alpha: float, delta: float) -> CalibrationResult:
    """grid must be ordered strict -> loose and fixed before seeing data."""
    if any(grid[i] <= grid[i + 1] for i in range(len(grid) - 1)):
        raise ValueError("grid must be strictly decreasing (strict -> loose)")
    chosen, trace = None, []
    for j, (nj, kj) in enumerate(zip(n, k)):
        u = cp_upper(int(kj), int(nj), delta)
        rejected = u <= alpha
        trace.append((float(grid[j]), int(nj), int(kj), u, rejected))
        if not rejected:
            break                      # stop at first failure: never skip ahead
        chosen = j
    if chosen is None:
        return CalibrationResult(False, None, None, alpha, delta, 0, 0, None, trace)
    return CalibrationResult(True, chosen, float(grid[chosen]), alpha, delta,
                             int(n[chosen]), int(k[chosen]), trace[chosen][3], trace)


def naive_calibrate(n, k, grid, alpha: float):
    """The WRONG method, for comparison only: loosest threshold whose
    empirical error <= alpha (no confidence bound, no sequence)."""
    best = None
    for j, (nj, kj) in enumerate(zip(n, k)):
        if nj > 0 and kj / nj <= alpha:
            best = j
    return best


def min_samples_zero_errors(alpha: float, delta: float) -> int:
    """Smallest n such that 0 errors in n accepted decisions certifies <= alpha."""
    n = 1
    while cp_upper(0, n, delta) > alpha:
        n += 1
    return n


def min_samples(k: int, alpha: float, delta: float) -> int:
    n = k + 1
    while cp_upper(k, n, delta) > alpha:
        n += 1
    return n
