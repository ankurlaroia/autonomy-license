import numpy as np
import pytest

from calibration.selective_risk import cp_upper, fixed_sequence_calibrate, min_samples


def test_T03_zero_errors_in_40_not_licensed():
    assert cp_upper(0, 40, 0.10) == pytest.approx(0.0559, abs=1e-4)
    r = fixed_sequence_calibrate([40], [0], [0.99], 0.05, 0.10)
    assert not r.licensed


def test_T04_stop_at_first_failure_never_skip():
    # thresholds strict->loose; second fails, third would pass: licence must use the first only
    r = fixed_sequence_calibrate([100, 120, 400], [0, 10, 3], [0.99, 0.95, 0.9], 0.05, 0.10)
    assert r.licensed and r.threshold == 0.99


def test_T23_zero_accepted_means_no_licence():
    r = fixed_sequence_calibrate([0, 0], [0, 0], [0.99, 0.9], 0.05, 0.10)
    assert not r.licensed and cp_upper(0, 0, 0.1) == 1.0


def test_grid_must_be_strictly_decreasing():
    with pytest.raises(ValueError):
        fixed_sequence_calibrate([1, 2], [0, 0], [0.9, 0.95], 0.05, 0.1)


@pytest.mark.parametrize("k,expected", [(0, 45), (1, 77), (2, 105)])
def test_sample_size_wall(k, expected):
    assert min_samples(k, 0.05, 0.10) == expected


def test_50_action_window_bounds():
    assert [round(cp_upper(k, 50, 0.10), 4) for k in (0, 1, 2)] == [0.045, 0.0756, 0.103]


def test_validity_monte_carlo_small():
    """Fixed-sequence violations stay below delta on a simple synthetic model."""
    rng = np.random.default_rng(0)
    grid = [0.99, 0.97, 0.95, 0.9, 0.85, 0.8]
    viol, runs = 0, 400
    for _ in range(runs):
        s = rng.beta(8, 1, 450)
        c = rng.random(450) < s ** 1.5
        n = [int((s >= t).sum()) for t in grid]
        k = [int(((s >= t) & ~c).sum()) for t in grid]
        r = fixed_sequence_calibrate(n, k, grid, 0.05, 0.10)
        if r.licensed:
            # true risk at the chosen threshold, by large-sample Monte Carlo
            S = rng.beta(8, 1, 200000)
            C = rng.random(200000) < S ** 1.5
            m = S >= r.threshold
            viol += (~C[m]).mean() > 0.05
    assert viol / runs <= 0.10
