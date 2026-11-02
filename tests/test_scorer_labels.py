"""The classifier's head predicts TeleLogs codes; the catalogue uses its own numbering. to_catalogue() must
move each probability to the same fault in catalogue order, or the agent would apply the wrong fix."""
import numpy as np

from model.scorer import HEAD_LABELS, to_catalogue

PAPER_MAP = {"C1": "C2", "C2": "C3", "C3": "C7", "C4": "C4", "C5": "C6", "C6": "C5", "C7": "C1", "C8": "C8"}


def test_head_labels_are_c1_to_c8():
    assert HEAD_LABELS == ["C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8"]


def test_speed_prediction_lands_on_catalogue_speed():
    p = np.zeros(8)
    p[6] = 1.0                                   # head says TeleLogs C7 = speed
    out = to_catalogue(p, PAPER_MAP)
    assert out.argmax() == 0 and out.sum() == 1.0     # catalogue C1 = speed


def test_mass_preserved_and_identity_without_map():
    p = np.random.default_rng(0).dirichlet(np.ones(8))
    assert np.isclose(to_catalogue(p, PAPER_MAP).sum(), 1.0)
    assert np.allclose(to_catalogue(p, None), p)
    assert np.allclose(to_catalogue(p, {c: c for c in HEAD_LABELS}), p)
