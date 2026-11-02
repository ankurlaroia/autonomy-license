import time

import jwt
import pytest

from calibration.selective_risk import CalibrationResult
from federation.aggregation import aggregate, mask_vector
from federation.operators import validate_vector
from license.issuer import issue_licence
from license.signer import LocalSigner
from license.verifier import verify_licence

CAL = CalibrationResult(True, 0, 0.95, 0.05, 0.10, 312, 7, 0.0398, [])


def _issue(signer, ttl=3600, **kw):
    return issue_licence(signer, issuer="iss", audience="aud", agent_id="agent", fingerprint="sha256:cfg",
                         calib=CAL, categories=["k1", "k2"], actions=["adjust_tilt"], operators=["A", "B"],
                         round_id="r1", prereg_sha="sha256:p", ttl_s=ttl, **kw)


def _verify(tok, pub, **over):
    kw = dict(issuer="iss", audience="aud", expected_fingerprint="sha256:cfg",
              status_lookup=lambda j: "active", operator="A", requested_category="k1",
              requested_action="adjust_tilt")
    kw.update(over)
    return verify_licence(tok, pub, **kw)


@pytest.fixture(scope="module")
def signer():
    return LocalSigner()


def test_T01_valid(signer):
    tok, _ = _issue(signer)
    assert _verify(tok, signer.public_key())["risk"]["threshold"] == 0.95


@pytest.mark.parametrize("over,err", [
    ({"audience": "other"}, jwt.InvalidAudienceError),                        # T10
    ({"expected_fingerprint": "sha256:changed"}, PermissionError),            # T06
    ({"status_lookup": lambda j: "revoked"}, PermissionError),                # T08
    ({"operator": "Z"}, PermissionError),                                     # T10 operator
    ({"warned_categories": frozenset({"k1"})}, PermissionError),              # warned category
    ({"requested_action": "power_down_cells"}, PermissionError),              # out of scope
])
def test_verifier_denies(signer, over, err):
    tok, _ = _issue(signer)
    with pytest.raises(err):
        _verify(tok, signer.public_key(), **over)


def test_T09_forged_key(signer):
    tok, _ = _issue(LocalSigner())
    with pytest.raises(jwt.InvalidSignatureError):
        _verify(tok, signer.public_key())


def test_T07_expired(signer):
    tok, _ = _issue(signer, ttl=-120)
    with pytest.raises(jwt.ExpiredSignatureError):
        _verify(tok, signer.public_key())


def test_refused_calibration_cannot_issue(signer):
    with pytest.raises(ValueError):
        issue_licence(signer, issuer="i", audience="a", agent_id="x", fingerprint="f",
                      calib=CalibrationResult(False, None, None, 0.05, 0.1, 0, 0, None, []),
                      categories=[], actions=[], operators=[], round_id="r", prereg_sha="p")


def test_T19_masked_sum_exact():
    v = {"A": [300, 200, 5, 3], "B": [80, 60, 2, 1], "C": [10, 8, 0, 0]}
    seeds = {("A", "B"): b"ab", ("A", "C"): b"ac", ("B", "C"): b"bc"}
    masked = [mask_vector(o, v[o], {p: seeds[tuple(sorted((o, p)))] for p in v if p != o}, "r1") for o in v]
    assert aggregate(masked) == [390, 268, 7, 4]
    assert masked[0] != v["A"]


def test_T20_dropout_breaks_sum_so_round_must_abort():
    v = {"A": [3, 1], "B": [2, 1], "C": [1, 0]}
    seeds = {("A", "B"): b"ab", ("A", "C"): b"ac", ("B", "C"): b"bc"}
    masked = [mask_vector(o, v[o], {p: seeds[tuple(sorted((o, p)))] for p in v if p != o}, "r1") for o in "AB"]
    assert aggregate(masked) != [5, 2]          # masks do not cancel: never publish a partial sum


@pytest.mark.parametrize("vec", [[5, 6, 6, 1], [5, 6, -1, 0], [6, 5, 0, 0]])
def test_T21_malformed_vectors_rejected(vec):
    with pytest.raises(ValueError):
        validate_vector(vec, 2)
