"""Score-cache command: the pilot check touches only pilot incidents and writes nothing; a full build
replaces the cache and retires a PREREG made with another model."""
import json
import os
import subprocess
import sys

import pytest
import yaml

from model import score_cache as S
from model.scorer import SyntheticScorer

ROOT = os.path.dirname(os.path.dirname(__file__))


@pytest.fixture(scope="module")
def data(tmp_path_factory):
    out = tmp_path_factory.mktemp("data")
    subprocess.check_call([sys.executable, "-m", "data.prepare_telelogs", "--source", "synthetic", "--out", str(out)],
                          cwd=ROOT, stdout=subprocess.DEVNULL)
    return str(out)


class Spy(SyntheticScorer):
    def __init__(self):
        self.seen = []

    def predict(self, inc):
        self.seen.append(inc["incident_id"])
        return super().predict(inc)


def test_pilot_check_reads_only_pilot_and_writes_nothing(data):
    spy = Spy()
    r = S.pilot_check(data, spy, 20)
    pilot = json.load(open(os.path.join(data, "splits.json")))["pilot"]
    assert spy.seen == pilot[:20] and r["pilot_scored"] == 20
    assert not os.path.exists(os.path.join(data, "scores.jsonl"))
    assert 0 <= r["pilot_accuracy"] <= 1 and r["score_min"] <= r["score_median"] <= r["score_max"]


def test_build_writes_cache_and_retires_stale_prereg(data):
    pre = os.path.join(data, "PREREG.yaml")
    yaml.safe_dump({"model_fingerprint": "sha256:old-model"}, open(pre, "w"))
    r = S.build(data, SyntheticScorer())
    assert r["scored"] > 0 and r["fingerprint"] == SyntheticScorer().fingerprint()
    assert not os.path.exists(pre) and os.path.exists(os.path.join(data, "PREREG.stale.yaml"))


def test_build_keeps_prereg_for_same_model(data):
    pre = os.path.join(data, "PREREG.yaml")
    yaml.safe_dump({"model_fingerprint": SyntheticScorer().fingerprint()}, open(pre, "w"))
    assert "prereg" not in S.build(data, SyntheticScorer()) and os.path.exists(pre)
