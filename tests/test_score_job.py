"""SageMaker scoring job: valid requests, a role scoped to its bucket, the scorer shipped unchanged, and
an entry point whose outputs carry no incident text."""
import io
import json
import os
import subprocess
import sys
import tarfile

import boto3
import pytest
from botocore.validate import ParamValidator

from aws.infra import score_job as J
from aws.scoring import entry
from model import score_cache as S
from model.scorer import SyntheticScorer

ROOT = os.path.dirname(os.path.dirname(__file__))
SESSION = boto3.session.Session(region_name="us-east-1")


@pytest.mark.parametrize("op,req", J.plan(), ids=lambda x: x if isinstance(x, str) else "")
def test_request_matches_aws_api(op, req):
    service, method = op.split(".")
    m = SESSION._session.get_service_model(service)
    name = next(o for o in m.operation_names if method.replace("_", "").lower() == o.lower())
    report = ParamValidator().validate(req, m.operation_model(name).input_shape)
    assert not report.has_errors(), report.generate_report()


def test_role_reaches_only_its_bucket():
    p = J.role_policy("123456789012", "us-east-1", "al-scoring-x")
    s3 = [r for st in p["Statement"] for r in st["Resource"] if "s3" in str(st["Action"])]
    assert s3 and all(r.startswith("arn:aws:s3:::al-scoring-x") for r in s3)


def test_spot_wait_covers_runtime_and_job_holds_no_token():
    req = J.job_request("j", "arn:aws:iam::1:role/r", "b", "us-east-1", "full", 0)
    assert req["StoppingCondition"]["MaxWaitTimeInSeconds"] >= req["StoppingCondition"]["MaxRuntimeInSeconds"]
    assert not any("TOKEN" in k.upper() for k in req["Environment"] | req["HyperParameters"])


def test_source_tar_ships_the_scorer_unchanged_and_nothing_else():
    t = tarfile.open(fileobj=io.BytesIO(J.source_tar()), mode="r:gz")
    names = set(t.getnames())
    assert names == set(J.CODE) | {"score_entry.py", "requirements.txt"}
    assert t.extractfile("model/scorer.py").read() == open(os.path.join(ROOT, "model", "scorer.py"), "rb").read()
    assert b"transformers==5.2.0" in t.extractfile("requirements.txt").read()


@pytest.fixture(scope="module")
def data(tmp_path_factory):
    out = tmp_path_factory.mktemp("data")
    subprocess.check_call([sys.executable, "-m", "data.prepare_telelogs", "--source", "synthetic", "--out", str(out)],
                          cwd=ROOT, stdout=subprocess.DEVNULL)
    return str(out)


def test_entry_pilot_matches_local_pilot_check(data, tmp_path):
    res = entry.run(data, str(tmp_path / "pilot"), "pilot", 20, SyntheticScorer())
    assert res == S.pilot_check(data, SyntheticScorer(), 20)
    assert os.listdir(tmp_path / "pilot") == ["result.json"]


def test_entry_full_writes_scores_without_incident_text(data, tmp_path):
    out = tmp_path / "full"
    res = entry.run(data, str(out), "full", 0, SyntheticScorer())
    rows = [json.loads(x) for x in open(out / "scores.jsonl")]
    assert res["scored"] == len(rows) - 1 and rows[0] == {"fingerprint": SyntheticScorer().fingerprint()}
    assert all(set(r) <= {"incident_id", "pred", "score", "probs", "correct"} for r in rows[1:])
    assert not os.path.exists(os.path.join(data, "scores.jsonl"))   # the job works on a copy


def test_instance_has_ram_for_the_weights_file():
    """Pilot 2026-10-31 on ml.g5.xlarge (16 GB RAM) failed to mmap the 16.6 GB safetensors file."""
    from aws.infra import score_job
    assert score_job.INSTANCE in {"ml.g5.2xlarge", "ml.g5.4xlarge", "ml.g6.2xlarge", "ml.g6e.xlarge"}
