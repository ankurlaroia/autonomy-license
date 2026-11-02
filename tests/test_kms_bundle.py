"""Step 3 bundle: real (here: prepared synthetic) data and a KMS-signed licence. The Lambdas get the KMS key
id, never a PEM; raw question text never enters the bundle; the licence verifies against the KMS public key.
KMS itself is replaced by a local key behind the same interface."""
import json
import os
import subprocess
import sys

import pytest

from aws import lambda_bootstrap as B
from aws.infra import stub_bundle
from license.signer import LocalSigner
from model import score_cache

ROOT = os.path.dirname(os.path.dirname(__file__))
KEY = "alias/al-licence-issuer"


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    data = tmp_path_factory.mktemp("data")
    subprocess.check_call([sys.executable, "-m", "data.prepare_telelogs", "--source", "synthetic", "--out", str(data)],
                          cwd=ROOT, stdout=subprocess.DEVNULL)
    score_cache.build(str(data), score_cache.make_scorer("synthetic"))
    p = data / "incidents.jsonl"
    rows = [json.loads(x) for x in open(p)]
    for r in rows:                                    # what parse_row adds for real TeleLogs rows
        r["raw_text"], r["code_map"] = "QUESTION TEXT " + r["incident_id"], {"C1": "C1"}
    p.write_text("".join(json.dumps(r) + "\n" for r in rows))
    signer = LocalSigner(kid=KEY)
    out = tmp_path_factory.mktemp("bundle")
    info = stub_bundle.build(str(out), data=str(data), kms_key=KEY, signer=signer)
    return out, info, signer


def test_env_names_kms_key_and_no_pem(built):
    out, info, _ = built
    env = json.load(open(out / "lambda_env.json"))
    assert env["AL_ISSUER_KMS_KEY"] == KEY and "AL_ISSUER_PUBLIC_KEY_PEM" not in env
    assert info["data_source"] == "telelogs" and info["signer"] == "kms"
    assert "PRIVATE KEY" not in "".join(open(os.path.join(dp, f), errors="ignore").read()
                                        for dp, _, fs in os.walk(out) if "_work" not in dp for f in fs
                                        if not f.endswith(".db"))


def test_bundle_strips_raw_text_and_code_map(built):
    out, _, _ = built
    blob = (out / "data" / "incidents.jsonl").read_text()
    assert "QUESTION TEXT" not in blob and "raw_text" not in blob and "code_map" not in blob


def test_licence_verifies_against_kms_public_key(built, monkeypatch):
    out, info, signer = built

    class FakeKms:
        def __init__(self, key_id, region=None):
            assert key_id == KEY

        def public_key(self):
            return signer.public_key()

    monkeypatch.setattr("license.signer.KmsSigner", FakeKms)
    env = json.load(open(out / "lambda_env.json"))
    assert B.issuer_public_key_from_env(env).public_numbers() == signer.public_key().public_numbers()


def test_wrong_kms_key_fails_closed(built, monkeypatch):
    out, _, _ = built
    other = LocalSigner()
    monkeypatch.setattr("license.signer.KmsSigner", lambda k, region=None: other)
    env = json.load(open(out / "lambda_env.json"))
    with pytest.raises(RuntimeError):
        B.issuer_public_key_from_env({**env, "AL_ISSUER_PUBLIC_KEY_PEM": "x"})   # both sources: refuse


def test_real_data_without_scores_refuses(tmp_path):
    (tmp_path / "data").mkdir()
    with pytest.raises(SystemExit):
        stub_bundle.build(str(tmp_path / "b"), data=str(tmp_path / "data"))
