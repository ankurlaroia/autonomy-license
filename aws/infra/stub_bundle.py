"""Lambda bundle: incidents + trusted scores, and a SQLite seed holding the licence.

    python -m aws.infra.stub_bundle --out dist/bundle                                  # S1-S4: synthetic, stub licence
    python -m aws.infra.stub_bundle --out dist/bundle --data state/data --kms-key alias/al-licence-issuer   # S5

With --data, the prepared TeleLogs directory (incidents, splits, real scores, PREREG) is calibrated instead
of the synthetic stand-in; raw question text and code maps are stripped from the bundled incidents (the
Lambdas never need them). With --kms-key the licence is signed by KMS (step 3) and the Lambdas verify
against the KMS public key (AL_ISSUER_KMS_KEY) instead of a PEM.

Writes <out>/data/{incidents,scores}.jsonl, <out>/al.db and <out>/lambda_env.json (environment for both Lambdas).
The stub licence comes from a calibration on the SYNTHETIC stand-in; it exists only to prove the Gateway path,
never to claim anything. The issuer private key stays in state/keys (git-ignored); only the public key is written.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil

TASK_ROOT = "/var/task/bundle"


DATA_FILES = ("incidents.jsonl", "scores.jsonl", "splits.json", "split_hashes.json", "categories.json",
              "PREREG.yaml")
PRIVATE_FIELDS = ("raw_text", "code_map")


def _copy_incidents(src: str, dst: str):
    with open(dst, "w") as f:
        for line in open(src):
            x = json.loads(line)
            f.write(json.dumps({k: v for k, v in x.items() if k not in PRIVATE_FIELDS}) + "\n")


def build(out: str, data: str | None = None, kms_key: str | None = None, signer=None) -> dict:
    from cryptography.hazmat.primitives import serialization

    from demo.engine import Demo
    out = os.path.abspath(out)
    work = os.path.join(out, "_work")
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(os.path.join(out, "data"))
    if data:
        if not os.path.exists(os.path.join(data, "scores.jsonl")):
            raise SystemExit(f"{data} has no scores.jsonl; run python -m model.score_cache first")
        os.makedirs(os.path.join(work, "data"))
        for f in DATA_FILES:
            if os.path.exists(os.path.join(data, f)):
                shutil.copy(os.path.join(data, f), os.path.join(work, "data", f))
    d = Demo(data_dir=os.path.join(work, "data"), db=os.path.join(work, "al.db"), fresh=True)
    if kms_key or signer:
        from license.signer import KmsSigner
        d.issuer = signer or KmsSigner(kms_key)
    res = d.moment1_earn()
    source = "telelogs" if data else "synthetic"
    if not res["calibration"]["licensed"]:
        raise SystemExit(f"{source} calibration did not license; no licence to deploy")
    _copy_incidents(os.path.join(work, "data", "incidents.jsonl"), os.path.join(out, "data", "incidents.jsonl"))
    shutil.copy(os.path.join(work, "data", "scores.jsonl"), os.path.join(out, "data", "scores.jsonl"))
    d.store.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    d.store.db.close()
    shutil.copy(os.path.join(work, "al.db"), os.path.join(out, "al.db"))
    shutil.rmtree(work, ignore_errors=True)
    env = {"AL_DATA_DIR": f"{TASK_ROOT}/data", "AL_DB_SEED": f"{TASK_ROOT}/al.db", "AL_DB": "/tmp/al.db",
           "AL_EXPECTED_FINGERPRINT": d.scores.fingerprint, "AL_LOG_EVENT_SHAPE": "1", "OPERATOR": "A"}
    if kms_key:
        env["AL_ISSUER_KMS_KEY"] = kms_key
    else:
        env["AL_ISSUER_PUBLIC_KEY_PEM"] = d.issuer.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    json.dump(env, open(os.path.join(out, "lambda_env.json"), "w"), indent=1)
    info = {"licence_jti": res["licence"]["jti"], "threshold": res["calibration"]["threshold"],
            "fingerprint": d.scores.fingerprint, "data_source": source,
            "signer": "kms" if kms_key else "local", "upper_bound": res["calibration"]["upper_bound"]}
    json.dump(info, open(os.path.join(out, "stub_info.json"), "w"), indent=1)   # for aws.infra.smoke
    return {"out": out, **info}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="dist/bundle")
    ap.add_argument("--data", help="prepared TeleLogs data dir with real scores (S5)")
    ap.add_argument("--kms-key", help="KMS key id or alias that signs the licence (step 3)")
    a = ap.parse_args()
    print(json.dumps(build(a.out, a.data, a.kms_key), indent=1))
