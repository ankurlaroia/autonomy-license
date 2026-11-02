"""SageMaker training-job entry point: run the unchanged model.score_cache on the job's GPU.

Shipped as score_entry.py at the root of the job's source tarball (aws.infra.score_job). Input channel
"data" holds incidents.jsonl and splits.json; /opt/ml/model receives result.json and, for a full build,
scores.jsonl (predictions, scores and probabilities only: no incident text).
"""
from __future__ import annotations

import json
import os
import shutil

IN = "/opt/ml/input/data/data"
OUT = "/opt/ml/model"
HP = "/opt/ml/input/config/hyperparameters.json"


def run(src: str, out: str, mode: str, n: int, scorer) -> dict:
    from model import score_cache as S
    work = "/tmp/al-data" if os.path.isdir("/tmp") else os.path.join(out, "_work")
    shutil.rmtree(work, ignore_errors=True)
    shutil.copytree(src, work)
    os.makedirs(out, exist_ok=True)
    if mode == "pilot":
        res = S.pilot_check(work, scorer, n)
    else:
        res = S.build(work, scorer)
        shutil.copy(os.path.join(work, "scores.jsonl"), os.path.join(out, "scores.jsonl"))
    json.dump(res, open(os.path.join(out, "result.json"), "w"), indent=1)
    shutil.rmtree(work, ignore_errors=True)
    return res


def main():   # pragma: no cover - runs inside the SageMaker container
    hp = {k: str(v).strip('"') for k, v in json.load(open(HP)).items()} if os.path.exists(HP) else {}
    from model.scorer import HFClassifierScorer
    print(json.dumps(run(IN, OUT, hp.get("mode", "pilot"), int(hp.get("n", "20")), HFClassifierScorer()), indent=1))


if __name__ == "__main__":
    main()
