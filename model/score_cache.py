"""Build the trusted score cache for a prepared data directory (spec 5.5: score once, cache forever).

  python -m model.score_cache --data state/data --scorer hf --pilot-check 20   # sanity, writes nothing
  python -m model.score_cache --data state/data --scorer hf                    # all incidents -> scores.jsonl

--pilot-check scores only pilot incidents (never calibration or held-out) and prints accuracy and the
score range, so a broken input format or label map shows up before anything is cached.

A PREREG.yaml made with another model fingerprint is moved to PREREG.stale.yaml: the next run regenerates
it from the new pilot scores BEFORE calibration (spec 5.4). Output is counts and hashes only, never data.
"""
from __future__ import annotations

import argparse
import json
import os

import yaml

from model.scorer import ScoreCache, SyntheticScorer


def make_scorer(kind: str):
    if kind == "synthetic":
        return SyntheticScorer()
    if kind == "hf":   # pragma: no cover - needs GPU and model download
        from model.scorer import HFClassifierScorer
        return HFClassifierScorer()
    raise ValueError(kind)


def load(data: str):
    inc = [json.loads(line) for line in open(os.path.join(data, "incidents.jsonl"))]
    splits = json.load(open(os.path.join(data, "splits.json")))
    return inc, splits


def pilot_check(data: str, scorer, n: int) -> dict:
    inc, splits = load(data)
    by_id = {x["incident_id"]: x for x in inc}
    rows = [scorer.predict(by_id[i]) | {"label": by_id[i]["label"]} for i in splits["pilot"][:n]]
    scores = sorted(r["score"] for r in rows)
    return {"pilot_scored": len(rows), "pilot_accuracy": round(sum(r["pred"] == r["label"] for r in rows) / len(rows), 3),
            "score_min": round(scores[0], 4), "score_median": round(scores[len(scores) // 2], 4),
            "score_max": round(scores[-1], 4), "fingerprint": scorer.fingerprint()}


def build(data: str, scorer) -> dict:
    inc, _ = load(data)
    cache = ScoreCache(os.path.join(data, "scores.jsonl")).build(inc, scorer)
    return {"scored": len(cache.rows), "fingerprint": cache.fingerprint} | retire_stale_prereg(data, cache.fingerprint)


def retire_stale_prereg(data: str, fingerprint: str) -> dict:
    """Also used when the cache was built remotely (aws.infra.score_job) and copied in."""
    prereg = os.path.join(data, "PREREG.yaml")
    if os.path.exists(prereg) and yaml.safe_load(open(prereg)).get("model_fingerprint") != fingerprint:
        os.replace(prereg, os.path.join(data, "PREREG.stale.yaml"))
        return {"prereg": "stale PREREG moved aside; it is regenerated from pilot scores before calibration"}
    return {}


def main():   # pragma: no cover - CLI
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="state/data")
    ap.add_argument("--scorer", choices=["synthetic", "hf"], default="synthetic")
    ap.add_argument("--pilot-check", type=int, default=0)
    a = ap.parse_args()
    s = make_scorer(a.scorer)
    print(json.dumps(pilot_check(a.data, s, a.pilot_check) if a.pilot_check else build(a.data, s), indent=1))


if __name__ == "__main__":
    main()
