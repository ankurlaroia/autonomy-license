"""Data audit before calibration (spec 5.3, test T05): disjoint splits, exact-duplicate screening,
per-cause distribution. Exits non-zero if the run would be invalid."""
from __future__ import annotations

import collections
import hashlib
import json
import sys


def fingerprint(inc) -> str:
    body = {"cells": inc["cells"], "features": inc["features"]}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


def audit(incidents, splits) -> dict:
    by = {x["incident_id"]: x for x in incidents}
    sets = {"pilot": set(splits["pilot"]), "heldout": set(splits["heldout"])}
    for op, ids in splits["operators"].items():
        sets[f"cal_{op}"] = set(ids)
    problems = []
    names = list(sets)
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            if sets[a] & sets[b]:
                problems.append(f"overlap {a}/{b}: {len(sets[a] & sets[b])}")
    fps = collections.defaultdict(list)
    for x in incidents:
        fps[fingerprint(x)].append(x["incident_id"])
    dups = [v for v in fps.values() if len(v) > 1]
    if dups:
        problems.append(f"{len(dups)} exact-duplicate groups")
    dist = collections.Counter(x["label"] for x in incidents)
    return {"ok": not problems, "problems": problems, "per_cause": dict(sorted(dist.items())),
            "n": len(incidents), "sources": sorted({x.get("_source", "?") for x in incidents})}


if __name__ == "__main__":
    d = sys.argv[1] if len(sys.argv) > 1 else "state/data"
    inc = [json.loads(l) for l in open(f"{d}/incidents.jsonl")]
    rep = audit(inc, json.load(open(f"{d}/splits.json")))
    print(json.dumps(rep, indent=1))
    sys.exit(0 if rep["ok"] else 1)
