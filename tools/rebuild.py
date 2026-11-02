"""Rebuild the reported results from evidence/ with no AWS access, and fail if anything changed.

    python tools/rebuild.py

For every run id in judging.json: re-hash its per-item outputs and records against the record file, recompute the
unit's metric and the evidence checks from them (aws/evidence.py), and compare with the reported result. When
the frozen data is present (state/data, git-ignored), its split hashes must equal the ones declared.
Exit code 0 only when every run rebuilds to the same result.
"""
from __future__ import annotations

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from aws import evidence as E  # noqa: E402


def load_jsonl(path):
    return [json.loads(x) for x in open(path, encoding="utf-8").read().splitlines() if x.strip()]


def rebuild_run(root: str, rid: str, reported: dict | None, data_dir: str | None = None) -> list[str]:
    """Problems found for one run; empty when it rebuilds exactly."""
    problems = []
    decl_p = os.path.join(root, "evidence", "declared", f"{rid}.json")
    run_d = os.path.join(root, "evidence", "runs", rid)
    if not (os.path.exists(decl_p) and os.path.isdir(run_d)):
        return [f"{rid}: evidence files missing"]
    decl = json.load(open(decl_p, encoding="utf-8"))
    rec = json.load(open(os.path.join(run_d, "record.json"), encoding="utf-8"))
    for name, key in (("items.jsonl", "items_sha256"), ("records.jsonl", "records_sha256")):
        got = E.sha256_file(os.path.join(run_d, name))
        if got != rec[key]:
            problems.append(f"{rid}: {name} changed ({got[:19]} != {rec[key][:19]})")
    items = load_jsonl(os.path.join(run_d, "items.jsonl"))
    records = load_jsonl(os.path.join(run_d, "records.jsonl"))
    res = E.check(decl, items, records, rec["declaration_last_modified"], files_time=rec.get("items_last_modified"))
    if reported is not None:
        if abs(res["value"] - reported["value"]) > 1e-9 or res["pass"] != reported["pass"]:
            problems.append(f"{rid}: rebuilt {res['value']:.6g} {res['pass']} != reported "
                            f"{reported['value']:.6g} {reported['pass']}")
    if data_dir and os.path.exists(os.path.join(data_dir, "split_hashes.json")):
        h = json.load(open(os.path.join(data_dir, "split_hashes.json")))
        if decl["test_set_sha256"] not in (h.get("calibration"), h.get("heldout")):
            problems.append(f"{rid}: frozen test set changed (declared {decl['test_set_sha256'][:19]})")
    print(f"{rid:40} {decl['unit']:12} {decl['target']['metric'][:44]:44} {res['value']:.4g}  "
          f"{'PASS' if res['pass'] else 'FAIL'}")
    return problems


def main(root: str = ROOT) -> int:
    if not os.path.exists(os.path.join(root, "judging.json")):
        print("no judging.json yet: run python -m aws.infra.judged_run first")
        return 1
    j = json.load(open(os.path.join(root, "judging.json"), encoding="utf-8"))
    problems = []
    for rid in j["run_ids"]:
        problems += rebuild_run(root, rid, j["reported_results"].get(rid), os.path.join(root, "state", "data"))
    for p in problems:
        print("CHANGED", p)
    print("rebuild: " + ("identical to the reported results" if not problems else f"{len(problems)} problem(s)"))
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
