"""Load incidents, filter single-cause, split, assign operators, write manifests + PREREG hashes.

Sources:
  --source synthetic   stand-in generator (default until TeleLogs access is granted)
  --source telelogs    netop/TeleLogs (config "troubleshooting") from Hugging Face; gated: accept the terms on the
                       dataset page and set HF_TOKEN. Rows are parsed by data/telelogs_parse.py (layout from the
                       TeleLogs paper; cause codes mapped by meaning). Only the `test` split is used: the classifier
                       was fine-tuned on TeleLogs, so test rows whose text also appears in `train` are dropped too.
                       Never commit or print the data: only counts and split hashes leave this module.

Usage:  python -m data.prepare_telelogs --source synthetic --out state/data
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os

import numpy as np

from data.categories import fit_categories, assign_category

SEED = 20261101
SIZES = {"pilot": 60, "A": 240, "B": 170, "C": 40}   # spec 5.3; held-out = the rest


def parse_telelogs_row(row: dict) -> dict | None:
    """One TeleLogs record -> normalised incident, or None (multi-cause or unparseable; spec 5.2)."""
    from data.telelogs_parse import parse_row
    return parse_row(row)


def select_telelogs(test_rows, train_rows) -> tuple[list[dict], dict]:
    """Parsed single-cause test incidents not seen in train, plus counts for the run log (no data)."""
    from data.telelogs_parse import text_hash
    seen = {text_hash(r) for r in train_rows}
    stats = {"test_rows": 0, "in_train": 0, "not_single_cause_or_unparsed": 0, "duplicates": 0, "kept": 0}
    out, ids = [], set()
    for r in test_rows:
        stats["test_rows"] += 1
        if text_hash(r) in seen:
            stats["in_train"] += 1
            continue
        inc = parse_telelogs_row(r)
        if inc is None:
            stats["not_single_cause_or_unparsed"] += 1
        elif inc["incident_id"] in ids:
            stats["duplicates"] += 1
        else:
            ids.add(inc["incident_id"])
            out.append(inc)
    stats["kept"] = len(out)
    stats["labels"] = {c: sum(1 for x in out if x["label"] == c) for c in sorted({x["label"] for x in out})}
    return out, stats


def load(source: str, n: int = 800):
    if source == "synthetic":
        from data.synthetic_telelogs import generate
        return generate(n=n, seed=SEED)
    if source == "telelogs":
        from datasets import load_dataset          # pip install datasets; HF_TOKEN with accepted terms
        ds = load_dataset("netop/TeleLogs", "troubleshooting")
        inc, stats = select_telelogs(ds["test"], ds["train"])
        print(json.dumps({"telelogs": stats}, indent=1))
        need = sum(SIZES.values()) + 100
        if len(inc) < need:
            raise SystemExit(f"only {len(inc)} eligible TeleLogs incidents; the split needs at least {need}")
        return inc
    raise ValueError(source)


def _hash(items) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(sorted(items)).encode()).hexdigest()


def split(incidents, heterogeneous: bool = True, seed: int = SEED):
    """Pilot / calibration (A, B, C) / held-out. P0 uses A+B+C pooled centrally; P1 keeps them apart.
    heterogeneous=True gives C a skewed incident mix by category (Dirichlet 0.5), so C's own result
    is not fine by construction (spec 5.3)."""
    rng = np.random.default_rng(seed)
    ids = [x["incident_id"] for x in incidents]
    order = rng.permutation(len(ids))
    ids = [ids[i] for i in order]
    pilot, rest = ids[:SIZES["pilot"]], ids[SIZES["pilot"]:]
    by_id = {x["incident_id"]: x for x in incidents}
    cal_n = SIZES["A"] + SIZES["B"] + SIZES["C"]
    cal, held = rest[:cal_n], rest[cal_n:]
    if heterogeneous:
        cats = sorted({by_id[i]["category"] for i in cal})
        w = rng.dirichlet([0.5] * len(cats))
        pw = np.array([w[cats.index(by_id[i]["category"])] for i in cal])
        c_idx = rng.choice(len(cal), size=SIZES["C"], replace=False, p=pw / pw.sum())
    else:
        c_idx = rng.choice(len(cal), size=SIZES["C"], replace=False)
    c_set = {cal[i] for i in c_idx}
    remaining = [i for i in cal if i not in c_set]
    ops = {"A": remaining[:SIZES["A"]], "B": remaining[SIZES["A"]:], "C": sorted(c_set)}
    # held-out: tag each incident with an operator, using the SAME mix as calibration, so C's own
    # held-out result reflects C's (skewed) population (P1 per-operator evaluation)
    n_c = len(held) // 3
    if heterogeneous:
        hw = np.array([w[cats.index(by_id[i]["category"])] if by_id[i]["category"] in cats else 1e-6
                       for i in held])
        hc = set(rng.choice(len(held), size=n_c, replace=False, p=hw / hw.sum()).tolist())
    else:
        hc = set(rng.choice(len(held), size=n_c, replace=False).tolist())
    ab = [i for k, i in enumerate(held) if k not in hc]
    held_ops = {held[k]: "C" for k in hc}
    held_ops.update({i: "AB"[k % 2] for k, i in enumerate(ab)})
    return {"pilot": pilot, "operators": ops, "heldout": held, "heldout_operator": held_ops,
            "heldout_order": held}   # pre-registered demo order = this order


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", default="synthetic")
    ap.add_argument("--out", default="state/data")
    ap.add_argument("--homogeneous", action="store_true")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    inc = load(a.source)
    cents = fit_categories(inc)                         # fitted on features only, never labels
    for x in inc:
        x["category"] = assign_category(x, cents)
    sp = split(inc, heterogeneous=not a.homogeneous)
    with open(os.path.join(a.out, "incidents.jsonl"), "w") as f:
        for x in inc:
            f.write(json.dumps(x) + "\n")
    json.dump(cents, open(os.path.join(a.out, "categories.json"), "w"))
    json.dump(sp, open(os.path.join(a.out, "splits.json"), "w"), indent=1)
    hashes = {"pilot": _hash(sp["pilot"]), "calibration": _hash(sum(sp["operators"].values(), [])),
              "heldout": _hash(sp["heldout"]), "source": a.source, "seed": SEED}
    json.dump(hashes, open(os.path.join(a.out, "split_hashes.json"), "w"), indent=1)
    print(json.dumps({"incidents": len(inc), "calibration": {k: len(v) for k, v in sp["operators"].items()},
                      "pilot": len(sp["pilot"]), "heldout": len(sp["heldout"]), "hashes": hashes}, indent=1))


if __name__ == "__main__":
    main()
