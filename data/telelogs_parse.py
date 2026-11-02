"""Parse one TeleLogs `troubleshooting` row ({"question", "answer"}) into the normalised incident format
(data/synthetic_telelogs.py). Layout from the TeleLogs paper (arXiv 2507.21974, Fig. 8): a task text, the
eight candidate causes as "Cn : <text>", rules, a pipe table of user-plane drive-test samples and a pipe
table of engineering parameters. The answer names the cause, e.g. "\\boxed{C3}".

Cause codes are NOT positional. The paper's question numbers the causes differently from the model card
(which common/catalogue.py follows): TeleLogs C1 is "downtilt too large", catalogue C1 is "speed". Each
question lists its own definitions, so codes are mapped by meaning (CANON_RULES) per row, and the row is
dropped if the eight definitions do not map one-to-one. The classifier predicts TeleLogs codes, so its
probabilities are re-ordered through the same per-row map (row["code_map"]).

Single-cause eligibility (spec 5.2): an answer naming more or fewer than one cause gives None.
Parameters TeleLogs does not carry (handover TTT/offset) get documented simulator defaults, listed in
`_sim_defaults`; they are simulator state, never evidence for the diagnosis.
"""
from __future__ import annotations

import hashlib
import math
import re

# (catalogue code, all of these words must appear in the cause text). First match wins; order matters.
CANON_RULES = [
    ("C5", ("pci", "30")),
    ("C1", ("speed",)),
    ("C2", ("downtilt",)),
    ("C3", ("distance",)),
    ("C4", ("co-frequency",)),
    ("C4", ("cofrequency",)),
    ("C6", ("frequent", "handover")),
    ("C7", ("handover", "threshold")),
    # ASSUMPTION (confirm on the first 20 rows): the paper's "a neighbouring cell provides higher throughput"
    # is the model card's "misconfigured handover thresholds": the UE stays on a worse cell because the
    # handover does not fire. Same remediation (handover parameters), so the catalogue action is unchanged.
    ("C7", ("neighbo", "higher throughput")),
    ("C8", ("rb",)),
]
DEFAULT_TILT_CODE, DEFAULT_TILT_DEG = 255, 6.0       # "default electronic downtilt 255 = 6 degrees"
SIM_DEFAULTS = {"ho_ttt_ms": 320, "ho_a3_offset_db": 3.0}


def canonical(cause_text: str) -> str | None:
    t = cause_text.lower().replace("’", "'")
    for code, words in CANON_RULES:
        if all(w in t for w in words):
            return code
    return None


def cause_map(question: str) -> dict[str, str] | None:
    """TeleLogs code -> catalogue code, from the question's own list. None unless one-to-one over C1..C8."""
    defs = dict(re.findall(r"^\s*(C[1-8])\s*[:：]\s*(.+?)\s*$", question, flags=re.M))
    if sorted(defs) != [f"C{i}" for i in range(1, 9)]:
        return None
    m = {k: canonical(v) for k, v in defs.items()}
    return m if None not in m.values() and len(set(m.values())) == 8 else None


def answer_codes(answer) -> set[str]:
    return set(re.findall(r"C[1-8]", str(answer or "")))


# ---------------------------------------------------------------- tables
def _norm(col: str) -> str:
    return re.sub(r"[^a-z0-9]", "", col.lower())


def _table(question: str, header_key: str) -> list[dict]:
    lines = question.splitlines()
    for i, ln in enumerate(lines):
        if "|" in ln and header_key in _norm(ln):
            cols = [_norm(c) for c in ln.split("|")]
            rows = []
            for row in lines[i + 1:]:
                cells = [c.strip() for c in row.split("|")]
                if "|" not in row or len(cells) != len(cols):
                    if rows:
                        break
                    continue
                rows.append(dict(zip(cols, cells)))
            return rows
    return []


def _col(row: dict, *keys: str):
    """Value of the first column whose normalised name contains every key."""
    for k, v in row.items():
        if all(x in k for x in keys):
            return v
    return None


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _mean(xs):
    xs = [x for x in xs if x is not None]
    return sum(xs) / len(xs) if xs else None


def _metres(lon1, lat1, lon2, lat2) -> float:
    p1, p2 = math.radians(lat1), math.radians(lat2)
    a = math.sin((p2 - p1) / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(math.radians(lon2 - lon1) / 2) ** 2
    return 2 * 6371000 * math.asin(math.sqrt(a))


# ---------------------------------------------------------------- row
def parse_row(row: dict) -> dict | None:
    q, a = row.get("question"), row.get("answer")
    if not isinstance(q, str):
        return None
    cmap = cause_map(q)
    codes = answer_codes(a)
    if cmap is None or len(codes) != 1:
        return None                                        # unmappable causes, or not single-cause
    drive, eng = _table(q, "timestamp"), _table(q, "gnodebid")
    if not drive or not eng:
        return None
    serving_pcis = [_num(_col(r, "serving", "pci")) for r in drive]
    if None in serving_pcis:
        return None
    pcis = [int(p) for p in serving_pcis]
    main_pci = max(set(pcis), key=pcis.count)

    cells, by_pci = [], {}
    for e in eng:
        pci, mech, dig = _num(_col(e, "pci")), _num(_col(e, "mechanicaldowntilt")), _num(_col(e, "digitaltilt"))
        if pci is None:
            continue
        tilt = (mech or 0.0) + (DEFAULT_TILT_DEG if dig in (None, DEFAULT_TILT_CODE) else dig)
        c = {"cell_id": f"{_col(e, 'gnodeb')}-{_col(e, 'cellid')}", "gnb": _col(e, "gnodeb"), "pci": int(pci),
             "downtilt_deg": round(tilt, 1), "lon": _num(_col(e, "longitude")), "lat": _num(_col(e, "latitude")),
             "tx_power_dbm": _num(_col(e, "maxtransmitpower")), **SIM_DEFAULTS}
        cells.append(c)
        by_pci.setdefault(int(pci), c)
    serving = by_pci.get(main_pci)
    if serving is None:
        return None
    for c in cells:
        c["role"] = "serving" if c is serving else ("cosite" if c["gnb"] == serving["gnb"] else "neighbour")
        c["co_located"] = c["gnb"] == serving["gnb"]

    rb = [_num(_col(r, "rbnum")) for r in drive]
    dist = []
    for r, p in zip(drive, pcis):
        c, lon, lat = by_pci.get(p), _num(_col(r, "longitude")), _num(_col(r, "latitude"))
        if c and None not in (c["lon"], c["lat"], lon, lat):
            dist.append(_metres(c["lon"], c["lat"], lon, lat))
    nb_pci = [_num(_col(r, "top1", "pci")) for r in drive]
    srv_rsrp = [_num(_col(r, "serving", "rsrp")) for r in drive]
    nb_rsrp = [_num(_col(r, "top1", "rsrp")) for r in drive]
    gaps = [s - n for s, n in zip(srv_rsrp, nb_rsrp) if s is not None and n is not None]
    avg_rb = _mean(rb)
    serving["rb_scheduled"] = round(avg_rb) if avg_rb is not None else None
    for c in cells:
        c.setdefault("rb_scheduled", None)
        del c["gnb"], c["lon"], c["lat"]
    feats = {
        "speed_kmh": _mean(_num(_col(r, "speed")) for r in drive),
        "serving_distance_m": _mean(dist),
        "serving_rsrp_dbm": _mean(srv_rsrp),
        "sinr_db": _mean(_num(_col(r, "serving", "sinr")) for r in drive),
        "cofreq_gap_db": _mean(gaps),
        "pci_mod30_clash": int(any(n is not None and int(n) != p and int(n) % 30 == p % 30
                                   for p, n in zip(pcis, nb_pci))),
        "n_handovers": sum(1 for x, y in zip(pcis, pcis[1:]) if x != y),
        "avg_rb": avg_rb,
        "dl_tput_mbps": _mean(_num(_col(r, "throughput")) for r in drive),
    }
    feats = {k: (round(v, 2) if isinstance(v, float) else v) for k, v in feats.items()}
    if feats["speed_kmh"] is None or feats["serving_distance_m"] is None or avg_rb is None:
        return None                                        # categories need these; never guess them
    (code,) = codes
    return {"incident_id": "TL-" + hashlib.sha256(q.encode()).hexdigest()[:12],
            "cells": [serving] + [c for c in cells if c is not serving],
            "features": feats, "label": cmap[code], "telelogs_label": code, "code_map": cmap,
            "raw_text": q, "_sim_defaults": sorted(SIM_DEFAULTS), "_source": "telelogs"}


def text_hash(row: dict) -> str:
    return hashlib.sha256(str(row.get("question", "")).encode()).hexdigest()
