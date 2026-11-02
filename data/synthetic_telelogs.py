"""SYNTHETIC STAND-IN for TeleLogs single-cause incidents.

TeleLogs (netop/TeleLogs) is gated and must not be redistributed, so this module generates
incidents with the same *shape* (gNodeB engineering parameters + drive-test summary, one of
eight root causes) so the whole pipeline can be built and tested before access is granted.

Nothing produced here is a TeleLogs result. On Sunday, data/prepare_telelogs.py replaces this
source; every downstream module consumes the same normalised record format:

  {"incident_id": str,
   "cells": [{"cell_id", "role": serving|cosite|neighbour, "downtilt_deg", "pci", "ho_ttt_ms",
              "ho_a3_offset_db", "rb_scheduled", "tx_power_dbm", "co_located": bool}],
   "features": {"speed_kmh", "serving_distance_m", "serving_rsrp_dbm", "sinr_db",
                "cofreq_gap_db", "pci_mod30_clash", "n_handovers", "avg_rb", "dl_tput_mbps"},
   "label": "C1".."C8"          # ground truth: evaluation pipeline only, never sent to the agent
   "_source": "synthetic"}
"""
from __future__ import annotations

import numpy as np

from common.catalogue import CAUSES

# How far each cause's "primary signal" sits beyond its threshold, in normalised units.
# Smaller margins make incidents ambiguous for the classifier stand-in.


def _margin(rng, inside: bool):
    m = abs(rng.normal(1.0, 0.7)) + 0.05
    return m if inside else -m


def generate(n: int = 800, seed: int = 20261101):
    rng = np.random.default_rng(seed)
    out = []
    for i in range(n):
        y = CAUSES[rng.integers(0, 8)]
        mg = {c: _margin(rng, c == y) for c in CAUSES}     # >0 means the cause's condition holds
        serving_pci = int(rng.integers(0, 504))
        clash = mg["C5"] > 0
        nb_pci = serving_pci + 30 * int(rng.integers(1, 5)) if clash else serving_pci + int(rng.integers(1, 29))
        cells = [
            {"cell_id": f"gNB{i % 97:02d}-S1", "role": "serving", "co_located": True,
             "downtilt_deg": round(9 + 2.5 * mg["C2"], 1), "pci": serving_pci % 504,
             "ho_ttt_ms": 320 if mg["C6"] < 0 else 64, "ho_a3_offset_db": round(3 + 2.0 * max(mg["C7"], -1), 1),
             "rb_scheduled": int(160 - 30 * mg["C8"]), "tx_power_dbm": 43.0},
            {"cell_id": f"gNB{i % 97:02d}-S2", "role": "cosite", "co_located": True,
             "downtilt_deg": round(8 + rng.normal(0, 1), 1), "pci": (serving_pci + 1) % 504,
             "ho_ttt_ms": 320, "ho_a3_offset_db": 3.0, "rb_scheduled": int(rng.integers(170, 260)),
             "tx_power_dbm": 43.0},
        ]
        for j in range(3):
            cells.append({"cell_id": f"gNB{(i + 11 * (j + 1)) % 97:02d}-N{j + 1}", "role": "neighbour",
                          "co_located": False, "downtilt_deg": round(8 + rng.normal(0, 1.5), 1),
                          "pci": (nb_pci if j == 0 else serving_pci + 7 * (j + 1)) % 504,
                          "ho_ttt_ms": 320, "ho_a3_offset_db": 3.0,
                          "rb_scheduled": int(rng.integers(170, 260)), "tx_power_dbm": 43.0})
        feats = {
            "speed_kmh": round(40 + 18 * mg["C1"], 1),
            "serving_distance_m": round(1000 + 300 * mg["C3"]),
            "serving_rsrp_dbm": round(-95 - 6 * max(mg["C3"], 0) - 4 * max(mg["C2"], 0) + rng.normal(0, 2), 1),
            "sinr_db": round(12 - 6 * max(mg["C4"], 0) + rng.normal(0, 2), 1),
            "cofreq_gap_db": round(3 - 2.5 * mg["C4"], 1),          # neighbour within 3 dB of serving => C4
            "pci_mod30_clash": int(clash),
            "n_handovers": int(max(0, round(4 + 2.5 * mg["C6"]))),
            "avg_rb": int(160 - 30 * mg["C8"]),
            "dl_tput_mbps": round(float(rng.uniform(250, 590)), 1),  # symptom: always < 600 Mbps
        }
        out.append({"incident_id": f"INC-{i:05d}", "cells": cells, "features": feats, "label": y,
                    "_margins": {c: round(float(v), 4) for c, v in mg.items()}, "_source": "synthetic"})
    return out
