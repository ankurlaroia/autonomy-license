"""Cell simulator (spec 14.3). Changes small cell-state records; nothing touches a real network.

* Called only after Cedar ALLOW and the tool Lambda's own checks: a denied call never reaches it.
* 'resolved' is decided from the ground-truth label (the catalogue action for the true cause).
  DISCLOSE THIS: the simulator shows the consequences of enforcement decisions, not real
  remediation efficacy.
"""
from __future__ import annotations

import json
import time
import uuid

from common.catalogue import CATALOGUE

EFFECTS = {
    "adjust_tilt": [("downtilt_deg", -2.0)],
    "reassign_pci": [("pci", "reassign")],
    "set_handover_params": [("ho_ttt_ms", +160), ("ho_a3_offset_db", -1.5)],
    "adjust_neighbour_power": [("tx_power_dbm", -3.0)],
    "rebalance_scheduler": [("rb_scheduled", +60)],
    "annotate_close": [],
}


class Simulator:
    def __init__(self, store):
        self.s = store

    def ensure(self, inc: dict):
        for c in inc["cells"]:
            self.s.x("INSERT OR IGNORE INTO cells VALUES (?,?,?,?)",
                     (inc["incident_id"], c["cell_id"], json.dumps(c), 0))

    def state(self, incident_id: str) -> dict:
        rows = self.s.q("SELECT cell_id, params, version FROM cells WHERE incident_id=?", (incident_id,))
        return {r[0]: {**json.loads(r[1]), "version": r[2]} for r in rows}

    def kpi(self, incident_id: str, inc: dict) -> float:
        r = self.s.q("SELECT resolved FROM sim_actions WHERE incident_id=? AND resolved=1", (incident_id,))
        return 780.0 if r else inc["features"]["dl_tput_mbps"]

    def apply(self, inc: dict, action: str, cells: list[str]) -> dict:
        iid = inc["incident_id"]
        self.ensure(inc)
        with self.s._lock:
            self.s.db.execute("BEGIN IMMEDIATE")
            try:
                before = self.state(iid)
                after = {k: dict(v) for k, v in before.items()}
                for cid in sorted(set(cells)):
                    for param, delta in EFFECTS.get(action, []):
                        if param == "pci":
                            after[cid]["pci"] = (after[cid]["pci"] + 1) % 504
                        else:
                            after[cid][param] = round(after[cid].get(param, 0) + delta, 2)
                    after[cid]["version"] += 1
                    p = {k: v for k, v in after[cid].items() if k != "version"}
                    self.s.db.execute("UPDATE cells SET params=?, version=? WHERE incident_id=? AND cell_id=?",
                                      (json.dumps(p), after[cid]["version"], iid, cid))
                resolved = int(CATALOGUE[inc["label"]]["action"] == action)
                aid = "ACT-" + uuid.uuid4().hex[:10]
                self.s.db.execute("INSERT INTO sim_actions VALUES (?,?,?,?,?,?,?,?)",
                                  (aid, iid, action, json.dumps(sorted(set(cells))),
                                   json.dumps({c: before[c] for c in set(cells)}),
                                   json.dumps({c: after[c] for c in set(cells)}), resolved, time.time()))
                self.s.db.execute("COMMIT")
            except Exception:
                self.s.db.execute("ROLLBACK")
                raise
        return {"action_id": aid, "before": {c: before[c] for c in set(cells)},
                "after": {c: after[c] for c in set(cells)}, "resolved": bool(resolved),
                "kpi_before": inc["features"]["dl_tput_mbps"], "kpi_after": self.kpi(iid, inc),
                "note": "simulated; resolution decided from ground truth"}

    def mutation_count(self) -> int:
        return self.s.q("SELECT COUNT(*) FROM sim_actions")[0][0]
