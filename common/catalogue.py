"""Shared definitions: root causes C1-C8, the action catalogue and autonomy classes.

The catalogue is illustrative (spec 5.1), executed only on the simulator. It is NOT validated RAN
engineering practice. The certificate bounds wrong diagnoses; the catalogue + Cedar enforce action safety.
"""

CAUSES = ["C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8"]

CAUSE_TEXT = {
    "C1": "Test vehicle speed exceeds 40 km/h",
    "C2": "Serving-cell downtilt too large; weak far-end coverage",
    "C3": "Serving-cell coverage distance exceeds 1 km; poor RSRP",
    "C4": "Non-co-located co-frequency neighbours cause severe interference",
    "C5": "Neighbour and serving cell share PCI mod 30",
    "C6": "Frequent handovers degrade performance",
    "C7": "Misconfigured handover thresholds",
    "C8": "Average scheduled RBs of serving cell below 160",
}

# cause -> (action, autonomy class, parameter change applied by the simulator)
CATALOGUE = {
    "C1": {"action": "annotate_close", "cls": "AUTO", "param": None},
    "C2": {"action": "adjust_tilt", "cls": "AUTO", "param": ("downtilt_deg", -2.0)},
    "C3": {"action": "plan_new_site", "cls": "NEVER", "param": None},
    "C4": {"action": "adjust_neighbour_power", "cls": "HUMAN", "param": ("tx_power_dbm", -3.0)},
    "C5": {"action": "reassign_pci", "cls": "AUTO", "param": ("pci", "reassign")},
    "C6": {"action": "set_handover_params", "cls": "AUTO", "param": ("ho_ttt_ms", +160)},
    "C7": {"action": "set_handover_params", "cls": "AUTO", "param": ("ho_a3_offset_db", -3.0)},
    "C8": {"action": "rebalance_scheduler", "cls": "HUMAN", "param": ("rb_scheduled", +60)},
}

AUTO_ACTIONS = sorted({v["action"] for v in CATALOGUE.values() if v["cls"] == "AUTO"})
NEVER_AUTONOMOUS = ["plan_new_site", "power_down_cells", "restart_core_function", "change_emergency_config"]
ALL_ACTIONS = sorted({v["action"] for v in CATALOGUE.values()} | set(NEVER_AUTONOMOUS))

CATEGORIES = ["k1", "k2", "k3", "k4"]   # incident categories (feature clusters), NOT root causes
BLAST_RADIUS = 3                        # absolute hard rule, applies to engineers too


def actions_for_cause(cause: str) -> str:
    return CATALOGUE[cause]["action"]
