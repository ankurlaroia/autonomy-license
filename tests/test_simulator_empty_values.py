"""Live run 2026-11-02: a cell with an empty value crashed the simulator after the approval had been spent."""
import pytest

from aws.tool_lambda.simulator import EFFECTS, Simulator
from common.catalogue import CATALOGUE
from common.store import Store

LABEL = next(iter(CATALOGUE))


@pytest.mark.parametrize("action", [a for a, e in EFFECTS.items() if e])
def test_empty_values_count_as_absent(tmp_path, action):
    params = {p: None for p, _ in EFFECTS[action]}
    inc = {"incident_id": "I", "label": LABEL, "features": {"dl_tput_mbps": 1.0}, "cells": [{"cell_id": "c1", **params}]}
    res = Simulator(Store(str(tmp_path / "t.db"))).apply(inc, action, ["c1"])
    assert res["after"]["c1"]["version"] == 1
    assert all(res["after"]["c1"][p] is not None for p in params)
