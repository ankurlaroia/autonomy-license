"""The declared team case and how its records are graded. The note and cell values stay out of the item files."""
import json
from types import SimpleNamespace

import pytest

from aws import evidence as E
from aws.infra import team as Tm
from common.catalogue import CATALOGUE


def plan():
    return E.team_plan("TL-1", "act", ["c1", "c2"], Tm.TASK, Tm.ATTACK)


def test_the_change_is_refused_before_the_approval_and_after_it():
    names = [p["step"] for p in plan()]
    assert names.index("change_refused_before_approval") < names.index("engineer_approves") < \
        names.index("engineer_applies") < names.index("second_change_refused")


def test_every_identity_is_refused_what_it_may_not_do():
    by = {p["step"]: p for p in plan()}
    for s in ("specialist_cannot_ask", "engineer_cannot_ask", "lead_cannot_approve", "specialist_cannot_approve",
              "specialist_cannot_change", "guardrail_stops_prompt_attack"):
        assert by[s]["expect"] == "DENY"
    assert by["engineer_applies"]["who"] == "engineer_client" and by["engineer_applies"]["expect"] == "ALLOW"


def test_refused_steps_have_their_own_trace_so_their_records_show_no_change():
    assert not any(p["shared"] for p in plan() if p["expect"] != "ALLOW")


def test_fill_step_replaces_only_the_placeholders():
    change = next(p for p in plan() if p["step"] == "engineer_applies")["args"]
    got = E.fill_step(change, "APR-1", "note")
    assert got["approval_id"] == "APR-1" and got["cells"] == ["c1", "c2"] and got["action"] == "act"
    assert change["approval_id"] == "{approval_id}"      # the declared plan is not touched


def rec(trace, source, kind):
    return {"source": source, "kind": kind, "record": {"trace_id": trace}, "ts": "2026-11-02T00:00:00.000Z"}


def grade(items, records):
    return E.unit_metric({"unit": "team"}, items, records)


def test_team_metric_passes_when_steps_match_and_only_the_approved_change_applied():
    items = [{"item": "x", "step": "engineer_applies", "trace_id": "t", "expect": "ALLOW", "observed": "ALLOW"},
             {"item": "x", "step": "lead_reads_incident", "trace_id": "t", "expect": "ALLOW", "observed": "ALLOW"}]
    # the second step shares the case's trace, so the change record there must not count against it
    value, rows = grade(items, [rec("t", "tool", "remediation_applied")])
    assert rows[0]["ok"] and rows[1]["ok"] and value == 1.0


def test_team_metric_fails_a_refused_step_that_changed_something():
    items = [{"item": "x", "step": "second_change_refused", "trace_id": "r", "expect": "REFUSED_BY_TOOL",
              "observed": "REFUSED_BY_TOOL"}]
    assert grade(items, [rec("r", "tool", "remediation_applied")])[0] == 0.0
    assert grade(items, [])[0] == 1.0


def test_team_metric_fails_when_the_approved_change_left_no_record():
    items = [{"item": "x", "step": "engineer_applies", "trace_id": "t", "expect": "ALLOW", "observed": "ALLOW"}]
    assert grade(items, [])[0] == 0.0


def test_team_metric_fails_on_the_wrong_outcome():
    items = [{"item": "x", "step": "lead_cannot_approve", "trace_id": "r", "expect": "DENY", "observed": "ALLOW"}]
    assert grade(items, [])[0] == 0.0


def test_item_files_keep_no_note_and_no_cell_values():
    o = {"decision": "ALLOW", "detail": {"ok": True, "result": {"note": "secret text", "before": {"tilt": 3},
                                                                "action_id": "A1", "resolved": True}}}
    d = E.team_detail(o)
    assert "secret text" not in d and "tilt" not in d
    assert json.loads(d)["action_id"] == "A1" and json.loads(d)["note_chars"] == 11


def test_team_runs_before_pause():
    assert E.ORDER.index("team") < E.ORDER.index("pause") and E.ORDER[-1] == "pause"


# ---------------------------------------------------------------- picking the case
@pytest.fixture
def bundle(tmp_path):
    (tmp_path / "data").mkdir()
    rows = [{"incident_id": i, "cells": [{"cell_id": f"{i}-c{n}"} for n in range(k)]}
            for i, k in (("A", 3), ("B", 0), ("C", 3))]
    (tmp_path / "data" / "incidents.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    return str(tmp_path)


PRED = next(iter(CATALOGUE))
SCORES = SimpleNamespace(get=lambda i: {"pred": PRED})


class Ledger:
    def __init__(self, touched=()):
        self.touched = touched

    def changed(self, iid):
        return {"c"} if iid in self.touched else set()


def test_pick_case_takes_at_most_the_blast_radius_in_preregistered_order(bundle):
    iid, action, cells = Tm.pick_case(bundle, ["A", "C"], SCORES, Ledger())
    assert iid == "A" and action == CATALOGUE[PRED]["action"] and cells == ["A-c0", "A-c1"]


def test_pick_case_skips_touched_empty_and_used_incidents(bundle):
    assert Tm.pick_case(bundle, ["A", "B", "C"], SCORES, Ledger(["A"]))[0] == "C"
    assert Tm.pick_case(bundle, ["A", "C"], SCORES, Ledger(), {"A"})[0] == "C"
    with pytest.raises(SystemExit):
        Tm.pick_case(bundle, ["A", "C"], SCORES, Ledger(["A", "C"]))
