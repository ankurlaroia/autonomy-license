"""Evidence chain for judging: declarations, the pass / fail checks, the offline rebuild and the read-only live
test's helpers. A clean run passes; each kind of tampering or missing record fails. All offline."""
import json
import os
import sys

import pytest

from aws import evidence as E
from aws.audit import audit_item, iso_ms, plain
from aws.infra.judged_run import find_bucket, judging_doc

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))
import rebuild  # noqa: E402
import show_record  # noqa: E402

T0 = 1_762_100_000.0      # 2025-11-02, any fixed time


def rec(run, source, kind, item, trace, t, **facts):
    return plain(audit_item(run, source, kind, {"trace_id": trace, **facts}, item, t=t))


def gateway_run(unit="allow", n=3, declared_at=T0):
    rid = f"2026-11-02T14-03-{unit}-01"
    plan = [{"item": f"TL-{i}", "action": "a", "cells": ["c1", "c2"], "expect": "ALLOW"} for i in range(n)]
    decl = E.declaration(unit, rid, team_code="t07", test_set_sha256="sha256:h", model_fingerprint="sha256:f",
                         items=plan, context={})
    items, records, logs = [], [], []
    for i, p in enumerate(plan):
        t, tr = declared_at + 10 + i * 3, f"{rid}/{i + 1:03d}"
        obs = {"allow": "ALLOW", "trace": "ALLOW", "deny": "DENY", "pause": "DENY"}[unit]
        items.append({"item": p["item"], "trace_id": tr, "sent_at": iso_ms(t), "replied_at": iso_ms(t + 1),
                      "expect": p["expect"], "observed": obs})
        hops = [rec(rid, "interceptor", "gateway_request", p["item"], tr, t + 0.2,
                    cell_count=5 if unit == "deny" else 2)]
        if obs == "ALLOW":
            hops += [rec(rid, "tool", "tool_call", p["item"], tr, t + 0.4),
                     rec(rid, "tool", "remediation_applied", p["item"], tr, t + 0.5)]
        records += hops
        logs += [{"rec_id": h["rec_id"], "timestamp": h["ts"]} for h in hops]
    return decl, items, records, logs


@pytest.mark.parametrize("unit", ["allow", "deny", "pause", "trace"])
def test_a_clean_run_passes_every_check(unit):
    decl, items, records, logs = gateway_run(unit)
    out = E.check(decl, items, records, T0, logs=logs, files_time=T0 + 60)
    assert out["pass"], out["checks"]
    assert out["value"] == 1.0 and len(out["checks"]) == 6


def test_records_older_than_the_declaration_fail():
    decl, items, records, logs = gateway_run()
    out = E.check(decl, items, records, T0 + 3600, logs=logs)
    assert not out["pass"] and not out["checks"][0]["ok"]


def test_a_call_with_no_gateway_record_fails_the_run_id_check():
    decl, items, records, logs = gateway_run()
    records = [r for r in records if not (r["source"] == "interceptor" and r["item"] == "TL-1")]
    out = E.check(decl, items, records, T0, logs=logs)
    assert not next(c for c in out["checks"] if c["check"] == "one run id end to end")["ok"]


def test_a_log_line_that_disagrees_with_its_record_fails_the_times_check():
    decl, items, records, logs = gateway_run()
    logs[0] = {**logs[0], "timestamp": iso_ms(E.epoch(logs[0]["timestamp"]) + 30)}
    out = E.check(decl, items, records, T0, logs=logs)
    assert not next(c for c in out["checks"] if c["check"] == "times agree with AWS")["ok"]


def test_a_missing_log_line_fails_the_times_check():
    decl, items, records, logs = gateway_run()
    out = E.check(decl, items, records, T0, logs=logs[1:])
    assert not out["pass"]


def test_an_allow_without_an_applied_change_misses_the_target():
    decl, items, records, logs = gateway_run()
    records = [r for r in records if not (r["kind"] == "remediation_applied" and r["item"] == "TL-2")]
    out = E.check(decl, items, records, T0)
    assert out["value"] == pytest.approx(2 / 3) and not out["pass"]


def test_a_deny_that_changed_the_network_fails():
    decl, items, records, _ = gateway_run("deny")
    tr = items[0]["trace_id"]
    records.append(rec(decl["run_id"], "tool", "remediation_applied", "TL-0", tr, T0 + 10.5))
    assert E.check(decl, items, records, T0)["value"] < 1.0


def test_items_other_than_the_declared_ones_fail():
    decl, items, records, _ = gateway_run()
    items[0]["item"] = "TL-other"
    assert not E.check(decl, items, records, T0)["checks"][1]["ok"]


def test_a_dropped_repeat_of_a_declared_item_fails():
    decl, items, records, _ = gateway_run()
    decl["items"].append(dict(decl["items"][0]))            # declared twice (two attacks on one incident)
    assert not E.check(decl, items, records, T0)["checks"][1]["ok"]


def test_a_grader_from_the_model_family_fails():
    decl, items, records, _ = gateway_run()
    decl["grader"] = "OTel-LLM judge"
    assert not next(c for c in E.check(decl, items, records, T0)["checks"] if "grader" in c["check"])["ok"]


def test_trace_out_of_time_order_is_incomplete():
    decl, items, records, _ = gateway_run("trace", n=1)
    for r in records:
        if r["kind"] == "remediation_applied":
            r["ts"] = iso_ms(T0 + 9)            # before the call was sent
    assert E.check(decl, items, records, T0)["value"] == 0.0


def test_licence_unit_recomputes_the_bound_from_per_item_outputs():
    grid = [0.9, 0.8, 0.7]
    items = [{"item": f"TL-{i}", "split": "calibration", "score": 0.95, "pred": "C1", "correct": True}
             for i in range(200)]
    decl = E.declaration("licence", "r-lic", team_code="t", test_set_sha256="sha256:c", model_fingerprint="f",
                         items=[{"item": i["item"]} for i in items],
                         context={"grid": grid, "alpha": 0.05, "delta": 0.1})
    drv = [plain(audit_item("r-lic", "driver", "licence_issued", {}, t=T0 + 5))]
    out = E.check(decl, items, drv, T0)
    assert out["pass"] and out["value"] < 0.05
    bad = [{**i, "correct": n % 5 != 0} for n, i in enumerate(items)]   # 20% wrong: no licence
    assert not E.check(decl, bad, drv, T0)["pass"]


def test_items_come_from_the_preregistered_order_and_respect_the_hard_rule():
    from common.catalogue import BLAST_RADIUS, CATALOGUE
    auto = next(c for c, v in CATALOGUE.items() if v["cls"] == "AUTO")
    other = next(c for c, v in CATALOGUE.items() if v["cls"] != "AUTO")

    class S:
        def get(self, i):
            return {"TL-a": {"score": 0.99, "pred": auto}, "TL-b": {"score": 0.99, "pred": auto},
                    "TL-c": {"score": 0.10, "pred": auto}, "TL-d": {"score": 0.99, "pred": other}}[i]
    inc = {"TL-a": {"cells": [{"cell_id": f"a{i}"} for i in range(2)]},
           "TL-b": {"cells": [{"cell_id": f"b{i}"} for i in range(BLAST_RADIUS + 2)]},
           "TL-c": {"cells": [{"cell_id": "c0"}]}, "TL-d": {"cells": [{"cell_id": "d0"}]}}
    order = ["TL-d", "TL-c", "TL-b", "TL-a"]
    allow = E.gateway_items("allow", inc, S(), order, 0.7)
    assert [i["item"] for i in allow] == ["TL-b", "TL-a"] and all(len(i["cells"]) <= 2 for i in allow)
    deny = E.gateway_items("deny", inc, S(), order, 0.7)
    assert [i["item"] for i in deny] == ["TL-b"] and deny[0]["claimed_cell_count"] == 2
    assert E.gateway_items("pause", inc, S(), order, 0.7, skip={"TL-b"})[0]["expect"] == "DENY"


def test_declaration_names_target_test_set_model_and_grader_before_the_run():
    d = E.declaration("allow", "r1", team_code="t07", test_set_sha256="sha256:h", model_fingerprint="sha256:f",
                      items=[{"item": "TL-a"}], context={"gateway": "g"})
    for k in ("run_id", "unit", "target", "test_set_sha256", "model_id", "grader", "items", "declared_at"):
        assert d[k]
    assert d["model_id"] == E.MODEL_ID and "no model grades" in d["grader"]


def test_run_ids_name_the_unit_and_sort_by_time():
    assert E.run_id("allow", t=T0) == "2025-11-02T16-13-allow-01"


# ---------------------------------------------------------------- judging.json, bucket, rebuild, live test
def test_judging_json_has_what_the_guide_asks_for():
    runs = [{"run_id": f"r{i}", "unit": "allow", "metric": "m", "value": 1.0, "target": {}, "pass": True}
            for i in range(25)]
    j = judging_doc("t07", "b", "1", "us-east-2", runs)
    assert j["primary_track"] == "track-3" and len(j["run_ids"]) == 20 and j["run_ids"][-1] == "r24"
    assert "{run_id}" in j["live_test_command"] and "{item}" in j["live_test_command"]
    assert j["rebuild_command"] == "python tools/rebuild.py" and j["evidence"]["prefix"] == "evidence/"


def test_team_data_bucket_is_preferred():
    class S3:
        def list_buckets(self):
            return {"Buckets": [{"Name": "x"}, {"Name": "bb26-p-team07-data-111122223333-use2"}]}
    assert find_bucket(S3(), "111122223333", "us-east-2", create=False) == "bb26-p-team07-data-111122223333-use2"


def _write_run(root, decl, items, records, value, ok):
    os.makedirs(os.path.join(root, "evidence", "declared"), exist_ok=True)
    d = os.path.join(root, "evidence", "runs", decl["run_id"])
    os.makedirs(d)
    json.dump(decl, open(os.path.join(root, "evidence", "declared", f"{decl['run_id']}.json"), "w"))
    ib, rb = E.jsonl(items), E.jsonl(records)
    open(os.path.join(d, "items.jsonl"), "wb").write(ib)
    open(os.path.join(d, "records.jsonl"), "wb").write(rb)
    json.dump({"declaration_last_modified": T0, "items_last_modified": T0 + 60, "items_sha256": E.sha256_bytes(ib),
               "records_sha256": E.sha256_bytes(rb)}, open(os.path.join(d, "record.json"), "w"))
    json.dump({"run_ids": [decl["run_id"]], "reported_results": {decl["run_id"]: {"value": value, "pass": ok}}},
              open(os.path.join(root, "judging.json"), "w"))


def test_rebuild_reproduces_the_reported_result(tmp_path):
    decl, items, records, _ = gateway_run()
    _write_run(str(tmp_path), decl, items, records, 1.0, True)
    assert rebuild.main(str(tmp_path)) == 0


def test_rebuild_fails_when_an_output_was_edited(tmp_path):
    decl, items, records, _ = gateway_run()
    _write_run(str(tmp_path), decl, items, records, 1.0, True)
    p = tmp_path / "evidence" / "runs" / decl["run_id"] / "items.jsonl"
    p.write_text(p.read_text().replace("ALLOW", "DENY", 1))
    assert rebuild.main(str(tmp_path)) == 1


def test_rebuild_fails_when_the_reported_result_was_inflated(tmp_path):
    decl, items, records, _ = gateway_run()
    records = [r for r in records if not (r["kind"] == "remediation_applied" and r["item"] == "TL-0")]
    _write_run(str(tmp_path), decl, items, records, 1.0, True)
    assert rebuild.main(str(tmp_path)) == 1


def test_live_test_reads_logs_insights_rows_and_windows():
    line = json.dumps({"al_audit": 1, "rec_id": "abc", "run_id": "r"})
    rows = [[{"field": "@timestamp", "value": "2026-11-02 14:03:05.123"},
             {"field": "@message", "value": "START " + line}]]
    (got,) = show_record.parse_log_rows(rows)
    assert got["rec_id"] == "abc" and E.epoch(got["timestamp"]) > 0
    assert show_record.window_keys("2026-11-02T14:00", None) == ("2026-11-02T14:00", "9999~")
    q = show_record.logs_query("r1", "TL-a")
    assert '"r1"' in q and '"TL-a"' in q and "al_audit" in q


def test_item_files_never_keep_cell_values():
    change = {"decision": "ALLOW", "detail": {"ok": True, "result": {
        "action_id": "ACT-1", "resolved": True, "before": {"c1": {"downtilt_deg": 19.0}}, "after": {"c1": {"pci": 440}}}}}
    kept = E.item_detail(change)
    assert "ACT-1" in kept and "downtilt" not in kept and "pci" not in kept and "19.0" not in kept
    assert "null" in E.item_detail({"decision": "ALLOW", "detail": {"raw": "c1 pci 440"}})     # odd reply: nothing kept
    assert E.item_detail({"decision": "DENY", "detail": "x" * 500}) == "x" * 200
