"""The live test reads the raw log events when Logs Insights leaves out lines, and a line in neither still fails."""
import json

from aws import evidence as E
from aws.audit import MARK
from tools.show_record import complete_lines, read_log_lines

T = 1793664119.0
ISO = "2026-11-03T00:01:59.000Z"


def rec(rec_id, source="tool"):
    return {"rec_id": rec_id, "source": source, "ts": ISO}


def event(rec_id, run="R", t=T):
    return {"timestamp": int(t * 1000), "message": json.dumps({MARK: 1, "rec_id": rec_id, "run_id": run}) + "\n"}


class Logs:
    def __init__(self, pages):
        self.pages, self.calls = list(pages), []

    def filter_log_events(self, **kw):
        self.calls.append(kw)
        return self.pages.pop(0)


def test_all_pages_are_read_and_other_lines_skipped():
    logs = Logs([{"events": [event("a"), {"timestamp": 1, "message": "START RequestId"}], "nextToken": "n"},
                 {"events": [event("b")]},
                 {"events": [{"timestamp": 1, "message": '{"rec_id": "not-audit"}'}]}])
    out = read_log_lines(logs, ["g1", "g2"], "R", 10, 20)
    assert [x["rec_id"] for x in out] == ["a", "b"] and out[0]["timestamp"] == ISO
    assert logs.calls[0] == {"logGroupName": "g1", "startTime": 10000, "endTime": 20000, "filterPattern": '"R"'}
    assert logs.calls[1]["nextToken"] == "n" and logs.calls[2]["logGroupName"] == "g2"


def test_no_extra_read_when_insights_found_every_line():
    logs = Logs([])
    found = [{"rec_id": "a", "timestamp": ISO}]
    assert complete_lines(logs, ["g"], "R", 1, 2, [rec("a"), rec("d", "driver")], found) == found
    assert logs.calls == []


def test_missing_lines_are_added_without_duplicates():
    found = [{"rec_id": "a", "timestamp": ISO, "line": {}}]
    out = complete_lines(Logs([{"events": [event("a"), event("b")]}]), ["g"], "R", 1, 2, [rec("a"), rec("b")], found)
    assert sorted(x["rec_id"] for x in out) == ["a", "b"] and len(out) == 2


def test_a_line_in_neither_place_or_at_another_time_is_still_caught():
    records = [rec("a"), rec("gone"), rec("late")]
    out = complete_lines(Logs([{"events": [event("a"), event("late", t=T + E.LOG_SKEW_S + 1)]}]), ["g"], "R", 1, 2, records, [])
    have = {x["rec_id"]: E.epoch(x["timestamp"]) for x in out}
    assert "gone" not in have and abs(have["a"] - T) <= E.LOG_SKEW_S < abs(have["late"] - T)
