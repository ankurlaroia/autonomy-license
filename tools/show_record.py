"""The read-only live test: show the record for an item in a run (and window), then the run's pass / fail checks.

    python tools/show_record.py --run-id <run_id> --item <TL-id>
    python tools/show_record.py --run-id <run_id> --item <TL-id> --from 2026-11-02T14:00:00 --to 2026-11-02T15:00:00
    python tools/show_record.py --list                       # the run ids in judging.json and their units

Read calls only (they keep working after the account turns read-only): S3 GetObject / HeadObject,
DynamoDB Query, CloudWatch Logs Insights StartQuery / GetQueryResults, STS GetCallerIdentity. It never calls a
model, an agent, a Lambda function or Athena, and it writes nothing.

What the chair can open to compare, for the same run id and item:
  S3        s3://<bucket>/evidence/declared/<run_id>.json and evidence/runs/<run_id>/items.jsonl
  DynamoDB  table al-audit, partition key run_id = <run_id>
  Logs      Logs Insights on /aws/lambda/al-netops-interceptor and /aws/lambda/al-netops-tools:
            fields @timestamp, @message | filter @message like "<run_id>" and @message like "<item>"
Exit code 0 when every check passes.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aws import evidence as E  # noqa: E402
from aws.audit import MARK, plain  # noqa: E402


def window_keys(start: str | None, end: str | None) -> tuple[str, str]:
    """Sort-key bounds for a time window (sk starts with the UTC time)."""
    return (start or "0000"), ((end or "9999") + "~")


def logs_query(run_id: str, item: str | None) -> str:
    q = f'fields @timestamp, @message | filter @message like "{MARK}" and @message like "{run_id}"'
    if item:
        q += f' and @message like "{item}"'
    return q + " | sort @timestamp asc | limit 10000"


def parse_log_rows(rows: list[list[dict]]) -> list[dict]:
    """Logs Insights rows -> [{rec_id, timestamp, line}]. @timestamp is the time CloudWatch recorded (UTC)."""
    out = []
    for row in rows:
        f = {c["field"]: c["value"] for c in row}
        try:
            line = json.loads(f["@message"][f["@message"].index("{"):])
        except (KeyError, ValueError):
            continue
        ts = f.get("@timestamp", "").replace(" ", "T")
        out.append({"rec_id": line.get("rec_id"), "timestamp": (ts + "Z") if ts and not ts.endswith("Z") else ts,
                    "line": line})
    return out


def show(decl: dict, item: str | None, items: list[dict], records: list[dict], logs: list[dict] | None) -> None:
    print(f"run {decl['run_id']}  unit {decl['unit']}  track {decl['track']}  team {decl.get('team_code')}")
    print(f"target  {decl['target']['metric']} {decl['target']['op']} {decl['target']['value']}")
    print(f"test set {decl['test_set_sha256']}  model {decl['model_id']}")
    print(f"grader  {decl['grader']}")
    if item:
        mine = [i for i in items if i["item"] == item]
        if not mine:
            print(f"\n{item} is not in this run (declared items: {len(decl['items'])})")
        for it in mine:
            print(f"\nitem {item}  trace {it.get('trace_id')}  expect {it.get('expect')}  observed "
                  f"{it.get('observed') or it.get('verdict')}  sent {it.get('sent_at')}  replied {it.get('replied_at')}")
            hops = [r for r in records if r.get("item") == item and
                    (not it.get("trace_id") or r["record"].get("trace_id") in (it.get("trace_id"), None))]
            lt = {x["rec_id"]: x["timestamp"] for x in (logs or [])}
            for r in sorted(hops, key=lambda r: r["sk"]):
                facts = {k: v for k, v in r["record"].items() if k not in ("trace_id",)}
                print(f"  {r['ts']}  {r['source']:11} {r['kind']:20} cloudwatch {lt.get(r['rec_id'], '-'):24} "
                      f"{json.dumps(facts, sort_keys=True)[:150]}")


def main():   # pragma: no cover - needs AWS
    import boto3
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-id")
    ap.add_argument("--item")
    ap.add_argument("--from", dest="start")
    ap.add_argument("--to", dest="end")
    ap.add_argument("--profile")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--judging", default=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                                      "judging.json"))
    a = ap.parse_args()
    j = json.load(open(a.judging))
    if a.list or not a.run_id:
        for rid in j["run_ids"]:
            r = j["reported_results"].get(rid, {})
            print(f"{rid:40} {r.get('unit', ''):12} {r.get('value')}  {'PASS' if r.get('pass') else 'FAIL'}")
        return
    ev = j["evidence"]
    s = boto3.session.Session(profile_name=a.profile, region_name=ev["region"])
    s3, ddb, logs = s.client("s3"), s.client("dynamodb"), s.client("logs")
    print(f"read-only, account {s.client('sts').get_caller_identity()['Account']}, {ev['region']}\n")
    key = f"evidence/declared/{a.run_id}.json"
    d = s3.get_object(Bucket=ev["bucket"], Key=key)
    decl, declared_t = json.loads(d["Body"].read()), d["LastModified"].timestamp()
    print(f"declaration s3://{ev['bucket']}/{key}  stored by S3 at {d['LastModified'].isoformat()}")
    f = s3.get_object(Bucket=ev["bucket"], Key=f"evidence/runs/{a.run_id}/items.jsonl")
    items = [json.loads(x) for x in f["Body"].read().decode().splitlines() if x.strip()]
    lo, hi = window_keys(a.start, a.end)      # the window limits what is shown; the checks use the whole run
    records, kw = [], {"TableName": ev["dynamodb_table"], "KeyConditionExpression": "run_id = :r",
                       "ExpressionAttributeValues": {":r": {"S": a.run_id}}}
    while True:
        r = ddb.query(**kw)
        records += [plain(i) for i in r.get("Items", [])]
        if "LastEvaluatedKey" not in r:
            break
        kw["ExclusiveStartKey"] = r["LastEvaluatedKey"]
    t_lo = int(E.epoch(min(r["ts"] for r in records))) - 60 if records else int(declared_t)
    t_hi = int(E.epoch(max(r["ts"] for r in records))) + 60 if records else int(time.time())
    qid = logs.start_query(logGroupNames=ev["log_groups"], startTime=t_lo, endTime=t_hi,
                           queryString=logs_query(a.run_id, None))["queryId"]
    while True:
        res = logs.get_query_results(queryId=qid)
        if res["status"] in ("Complete", "Failed", "Cancelled", "Timeout"):
            break
        time.sleep(1)
    lines = parse_log_rows(res.get("results", []))
    print(f"dynamodb {ev['dynamodb_table']}: {len(records)} records; cloudwatch: {len(lines)} lines "
          f"(Logs Insights {res['status']})")
    shown = [r for r in records if lo <= r["sk"] <= hi]
    if a.start or a.end:
        print(f"window {lo} .. {hi[:-1]}: {len(shown)} of {len(records)} records")
    show(decl, a.item, [i for i in items if lo <= (i.get("sent_at") or lo) <= hi], shown, lines)
    out = E.check(decl, items, records, declared_t, logs=lines, files_time=f["LastModified"].timestamp())
    print()
    for c in out["checks"]:
        print(f"{'PASS' if c['ok'] else 'FAIL'}  {c['check']}  ({c['detail']})")
    print(f"\n{decl['unit']}: {'PASS' if out['pass'] else 'FAIL'}  measured {out['value']:.4g}")
    raise SystemExit(0 if out["pass"] else 1)


if __name__ == "__main__":
    main()
