"""Declared runs for judging: each unit gets one run id, a declaration in the bucket BEFORE it starts, live calls
through the deployed Gateway carrying that id, and its outputs and records written back under the same id.

    python -m aws.infra.judged_run --profile fyuz --team-code <code>                  # all units, in order
    python -m aws.infra.judged_run --profile fyuz --team-code <code> --units allow,deny

Units (aws/evidence.py): licence (calibrate on the frozen split, KMS-sign, deploy with ENFORCE), allow, deny,
adversarial, trace, pause (withdraws the licence, so it runs last; run `licence` again for a new one).

Bucket: the team data bucket (*-data-<account>-use2) when it exists, else al-evidence-<account>-<region> with
versioning. Layout (guide): evidence/declared/<run_id>.json, evidence/runs/<run_id>/{items.jsonl, records.jsonl,
record.json}, judging/judging.json; the same files are mirrored to evidence/ and judging.json in this repository.

The Lambdas learn the run id from their environment (AL_RUN_ID), set here after the declaration is stored and
reset to "undeclared" at the end. Tokens and secrets are never written; records hold ids, decisions and times.
Cost: pay-per-request calls (cents) plus, for `licence`, one KMS signature and a Lambda deploy.
"""
from __future__ import annotations

import argparse
import json
import os
import time

from aws import evidence as E
from aws.audit import UNDECLARED, iso_ms, plain

FUNCTIONS = ("al-netops-interceptor", "al-netops-tools")
LOG_GROUPS = tuple(f"/aws/lambda/{f}" for f in FUNCTIONS)
AUDIT_TABLE = "al-audit"


def find_bucket(s3, account: str, region: str, create: bool = True) -> str:
    names = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
    team = [n for n in names if n.endswith(f"-data-{account}-use2")]
    if team:
        return team[0]
    name = f"al-evidence-{account}-{region}"
    if name not in names and create:   # pragma: no cover - needs AWS
        kw = {} if region == "us-east-1" else {"CreateBucketConfiguration": {"LocationConstraint": region}}
        s3.create_bucket(Bucket=name, **kw)
        s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
        s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    return name


def judging_doc(team_code: str, bucket: str, account: str, region: str, runs: list[dict]) -> dict:
    """judging.json (guide, "Submission and judging"), newest 20 runs."""
    runs = runs[-20:]
    return {"primary_track": E.TRACK, "team_code": team_code,
            "evidence": {"bucket": bucket, "prefix": "evidence/", "account": account, "region": region,
                         "dynamodb_table": AUDIT_TABLE, "log_groups": list(LOG_GROUPS)},
            "run_ids": [r["run_id"] for r in runs],
            "live_test_command": "python tools/show_record.py --run-id {run_id} --item {item}",
            "live_test_window": "python tools/show_record.py --run-id {run_id} --item {item} --from {start} --to {end}",
            "rebuild_command": "python tools/rebuild.py",
            "reported_results": {r["run_id"]: {"unit": r["unit"], "metric": r["metric"], "value": r["value"],
                                               "target": r["target"], "pass": r["pass"]} for r in runs},
            "data": "DATA.md", "gaps": "GAPS.md"}


class Run:   # pragma: no cover - needs AWS
    def __init__(self, profile, region, team_code, bundle, data):
        import boto3
        self.s = boto3.session.Session(profile_name=profile, region_name=region)
        self.region = self.s.region_name or "us-east-2"
        self.s = boto3.session.Session(profile_name=profile, region_name=self.region)
        self.profile, self.team, self.bundle, self.data = profile, team_code, bundle, data
        self.account = self.s.client("sts").get_caller_identity()["Account"]
        self.s3, self.ddb, self.lam = self.s.client("s3"), self.s.client("dynamodb"), self.s.client("lambda")
        self.bucket = find_bucket(self.s3, self.account, self.region)
        st = os.path.join("dist", "aws_state.json")
        self.state = json.load(open(st)) if os.path.exists(st) else {}
        if self.state and (self.state.get("account"), self.state.get("region")) != (self.account, self.region):
            aside = os.path.join("dist", f"aws_state.{self.state.get('account')}.{self.state.get('region')}.json")
            os.replace(st, aside)       # another account's stack: keep its ids, never reuse them here
            print(f"moved the other stack's state to {aside}")
            self.state = {}
        print(f"account {self.account} {self.region}, bucket {self.bucket}")

    def ensure_kms_key(self, alias: str):
        """The licence signing key (ES256, never leaves KMS). About $1/month while it exists."""
        kms = self.s.client("kms")
        try:
            kms.describe_key(KeyId=alias)
        except kms.exceptions.NotFoundException:
            key = kms.create_key(KeySpec="ECC_NIST_P256", KeyUsage="SIGN_VERIFY",
                                 Description="Autonomy License issuer (ES256)")["KeyMetadata"]["KeyId"]
            kms.create_alias(AliasName=alias, TargetKeyId=key)
            print(f"created KMS key {alias}")

    # ---- storage
    def put(self, key: str, body: bytes, local: str | None = None) -> float:
        self.s3.put_object(Bucket=self.bucket, Key=key, Body=body, ServerSideEncryption="AES256",
                           ContentType="application/json")
        if local:
            os.makedirs(os.path.dirname(local), exist_ok=True)
            open(local, "wb").write(body)
        return self.s3.head_object(Bucket=self.bucket, Key=key)["LastModified"].timestamp()

    def declare(self, decl: dict) -> float:
        rid = decl["run_id"]
        t = self.put(f"evidence/declared/{rid}.json", json.dumps(decl, indent=1).encode(),
                     os.path.join("evidence", "declared", f"{rid}.json"))
        print(f"\n== {decl['unit']}: declared {rid} ({len(decl['items'])} items, target "
              f"{decl['target']['metric']} {decl['target']['op']} {decl['target']['value']})")
        return t

    def records(self, rid: str) -> list[dict]:
        out, kw = [], {"TableName": AUDIT_TABLE, "KeyConditionExpression": "run_id = :r",
                       "ExpressionAttributeValues": {":r": {"S": rid}}, "ConsistentRead": True}
        while True:
            r = self.ddb.query(**kw)
            out += [plain(i) for i in r.get("Items", [])]
            if "LastEvaluatedKey" not in r:
                return out
            kw["ExclusiveStartKey"] = r["LastEvaluatedKey"]

    def driver_record(self, rid: str, kind: str, record: dict, item=None):
        from aws.audit import AuditWriter
        AuditWriter(self.ddb, AUDIT_TABLE, rid, "driver", out=lambda _: None).write(kind, record, item)

    def bind(self, rid: str):
        """Point both Lambdas at this run id (they read it from their environment)."""
        for f in FUNCTIONS:
            env = self.lam.get_function_configuration(FunctionName=f)["Environment"]["Variables"]
            if env.get("AL_RUN_ID") == rid:
                continue
            env["AL_RUN_ID"] = rid
            self.lam.update_function_configuration(FunctionName=f, Environment={"Variables": env})
            self.lam.get_waiter("function_updated_v2").wait(FunctionName=f)

    def finish(self, decl, declared_t, items, extra=None) -> dict:
        rid = decl["run_id"]
        time.sleep(3)
        recs = self.records(rid)
        base = f"evidence/runs/{rid}"
        local = os.path.join("evidence", "runs", rid)
        ib, rb = E.jsonl(items), E.jsonl(recs)
        files_t = self.put(f"{base}/items.jsonl", ib, os.path.join(local, "items.jsonl"))
        self.put(f"{base}/records.jsonl", rb, os.path.join(local, "records.jsonl"))
        res = E.check(decl, items, recs, declared_t, files_time=files_t)
        record = {"run_id": rid, "unit": decl["unit"], "declaration_last_modified": declared_t,
                  "items_last_modified": files_t, "items_sha256": E.sha256_bytes(ib),
                  "records_sha256": E.sha256_bytes(rb), "result": res, **(extra or {})}
        self.put(f"{base}/record.json", json.dumps(record, indent=1, default=str).encode(),
                 os.path.join(local, "record.json"))
        for c in res["checks"]:
            print(f"  {'PASS' if c['ok'] else 'FAIL'}  {c['check']}  ({c['detail']})")
        print(f"  {decl['unit']}: {'PASS' if res['pass'] else 'FAIL'}  value {res['value']:.4g}")
        return {"run_id": rid, "unit": decl["unit"], "metric": decl["target"]["metric"], "value": res["value"],
                "target": decl["target"], "pass": res["pass"]}

    # ---- context shared by declarations
    def context(self, info: dict) -> dict:
        zipf = os.path.join("dist", "netops_lambda.zip")
        return {"account": self.account, "region": self.region, "gateway": self.state.get("gateway_url"),
                "policy_mode": self.state.get("policy_mode"),
                "licence": {k: info.get(k) for k in ("licence_jti", "threshold", "upper_bound", "signer")},
                "code_sha256": E.sha256_file(zipf) if os.path.exists(zipf) else None,
                "records": {"dynamodb_table": AUDIT_TABLE, "log_groups": list(LOG_GROUPS),
                            "bucket": self.bucket, "prefix": "evidence/"}}

    def hashes(self) -> dict:
        h = json.load(open(os.path.join(self.data, "split_hashes.json")))
        prereg = os.path.join(self.data, "PREREG.yaml")
        return {**h, "prereg_sha256": E.sha256_file(prereg)}

    # ---- units
    def unit_licence(self, kms_key: str):
        import yaml

        from aws.infra import deploy as D
        from aws.infra import package, stub_bundle
        from model.scorer import ScoreCache
        h = self.hashes()
        pre = yaml.safe_load(open(os.path.join(self.data, "PREREG.yaml")))
        splits = json.load(open(os.path.join(self.data, "splits.json")))
        scores = ScoreCache(os.path.join(self.data, "scores.jsonl"))
        cal_ids = sum((splits["operators"][o] for o in "ABC"), [])
        rid = E.run_id("licence")
        decl = E.declaration("licence", rid, team_code=self.team, test_set_sha256=h["calibration"],
                             model_fingerprint=scores.fingerprint,
                             items=[{"item": i} for i in cal_ids],
                             context={"grid": pre["grid"], "alpha": pre["alpha"], "delta": pre["delta"],
                                      "check_set_sha256": h["heldout"], "prereg_sha256": h["prereg_sha256"],
                                      "split_hashes": {k: h[k] for k in ("pilot", "calibration", "heldout")},
                                      "account": self.account, "region": self.region, "kms_key": kms_key})
        t0 = self.declare(decl)
        sent = iso_ms(time.time())
        self.ensure_kms_key(kms_key)
        info = stub_bundle.build(self.bundle, self.data, kms_key)
        package.build(os.path.join("dist", "netops_lambda.zip"), self.bundle)
        d = D.Deployer(self.region, self.profile, self.bundle, os.path.join("dist", "netops_lambda.zip"))
        d.apply()
        d.attach("ENFORCE")
        d.save()
        self.state = json.load(open(os.path.join("dist", "aws_state.json")))
        items = [{**r, "sent_at": sent, "replied_at": iso_ms(time.time())}
                 for r in E.calibration_items(scores, cal_ids, splits)]
        self.driver_record(rid, "licence_issued", {k: info[k] for k in ("licence_jti", "threshold", "upper_bound",
                                                                        "signer", "fingerprint")})
        return self.finish(decl, t0, items, {"licence": info})

    def gateway_unit(self, unit: str, client, info: dict, used: set):
        from model.scorer import ScoreCache
        if not self.state.get("gateway_url"):
            raise SystemExit("no stack in this account yet: run the licence unit first (it deploys)")
        h = self.hashes()
        inc = {json.loads(x)["incident_id"]: json.loads(x)
               for x in open(os.path.join(self.bundle, "data", "incidents.jsonl"))}
        scores = ScoreCache(os.path.join(self.bundle, "data", "scores.jsonl"))
        order = json.load(open(os.path.join(self.data, "splits.json")))["heldout_order"]
        rid = E.run_id(unit)
        if unit == "adversarial":
            from aws.infra.attacks_live import SPLIT, attacks, pick, split_setup
            picked = pick(self.bundle, info["threshold"])
            plan = [{"item": a["incident_id"], "attack": name, "token": kind, "args": a, "expect": "BLOCKED",
                     **({"setup": split_setup(picked)} if name == SPLIT else {})}
                    for name, kind, a in attacks(picked)]
        else:
            plan = E.gateway_items(unit, inc, scores, order, info["threshold"], n=10 if unit != "trace" else 5,
                                   skip=used)
        used.update(p["item"] for p in plan)
        decl = E.declaration(unit, rid, team_code=self.team, test_set_sha256=h["heldout"],
                             model_fingerprint=scores.fingerprint,
                             items=[{k: v for k, v in p.items() if k != "args"} for p in plan],
                             context=self.context(info))
        t0 = self.declare(decl)
        self.bind(rid)
        if unit == "pause":
            from license.registry_ddb import DynamoRegistry
            reg = DynamoRegistry(self.ddb, "al")
            jti = reg.current()[0]
            reg.set_status(jti, "revoked", f"pause unit {rid}")
            self.driver_record(rid, "licence_withdrawn", {"jti": jti, "status": reg.status(jti)})
            print(f"  licence {jti} withdrawn")
        items = [self.call(client, rid, n, p) for n, p in enumerate(plan, 1)]
        self.bind(UNDECLARED)
        return self.finish(decl, t0, items)

    def call(self, client, rid: str, n: int, p: dict) -> dict:
        from aws.infra.attacks_live import tamper, verdict
        from aws.infra.smoke import outcome
        trace = f"{rid}/{n:03d}"
        if "setup" in p:       # the allowed first part of a split change, under its own trace id
            r = client.call_traced(client.agent, "apply_remediation", p["setup"], f"{trace}s")
            self.driver_record(rid, "driver_setup_call", {"trace_id": f"{trace}s", "cells": p["setup"]["cells"],
                                                          "observed": outcome(r)["decision"]}, p["item"])
        if "attack" in p:
            tok = {"agent": client.agent, "none": "", "tampered": tamper(client.agent)}[p["token"]]
            args = p["args"]
        else:
            tok = client.agent
            args = {"incident_id": p["item"], "action": p["action"], "cells": p["cells"], "mode": "autonomous"}
            if "claimed_cell_count" in p:
                args["cell_count"] = p["claimed_cell_count"]
        sent = time.time()
        reply = client.call_traced(tok, "apply_remediation", args, trace)
        out = {"item": p["item"], "trace_id": trace, "sent_at": iso_ms(sent), "replied_at": iso_ms(time.time()),
               "expect": p["expect"]}
        if "attack" in p:
            v = verdict(reply)
            http = (reply.get("error") or {}).get("http")
            out.update(attack=p["attack"], verdict=v["verdict"], by=v["by"], http=http)
            print(f"  {v['verdict']:12} {p['attack'][:60]:60} {v['by']}")
        else:
            o = outcome(reply)
            out.update(observed=o["decision"], detail=E.item_detail(o))
            print(f"  {o['decision']:16} {p['item']} {len(p['cells'])} cells")
        self.driver_record(rid, "driver_call", {k: out[k] for k in out if k != "detail"}, p["item"])
        return out


class TracedClient:   # pragma: no cover - needs AWS
    """The smoke-test client with the JSON-RPC id set to the trace id (the interceptor records it)."""

    def __init__(self, state, profile):
        from aws.infra.smoke import Client
        self.c = Client(state, profile)
        self.agent = self.c.token("agent_client")
        self.c.rpc(self.agent, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                              "clientInfo": {"name": "al-judged-run", "version": "1"}})

    def call_traced(self, tok, tool, args, trace):
        import urllib.error
        import urllib.request

        from aws.infra.smoke import parse_mcp
        body = {"jsonrpc": "2.0", "id": trace, "method": "tools/call",
                "params": {"name": f"NetOps___{tool}", "arguments": args}}
        req = urllib.request.Request(self.c.st["gateway_url"], data=json.dumps(body).encode(), method="POST",
                                     headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json",
                                              "Accept": "application/json, text/event-stream"})
        try:
            r = urllib.request.urlopen(req, timeout=60)
            return parse_mcp(r.read(), r.headers.get("Content-Type", ""))
        except urllib.error.HTTPError as e:
            return {"error": {"http": e.code, "body": e.read().decode("utf-8", "replace")[:300]}}


def main():   # pragma: no cover - needs AWS
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile")
    ap.add_argument("--region")
    ap.add_argument("--team-code", required=True)
    ap.add_argument("--units", default=",".join(E.ORDER))
    ap.add_argument("--bundle", default="dist/bundle")
    ap.add_argument("--data", default="state/data")
    ap.add_argument("--kms-key", default="alias/al-licence-issuer")
    a = ap.parse_args()
    units = [u for u in a.units.split(",") if u]
    bad = set(units) - set(E.ORDER)
    if bad:
        raise SystemExit(f"unknown units {sorted(bad)}; choose from {E.ORDER}")
    if a.profile:       # the KMS signer and the registry use default sessions: point them at the same account
        os.environ["AWS_PROFILE"] = a.profile
    r = Run(a.profile, a.region, a.team_code, a.bundle, a.data)
    os.environ["AWS_DEFAULT_REGION"] = os.environ["AWS_REGION"] = r.region
    done = json.load(open("judging.json"))["reported_results"] if os.path.exists("judging.json") else {}
    results = [{"run_id": k, **v} for k, v in done.items()]
    if "licence" in units:
        results.append(r.unit_licence(a.kms_key))
    info = json.load(open(os.path.join(a.bundle, "stub_info.json")))
    client = TracedClient(r.state, a.profile) if set(units) - {"licence"} else None
    used = set()
    for u in [u for u in E.ORDER if u in units and u != "licence"]:
        results.append(r.gateway_unit(u, client, info, used))
    doc = judging_doc(a.team_code, r.bucket, r.account, r.region, results)
    body = json.dumps(doc, indent=1).encode()
    open("judging.json", "wb").write(body)
    r.put("judging/judging.json", body)
    print(f"\njudging.json: {len(doc['run_ids'])} run ids; copy in s3://{r.bucket}/judging/judging.json")
    raise SystemExit(0 if all(x["pass"] for x in results[-len(units):]) else 1)


if __name__ == "__main__":
    main()
