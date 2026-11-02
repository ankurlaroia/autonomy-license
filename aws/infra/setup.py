"""Create the AWS resources whose APIs are stable and well known: the KMS issuer key and the
DynamoDB tables. AgentCore Gateway / Policy / interceptor wiring is done by aws/infra/deploy.py,
because the control-plane request shapes were confirmed against the live service, not guessed here.

  python -m aws.infra.setup --region us-west-2 --prefix al        # dry run
  python -m aws.infra.setup --region us-west-2 --prefix al --apply
"""
from __future__ import annotations

import argparse
import json

TABLES = {
    "licences": "jti", "warnings": "nonce", "approvals": "approval_id", "audit": "seq_id",
    "cells": "cell_key", "scores": "incident_id",
}


def main():   # pragma: no cover - needs AWS
    ap = argparse.ArgumentParser()
    ap.add_argument("--region", required=True)
    ap.add_argument("--prefix", default="al")
    ap.add_argument("--apply", action="store_true")
    a = ap.parse_args()
    plan = {"kms": {"KeySpec": "ECC_NIST_P256", "KeyUsage": "SIGN_VERIFY",
                    "Description": "Autonomy License issuer (ES256)"},
            "dynamodb": {f"{a.prefix}-{t}": pk for t, pk in TABLES.items()}}
    print(json.dumps(plan, indent=1))
    if not a.apply:
        print("dry run; add --apply to create")
        return
    import boto3
    kms = boto3.client("kms", region_name=a.region)
    key = kms.create_key(**plan["kms"])["KeyMetadata"]["KeyId"]
    kms.create_alias(AliasName=f"alias/{a.prefix}-licence-issuer", TargetKeyId=key)
    print("KMS key", key)
    ddb = boto3.client("dynamodb", region_name=a.region)
    for name, pk in plan["dynamodb"].items():
        ddb.create_table(TableName=name, BillingMode="PAY_PER_REQUEST",
                         AttributeDefinitions=[{"AttributeName": pk, "AttributeType": "S"}],
                         KeySchema=[{"AttributeName": pk, "KeyType": "HASH"}])
        print("table", name)


if __name__ == "__main__":
    main()
