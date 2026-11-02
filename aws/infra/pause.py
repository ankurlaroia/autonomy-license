"""Pause or resume the deployed stack without deleting anything.

    python -m aws.infra.pause pause     # every Lambda throttled to 0: the Gateway can run nothing, so nothing bills
    python -m aws.infra.pause resume    # back to normal
    python -m aws.infra.pause status

Everything else in the stack is pay-per-request (AgentCore Gateway, DynamoDB on-demand, Cognito, Lambda), so a
paused stack has no request charges. What still bills while paused: the KMS signing key (about $1/month, even
when disabled; only deletion stops it) and a few MB in S3 and CloudWatch Logs.
"""
from __future__ import annotations

import argparse

import boto3

FUNCTIONS = ("al-netops-pretoken", "al-netops-tools", "al-netops-interceptor")


def pause(lam, functions=FUNCTIONS):
    for f in functions:
        lam.put_function_concurrency(FunctionName=f, ReservedConcurrentExecutions=0)


def resume(lam, functions=FUNCTIONS):
    for f in functions:
        lam.delete_function_concurrency(FunctionName=f)


def status(lam, functions=FUNCTIONS) -> dict:
    """"paused" only when a function is throttled to exactly 0."""
    return {f: "paused" if lam.get_function_concurrency(FunctionName=f).get("ReservedConcurrentExecutions") == 0
            else "running" for f in functions}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("op", choices=["pause", "resume", "status"])
    ap.add_argument("--region", help="default: the profile's region, else us-east-2")
    ap.add_argument("--profile")
    a = ap.parse_args()
    s = boto3.session.Session(profile_name=a.profile, region_name=a.region)
    lam = s.client("lambda", region_name=s.region_name or "us-east-2")
    if a.op == "pause":
        pause(lam)
    elif a.op == "resume":
        resume(lam)
    for f, st in status(lam).items():
        print(f"{f}: {st}")


if __name__ == "__main__":
    main()
