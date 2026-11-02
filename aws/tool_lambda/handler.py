"""AgentCore Gateway Lambda target for the three NetOps tools.

Gateway passes the tool name in the Lambda context (client_context.custom['bedrockAgentCoreToolName'],
format '<Target>___<tool>') and the tool arguments as the event. Confirm both in the Sunday smoke
test (S1). The caller identity is NOT trusted from the event: Path B re-verifies everything
against the registries, and the role comes only from the Gateway-controlled Lambda context.

Role source, in order: client_context.custom[AL_ROLE_CONTEXT_KEY] if the Gateway ever forwards identity
there (the documented context does not), else the interceptor's HMAC attestation `caller`
(aws/caller.py, key AL_CALLER_KEY). Otherwise the role is None, so Path B refuses autonomous and
approved remediation (fail closed).
"""
import json
import os

from aws.audit import attach, writer_from_env
from aws.caller import verify
from aws.lambda_bootstrap import log_shape, trusted_from_env
from aws.tool_lambda.tools import NetOpsTools

ROLES = ("netops-agent", "noc-engineer")


def caller_role(context, attestation=None, tool: str = "", incident_id=None):
    """Role from the Gateway-controlled context or a valid interceptor attestation; None otherwise (fail closed)."""
    key = os.environ.get("AL_ROLE_CONTEXT_KEY")
    custom = getattr(getattr(context, "client_context", None), "custom", None) or {}
    role = custom.get(key) if key else None
    if role in ROLES:
        return role
    return verify(os.environ.get("AL_CALLER_KEY", "").encode(), attestation, tool, incident_id)


def lambda_handler(event, context, writer=None):
    log_shape("tool_lambda", event, context)
    tool = context.client_context.custom["bedrockAgentCoreToolName"].split("___")[-1]
    args = {k: v for k, v in event.items() if not k.startswith("_") and k != "caller"}   # never identity
    principal = {"role": caller_role(context, event.get("caller"), tool, args.get("incident_id"))}
    trace = str(args.pop("trace_id", "") or "")
    trusted = trusted_from_env()
    writer = writer or writer_from_env("tool")
    attach(trusted.store, writer, {"trace_id": trace})
    tools = NetOpsTools(trusted, os.environ.get("OPERATOR", "A"))
    try:
        if writer:      # no record, no action: this write comes before anything can change
            writer.write("tool_call", {"trace_id": trace, "tool": tool, "role": principal["role"],
                                       "mode": args.get("mode"),
                                       "action": args.get("action") or args.get("proposed_action"),
                                       "cells": sorted(set(args.get("cells", [])))}, args.get("incident_id"))
        return {"ok": True, "result": tools.dispatch(tool, principal, args)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


if __name__ == "__main__":
    print(json.dumps({"tools": ["get_incident", "apply_remediation", "request_human_approval"]}))
