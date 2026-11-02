"""The deployed policy text must pass AgentCore-style strict validation, and the tool schemas must
be in the shape CreateGatewayTarget accepts (both checked offline, before any AWS call)."""
from aws.cedar.engine import PolicyEngine
from aws.cedar.gen_policies import policies
from aws.cedar.schema import SCHEMA_KEYS, gateway_tool_schemas, validate

ARN = "arn:aws:bedrock-agentcore:us-east-1:123456789012:gateway/netops-abc"


def test_policies_pass_strict_validation():
    assert validate(ARN) == []


def test_unguarded_optional_read_is_rejected():
    bad = policies(ARN).replace("context.input has cell_count && context.input.cell_count >",
                                "context.input.cell_count >")
    assert any("cell_count" in e for e in validate(text=bad))


def _keys(s):
    yield set(s)
    for v in s.get("properties", {}).values():
        yield from _keys(v)
    if "items" in s:
        yield from _keys(s["items"])


def test_gateway_tool_schemas_only_use_allowed_keys():
    for t in gateway_tool_schemas():
        for ks in _keys(t["inputSchema"]):
            assert ks <= set(SCHEMA_KEYS), (t["name"], ks)
    mode = next(t for t in gateway_tool_schemas() if t["name"] == "apply_remediation")["inputSchema"]["properties"]["mode"]
    assert "enum" not in mode and "autonomous" in mode["description"]


def test_missing_cell_count_is_denied_even_for_licensed_agent():
    agent = {"role": "netops-agent", "lic_state": "active", "lic_cats": "|k1|k2|k3|k4|", "warned": "||"}
    inp = {"incident_id": "INC-1", "mode": "autonomous", "category": "k2", "score_ok": True,
           "licence_ok": True, "action": "adjust_tilt", "cells": ["a", "b"]}
    r = PolicyEngine().evaluate("p", agent, "apply_remediation", inp)
    assert r["decision"] == "DENY" and "F1m" in r["policies"], r


def test_missing_cell_count_is_denied_for_engineer():
    r = PolicyEngine().evaluate("p", {"role": "noc-engineer"}, "apply_remediation",
                                {"incident_id": "INC-1", "mode": "approved", "approval_id": "APR-1",
                                 "action": "adjust_tilt", "cells": ["a"]})
    assert r["decision"] == "DENY" and "F1m" in r["policies"], r
