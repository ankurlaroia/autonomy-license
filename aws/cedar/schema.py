"""Cedar schema for the NetOps gateway, built from the same tool schemas the Gateway target uses.

AgentCore validates policies against the target's tool schemas: a property that is not `required`
is an optional attribute of context.input, so every read of it needs a `has` guard. This module
rebuilds that schema locally so `validate()` catches a policy AgentCore would reject, before deploy.

Gateway tool schemas (SchemaDefinition) allow only type / properties / required / items /
description: `gateway_tool_schemas()` drops anything else (e.g. `enum`) and keeps it in the text.
"""
from __future__ import annotations

import json
import os

import cedarpy

from aws.cedar.gen_policies import TARGET, policies

TOOL_SCHEMAS = os.path.join(os.path.dirname(__file__), "..", "infra", "tool_schemas.json")
SCHEMA_KEYS = ("type", "properties", "required", "items", "description")
_CEDAR = {"string": "String", "integer": "Long", "number": "Long", "boolean": "Boolean"}


def load_tools(path: str = TOOL_SCHEMAS) -> list[dict]:
    return json.load(open(path, encoding="utf-8"))


def _gateway_def(s: dict) -> dict:
    out = {k: v for k, v in s.items() if k in SCHEMA_KEYS}
    if "enum" in s:
        out["description"] = (s.get("description", "") + f" One of: {', '.join(s['enum'])}.").strip()
    if "properties" in out:
        out["properties"] = {k: _gateway_def(v) for k, v in out["properties"].items()}
    if "items" in out:
        out["items"] = _gateway_def(out["items"])
    return out


def gateway_tool_schemas(tools: list[dict] | None = None) -> list[dict]:
    """Tool definitions in the shape CreateGatewayTarget accepts."""
    tools = load_tools() if tools is None else tools
    return [{"name": t["name"], "description": t["description"], "inputSchema": _gateway_def(t["inputSchema"])}
            for t in tools]


def _cedar_type(s: dict, required: bool = True) -> dict:
    t = s["type"]
    if t == "object":
        req = set(s.get("required", []))
        out = {"type": "Record",
               "attributes": {k: _cedar_type(v, k in req) for k, v in s.get("properties", {}).items()}}
    elif t == "array":
        out = {"type": "Set", "element": _cedar_type(s["items"])}
    else:
        out = {"type": _CEDAR[t]}
    if not required:
        out["required"] = False
    return out


def cedar_schema(tools: list[dict] | None = None) -> dict:
    tools = gateway_tool_schemas(tools)
    actions = {f"{TARGET}___{t['name']}": {"appliesTo": {
        "principalTypes": ["OAuthUser"], "resourceTypes": ["Gateway"],
        "context": {"type": "Record", "attributes": {"input": _cedar_type(t["inputSchema"])}}}}
        for t in tools}
    return {"AgentCore": {"entityTypes": {
        "OAuthUser": {"shape": {"type": "Record", "attributes": {}}, "tags": {"type": "String"}},
        "Gateway": {"shape": {"type": "Record", "attributes": {}}}}, "actions": actions}}


def validate(gateway: str = "GW", text: str | None = None) -> list[str]:
    """Validation errors for the policy set (empty list = valid)."""
    r = cedarpy.validate_policies(text if text is not None else policies(gateway), json.dumps(cedar_schema()))
    return [] if r.validation_passed else [str(e) for e in r.errors]
