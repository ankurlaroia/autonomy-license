"""The smoke client must read Gateway replies correctly: a policy deny, a Path B refusal and an ALLOW are
three different outcomes, whether the reply is plain JSON or server-sent events."""
import json

from aws.infra.smoke import outcome, parse_mcp


def test_sse_last_data_line_wins():
    raw = b'event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{"tools":[]}}\n\n'
    assert parse_mcp(raw, "text/event-stream")["result"] == {"tools": []}


def test_plain_json():
    assert parse_mcp(b'{"jsonrpc":"2.0","id":2,"result":{}}', "application/json")["id"] == 2


def test_policy_deny_is_deny():
    r = {"result": {"isError": True, "content": [{"type": "text",
                                                   "text": "AuthorizeActionException - Tool Execution Denied"}]}}
    assert outcome(r)["decision"] == "DENY"


def test_tool_refusal_is_not_an_allow():
    text = json.dumps({"ok": False, "error": "blast radius 5 > 3"})
    r = {"result": {"isError": False, "content": [{"type": "text", "text": text}]}}
    assert outcome(r)["decision"] == "REFUSED_BY_TOOL"


def test_allow():
    text = json.dumps({"ok": True, "result": {"applied": True}})
    assert outcome({"result": {"content": [{"type": "text", "text": text}]}})["decision"] == "ALLOW"


def test_other_errors_are_errors():
    assert outcome({"error": {"code": -32603, "message": "boom"}})["decision"] == "ERROR"
    assert outcome({"result": {"isError": True, "content": [{"type": "text", "text": "timeout"}]}})["decision"] == "ERROR"


def test_live_gateway_policy_deny_is_a_jsonrpc_error():
    """Shape seen from the live Gateway in ENFORCE, 2026-10-31."""
    r = {"error": {"code": -32002, "message": "Tool Execution Denied: Tool call not allowed due to policy "
                                              "enforcement [Policy evaluation denied due to F1-1z0axkyl_0]"}}
    assert outcome(r)["decision"] == "DENY"


def test_evidence_labels_data_source_from_the_bundle():
    from aws.infra.smoke import evidence_header
    st = {"gateway_url": "https://g", "policy_mode": "ENFORCE"}
    real = evidence_header(st, {"data_source": "telelogs", "signer": "kms", "licence_jti": "j", "threshold": 0.9})
    assert real["data_source"] == "telelogs" and real["signer"] == "kms" and real["licence_jti"] == "j"
    assert evidence_header(st, {"threshold": 0.7})["data_source"] == "synthetic (stub licence)"
