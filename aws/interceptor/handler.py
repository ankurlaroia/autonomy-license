"""Gateway request interceptor (Path C, spec 10.3 v1.2.1).

Runs on every request before Cedar. For apply_remediation it:
  1. drops agent-supplied trust fields (licence_valid, score, score_ok, licence_ok, category, cell_count);
  2. OVERWRITES cell_count = len(unique(cells)) and category = server-computed k1-k4 category;
  3. sets score_ok from the trusted score cache and licence_ok by re-verifying the licence against
     the live registry (status, fingerprint, operator, category, action, warnings).
Cedar then decides on these server-computed values.

`intercept()` is the tested core. `lambda_handler()` adapts the AgentCore interceptor event (shape from
the AgentCore interceptor docs; S3 still confirms it live) and adds the caller attestation (aws/caller.py).
"""
from __future__ import annotations

from license.verifier import verify_licence

AGENT_TRUST_FIELDS = ("licence_valid", "license_valid", "score", "score_ok", "licence_ok", "category",
                      "cell_count", "threshold", "caller")
ATTESTED_TOOLS = ("apply_remediation", "request_human_approval")


def _untrusted(k: str) -> bool:
    return k in AGENT_TRUST_FIELDS or k.startswith("_")   # "_" keys (e.g. _caller_role) are never accepted


def intercept(tool: str, args: dict, principal: dict, trusted, operator: str = "A") -> dict:
    a = {k: v for k, v in args.items() if not _untrusted(k)}
    notes = [k for k in args if _untrusted(k)]
    if tool != "apply_remediation":
        return {"input": a, "notes": notes}
    iid = a.get("incident_id")
    if iid not in trusted.incidents:
        return {"input": {**a, "cell_count": 0, "category": "none", "score_ok": False, "licence_ok": False},
                "notes": notes + ["unknown incident"]}
    cells = sorted(set(a.get("cells", [])))
    a["cells"] = cells
    a["cell_count"] = len(cells)
    a["category"] = trusted.category(iid)
    sc = trusted.score(iid)
    a["licence_ok"], a["score_ok"] = False, False
    if a.get("mode") == "autonomous":
        try:
            tok = trusted.registry.current()
            if tok is None:
                raise PermissionError("no licence")
            claims = verify_licence(tok[1], trusted.issuer_public_key, issuer=trusted.issuer,
                                    audience=trusted.audience, expected_fingerprint=trusted.expected_fingerprint,
                                    status_lookup=trusted.registry.status, operator=operator,
                                    requested_category=a["category"], requested_action=a.get("action"),
                                    warned_categories=trusted.registry.warned_categories(operator))
            a["licence_ok"] = True
            a["score_ok"] = bool(sc["score"] >= claims["risk"]["threshold"])
        except Exception as e:      # fail closed: Cedar default-denies autonomous calls
            notes.append(f"licence check failed: {e}")
    return {"input": a, "notes": notes}


def _header(headers: dict, name: str):
    return next((v for k, v in (headers or {}).items() if k.lower() == name), None)


def caller_role_from_headers(headers: dict, env=None) -> str | None:
    """Re-verify the caller's Cognito access token (the Gateway already did) and return its role.
    None when the header, the key set or any check is missing or fails (fail closed)."""
    import os
    import jwt
    from aws.caller import role_from_claims
    env = os.environ if env is None else env
    auth = _header(headers, "authorization") or ""
    if not auth.lower().startswith("bearer ") or not env.get("AL_JWKS_URL"):
        return None
    token = auth.split(" ", 1)[1]
    try:
        key = _jwks(env["AL_JWKS_URL"]).get_signing_key_from_jwt(token).key
        claims = jwt.decode(token, key, algorithms=["RS256"], options={"verify_aud": False})
    except Exception:
        return None
    clients = {c for c in env.get("AL_ALLOWED_CLIENTS", "").split(",") if c}
    return role_from_claims(claims, env.get("AL_JWT_ISSUER", ""), clients)


_JWKS = {}


def _jwks(url: str):
    import jwt
    if url not in _JWKS:
        _JWKS[url] = jwt.PyJWKClient(url, cache_keys=True)
    return _JWKS[url]


TRACE_FIELDS = ("mode", "action", "cells", "cell_count", "category", "score_ok", "licence_ok")


def lambda_handler(event, context, role_from_headers=None, writer=None):
    """REQUEST interceptor. Event (AgentCore docs): event["mcp"]["gatewayRequest"] holds the parsed JSON-RPC
    `body` and, with passRequestHeaders=true, the request `headers`. Returns the rewritten body under
    mcp.transformedGatewayRequest."""
    import os
    from aws.audit import writer_from_env
    from aws.caller import attest
    from aws.lambda_bootstrap import log_shape, trusted_from_env
    log_shape("interceptor", event, context)
    try:
        req = event["mcp"]["gatewayRequest"]
        body = req["body"]
    except (KeyError, TypeError):
        # Fail closed: never forward unenriched arguments. Even if the Gateway forwarded the call anyway,
        # Cedar F1m refuses apply_remediation without cell_count and Path B re-checks everything.
        raise RuntimeError("interceptor: mcp.gatewayRequest.body not found in event; check the logged shape")
    if body.get("method") != "tools/call":
        return {"interceptorOutputVersion": "1.0", "mcp": {"transformedGatewayRequest": {"body": body}}}
    trusted = trusted_from_env()
    params = dict(body.get("params", {}))
    tool = params.get("name", "").split("___")[-1]
    out = intercept(tool, params.get("arguments", {}) or {}, {}, trusted, os.environ.get("OPERATOR", "A"))
    args = out["input"]
    key = os.environ.get("AL_CALLER_KEY", "").encode()
    role = (role_from_headers or caller_role_from_headers)(req.get("headers") or {})
    args["trace_id"] = str(body.get("id"))      # the server's trace id; whatever the agent sent is replaced
    w = writer if writer is not None else writer_from_env("interceptor")
    if w:   # the first hop of the trace; a failed write raises, so the call never reaches Cedar unrecorded
        w.write("gateway_request", {"trace_id": args["trace_id"], "tool": tool, "role": role,
                                    **{k: args.get(k) for k in TRACE_FIELDS}, "dropped": out["notes"]},
                args.get("incident_id") if isinstance(args.get("incident_id"), str) else None)
    if tool in ATTESTED_TOOLS and role and key and isinstance(args.get("incident_id"), str):
        args["caller"] = attest(key, role, tool, args["incident_id"])
    params["arguments"] = args
    return {"interceptorOutputVersion": "1.0",
            "mcp": {"transformedGatewayRequest": {"body": {**body, "params": params}}}}
