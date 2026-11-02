"""Path B identity on AWS: Cognito token -> interceptor re-verifies it -> HMAC attestation -> tool Lambda.
Every break in that chain (no token, forged/expired/re-used attestation, agent-supplied caller) leaves
the role unknown, so Path B refuses remediation (fail closed)."""
import json
import time
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from aws import caller as C
from aws import lambda_bootstrap as B
from aws.infra import stub_bundle
from aws.interceptor import handler as I
from common.catalogue import CATALOGUE
from model.scorer import ScoreCache

KEY = b"k" * 32
ISS = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TEST"


# ---------------------------------------------------------------- attestation unit checks
def test_attestation_round_trip_and_binding():
    t = C.attest(KEY, "netops-agent", "apply_remediation", "INC-1", now=1000)
    assert C.verify(KEY, t, "apply_remediation", "INC-1", now=1000) == "netops-agent"
    assert C.verify(KEY, t, "apply_remediation", "INC-2", now=1000) is None        # other incident
    assert C.verify(KEY, t, "request_human_approval", "INC-1", now=1000) is None   # other tool
    assert C.verify(KEY, t, "apply_remediation", "INC-1", now=1000 + C.TTL_S + 1) is None   # expired
    assert C.verify(b"other" * 8, t, "apply_remediation", "INC-1", now=1000) is None      # wrong key
    assert C.verify(b"", t, "apply_remediation", "INC-1", now=1000) is None               # no key: closed


def test_forged_role_swap_fails():
    t = C.attest(KEY, "noc-engineer", "apply_remediation", "INC-1", now=1000)
    forged = "netops-agent" + t[len("noc-engineer"):]
    assert C.verify(KEY, forged, "apply_remediation", "INC-1", now=1000) is None
    assert C.verify(KEY, "netops-agent", "apply_remediation", "INC-1", now=1000) is None


# ---------------------------------------------------------------- token re-verification in the interceptor
@pytest.fixture(scope="module")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def token(key, **over):
    claims = {"iss": ISS, "token_use": "access", "client_id": "agent-client", "role": "netops-agent",
              "exp": int(time.time()) + 300, **over}
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": "k1"})


@pytest.fixture
def jwks(rsa_key, monkeypatch):
    class Fake:
        def get_signing_key_from_jwt(self, _):
            return SimpleNamespace(key=rsa_key.public_key())
    monkeypatch.setattr(I, "_jwks", lambda url: Fake())
    return {"AL_JWKS_URL": "https://example/jwks", "AL_JWT_ISSUER": ISS, "AL_ALLOWED_CLIENTS": "agent-client,eng-client"}


def test_role_from_valid_token(rsa_key, jwks):
    assert I.caller_role_from_headers({"Authorization": f"Bearer {token(rsa_key)}"}, jwks) == "netops-agent"


@pytest.mark.parametrize("over", [{"iss": "https://evil"}, {"token_use": "id"}, {"client_id": "other"},
                                  {"role": "admin"}, {"exp": 1}])
def test_bad_token_gives_no_role(rsa_key, jwks, over):
    assert I.caller_role_from_headers({"authorization": f"Bearer {token(rsa_key, **over)}"}, jwks) is None


def test_token_signed_by_another_key_gives_no_role(jwks):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert I.caller_role_from_headers({"Authorization": f"Bearer {token(other)}"}, jwks) is None


def test_no_header_or_no_jwks_gives_no_role(rsa_key, jwks):
    assert I.caller_role_from_headers({}, jwks) is None
    assert I.caller_role_from_headers({"Authorization": f"Bearer {token(rsa_key)}"}, {}) is None


# ---------------------------------------------------------------- full chain on the stub bundle
@pytest.fixture(scope="module")
def bundle(tmp_path_factory):
    out = tmp_path_factory.mktemp("bundle")
    return out, stub_bundle.build(str(out))


@pytest.fixture
def lambdas(bundle, tmp_path, monkeypatch):
    out, _ = bundle
    env = json.load(open(out / "lambda_env.json"))
    env.update(AL_DATA_DIR=str(out / "data"), AL_DB_SEED=str(out / "al.db"), AL_DB=str(tmp_path / "al.db"),
               AL_LOG_EVENT_SHAPE="0", AL_CALLER_KEY=KEY.decode())
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("AL_ROLE_CONTEXT_KEY", raising=False)
    B.trusted_from_env.cache_clear()
    from aws.tool_lambda import handler as T
    yield T.lambda_handler
    B.trusted_from_env.cache_clear()


def licensed_incident(out, threshold):
    scores = ScoreCache(str(out / "data" / "scores.jsonl"))
    for line in open(out / "data" / "incidents.jsonl"):
        inc = json.loads(line)
        s = scores.get(inc["incident_id"])
        if s["score"] >= threshold and CATALOGUE[s["pred"]]["cls"] == "AUTO" and len(inc["cells"]) >= 2:
            return inc, CATALOGUE[s["pred"]]["action"]
    pytest.skip("no licensed stub incident")


def through_gateway(tool_lambda, args, role, tool="apply_remediation"):
    """Interceptor (as the Gateway runs it) then the tool Lambda with the rewritten arguments."""
    ev = {"interceptorInputVersion": "1.0",
          "mcp": {"gatewayRequest": {"headers": {}, "body": {
              "jsonrpc": "2.0", "id": 1, "method": "tools/call",
              "params": {"name": f"NetOps___{tool}", "arguments": args}}}}}
    out = I.lambda_handler(ev, None, role_from_headers=lambda h: role)
    fwd = out["mcp"]["transformedGatewayRequest"]["body"]["params"]["arguments"]
    ctx = SimpleNamespace(client_context=SimpleNamespace(custom={"bedrockAgentCoreToolName": f"NetOps___{tool}"}))
    return fwd, tool_lambda(fwd, ctx)


def test_attested_agent_is_allowed_on_two_cells(bundle, lambdas):
    out, info = bundle
    inc, action = licensed_incident(out, info["threshold"])
    args = {"incident_id": inc["incident_id"], "action": action, "mode": "autonomous",
            "cells": [c["cell_id"] for c in inc["cells"]][:2]}
    fwd, r = through_gateway(lambdas, args, "netops-agent")
    assert fwd["cell_count"] == 2 and fwd["caller"].startswith("netops-agent.")
    assert r["ok"], r


def test_no_verified_token_means_refused(bundle, lambdas):
    out, info = bundle
    inc, action = licensed_incident(out, info["threshold"])
    args = {"incident_id": inc["incident_id"], "action": action, "mode": "autonomous",
            "cells": [c["cell_id"] for c in inc["cells"]][:2]}
    fwd, r = through_gateway(lambdas, args, None)
    assert "caller" not in fwd and not r["ok"] and "agent role" in r["error"]


def test_agent_supplied_caller_is_stripped(bundle, lambdas):
    out, info = bundle
    inc, action = licensed_incident(out, info["threshold"])
    forged = C.attest(b"guess" * 8, "netops-agent", "apply_remediation", inc["incident_id"])
    args = {"incident_id": inc["incident_id"], "action": action, "mode": "autonomous",
            "cells": [c["cell_id"] for c in inc["cells"]][:2], "caller": forged}
    fwd, r = through_gateway(lambdas, args, None)
    assert "caller" not in fwd and not r["ok"]


def test_direct_call_with_forged_caller_is_refused(bundle, lambdas):
    out, info = bundle
    inc, action = licensed_incident(out, info["threshold"])
    forged = C.attest(b"guess" * 8, "netops-agent", "apply_remediation", inc["incident_id"])
    ctx = SimpleNamespace(client_context=SimpleNamespace(custom={"bedrockAgentCoreToolName": "NetOps___apply_remediation"}))
    r = lambdas({"incident_id": inc["incident_id"], "action": action, "mode": "autonomous",
                 "cells": [c["cell_id"] for c in inc["cells"]][:2], "caller": forged}, ctx)
    assert not r["ok"] and "agent role" in r["error"]


def test_tools_list_passes_through_untouched(lambdas):
    body = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
    out = I.lambda_handler({"mcp": {"gatewayRequest": {"body": body}}}, None, role_from_headers=lambda h: None)
    assert out["mcp"]["transformedGatewayRequest"]["body"] == body
