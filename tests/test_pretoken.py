"""Path A on AWS: the Cognito V3_0 pre-token Lambda takes the role from the app client id only,
adds string licence tags for the agent, and fails closed for unknown clients or a revoked licence."""
import json

import pytest

from aws import lambda_bootstrap as B
from aws.infra import stub_bundle
from aws.pretoken import handler as H

CLIENTS = {"agent-client": "netops-agent", "eng-client": "noc-engineer"}


@pytest.fixture(scope="module")
def bundle(tmp_path_factory):
    out = tmp_path_factory.mktemp("bundle")
    return out, stub_bundle.build(str(out))


@pytest.fixture
def env(bundle, tmp_path, monkeypatch):
    out, _ = bundle
    e = json.load(open(out / "lambda_env.json"))
    e.update(AL_DATA_DIR=str(out / "data"), AL_DB_SEED=str(out / "al.db"), AL_DB=str(tmp_path / "al.db"),
             AL_LOG_EVENT_SHAPE="0", AL_CLIENT_ROLES=json.dumps(CLIENTS))
    for k, v in e.items():
        monkeypatch.setenv(k, v)
    B.trusted_from_env.cache_clear()
    yield
    B.trusted_from_env.cache_clear()


def event(client_id, role_claim=None):
    ev = {"version": "3", "triggerSource": "TokenGeneration_ClientCredentials",
          "callerContext": {"clientId": client_id}, "request": {"scopes": ["netops/invoke"]}, "response": {}}
    if role_claim:
        ev["request"]["clientMetadata"] = {"role": role_claim}       # caller-supplied: must be ignored
    return ev


def claims(ev):
    return H.lambda_handler(ev, None)["response"]["claimsAndScopeOverrideDetails"][
        "accessTokenGeneration"]["claimsToAddOrOverride"]


def test_agent_gets_active_licence_tags_as_strings(env):
    c = claims(event("agent-client"))
    assert c["role"] == "netops-agent" and c["lic_state"] == "active"
    assert c["lic_cats"].startswith("|") and c["lic_cats"].endswith("|") and c["warned"] == "||"
    assert all(isinstance(v, str) for v in c.values())


def test_engineer_gets_no_licence(env):
    c = claims(event("eng-client"))
    assert c["role"] == "noc-engineer" and c["lic_state"] == "none"


def test_role_comes_from_client_not_request(env):
    c = claims(event("eng-client", role_claim="netops-agent"))
    assert c["role"] == "noc-engineer" and c["lic_state"] == "none"


def test_unknown_client_gets_no_token(env):
    with pytest.raises(PermissionError):
        H.lambda_handler(event("someone-else"), None)


def test_no_client_roles_configured_fails_closed(env, monkeypatch):
    monkeypatch.delenv("AL_CLIENT_ROLES")
    with pytest.raises(PermissionError):
        H.lambda_handler(event("agent-client"), None)


def test_revoked_licence_gives_no_autonomy_tags(env):
    t = B.trusted_from_env()
    jti, _ = t.registry.current()
    t.registry.set_status(jti, "revoked", "test")
    c = claims(event("agent-client"))
    assert c["lic_state"] == "none" and "lic_error" in c
