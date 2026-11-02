"""Every request the deployer sends must be valid for the real AWS API (botocore service models), checked
offline; plus the safety properties of the stack it builds."""
import functools
import json

import boto3
import pytest
from botocore.validate import ParamValidator

from aws.infra import deploy as D

SESSION = boto3.session.Session(region_name="us-east-1")


@functools.lru_cache(maxsize=None)
def model(service):
    return SESSION._session.get_service_model(service)    # no client: offline, never loads credentials


@pytest.mark.parametrize("op,req", D.plan("us-east-1"), ids=lambda x: x if isinstance(x, str) else "")
def test_request_matches_aws_api(op, req):
    service, method = op.split(".")
    m = model(service)
    name = next(o for o in m.operation_names if "".join(method.split("_")).lower() == o.lower())
    report = ParamValidator().validate(req, m.operation_model(name).input_shape)
    assert not report.has_errors(), report.generate_report()


def test_interceptor_gets_headers_so_it_can_verify_the_caller():
    g = D.gateway_request("arn:r", "us-east-1", "us-east-1_P", ["c"], "arn:i")
    ic = g["interceptorConfigurations"][0]
    assert ic["interceptionPoints"] == ["REQUEST"] and ic["inputConfiguration"]["passRequestHeaders"] is True
    assert g["authorizerType"] == "CUSTOM_JWT" and g["authorizerConfiguration"]["customJWTAuthorizer"]["allowedClients"]


def test_gateway_role_can_invoke_only_our_functions_and_evaluate_policy():
    doc = D.gateway_role_policy("1", "us-east-1", ["arn:fn:a", "arn:fn:b"], "arn:engine")
    actions = {a for s in doc["Statement"] for a in ([s["Action"]] if isinstance(s["Action"], str) else s["Action"])}
    assert actions == {"lambda:InvokeFunction", "bedrock-agentcore:GetPolicyEngine",
                       "bedrock-agentcore:AuthorizeAction", "bedrock-agentcore:PartiallyAuthorizeActions"}
    inv = next(s for s in doc["Statement"] if s["Action"] == "lambda:InvokeFunction")
    assert inv["Resource"] == ["arn:fn:a", "arn:fn:b"]


def test_gateway_trust_is_scoped_to_account():
    st = D.gateway_trust("123", "us-east-1")["Statement"][0]
    assert st["Principal"] == {"Service": "bedrock-agentcore.amazonaws.com"}
    assert st["Condition"]["StringEquals"]["aws:SourceAccount"] == "123"


def test_pretoken_trigger_is_v3_for_m2m_tokens():
    r = D.user_pool_request("arn:fn")
    assert r["UserPoolTier"] == "ESSENTIALS"
    assert r["LambdaConfig"]["PreTokenGenerationConfig"]["LambdaVersion"] == "V3_0"


def test_clients_are_m2m_with_short_tokens():
    r = D.client_request("p", "agent_client")
    assert r["AllowedOAuthFlows"] == ["client_credentials"] and r["GenerateSecret"] is True
    assert r["AccessTokenValidity"] == 5 and r["TokenValidityUnits"] == {"AccessToken": "minutes"}


def test_policies_one_per_rule_strictly_validated():
    reqs = D.policy_requests("e", "arn:aws:bedrock-agentcore:us-east-1:1:gateway/g")
    assert [r["name"] for r in reqs][-5:] == ["F2", "F3k1", "F3k2", "F3k3", "F3k4"]
    assert all(r["validationMode"] == "FAIL_ON_ANY_FINDINGS" for r in reqs)
    assert all('AgentCore::Gateway::"arn:aws:bedrock-agentcore:us-east-1:1:gateway/g"' in r["definition"]["cedar"]["statement"]
               for r in reqs)


def test_attach_keeps_gateway_config_and_sets_mode():
    gw = {"gatewayId": "g1", "gatewayArn": "arn", "status": "READY",
          **D.gateway_request("arn:r", "us-east-1", "p", ["c"], "arn:i")}
    r = D.attach_request(gw, "arn:engine", "ENFORCE")
    assert r["policyEngineConfiguration"] == {"arn": "arn:engine", "mode": "ENFORCE"}
    assert r["interceptorConfigurations"] == gw["interceptorConfigurations"] and "status" not in r
    with pytest.raises(AssertionError):
        D.attach_request(gw, "arn:engine", "OFF")


def test_function_env_size_guard():
    with pytest.raises(SystemExit):
        D.function_env({"A": "x" * 5000}, {})
    assert D.function_env({"A": "1"}, {"B": "2"}) == {"A": "1", "B": "2"}


def test_plan_carries_no_secrets():
    blob = json.dumps(D.plan("us-east-1"), default=str)
    assert "AL_CALLER_KEY" not in blob and "PRIVATE KEY" not in blob and "ClientSecret" not in blob


def test_lambda_role_reaches_only_the_registry_tables():
    doc = D.lambda_role_policy("1", "us-east-1")
    st, _ = doc["Statement"]
    assert sorted(st["Resource"]) == ["arn:aws:dynamodb:us-east-1:1:table/al-changes",
                                      "arn:aws:dynamodb:us-east-1:1:table/al-licences",
                                      "arn:aws:dynamodb:us-east-1:1:table/al-warnings"]
    assert "dynamodb:DeleteItem" not in st["Action"] and "dynamodb:*" not in st["Action"]


def test_lambda_role_can_only_append_to_the_audit_table():
    _, st = D.lambda_role_policy("1", "us-east-2")["Statement"]
    assert st["Action"] == "dynamodb:PutItem"            # never UpdateItem or DeleteItem: records cannot change
    assert st["Resource"] == "arn:aws:dynamodb:us-east-2:1:table/al-audit"


def test_audit_table_keys_a_run_and_orders_by_time():
    req = D.audit_table_request()
    assert req["KeySchema"] == [{"AttributeName": "run_id", "KeyType": "HASH"},
                                {"AttributeName": "sk", "KeyType": "RANGE"}]


def test_roles_go_under_the_hackathon_path_and_boundary_when_required():
    r = D.role_request("al-lambda-exec", D.lambda_trust(), "111122223333", True)
    assert r["Path"] == "/bb26/"
    assert r["PermissionsBoundary"] == "arn:aws:iam::111122223333:policy/bb26-boundary/bb26-Boundary"
    assert "Path" not in D.role_request("al-lambda-exec", D.lambda_trust(), "1", False)


@pytest.mark.parametrize("key,resource", [
    ("arn:aws:kms:us-east-1:1:key/abc", "arn:aws:kms:us-east-1:1:key/abc"),
    ("abc", "arn:aws:kms:us-east-1:1:key/abc"),
    ("alias/al-licence-issuer", "arn:aws:kms:us-east-1:1:key/*")])
def test_lambda_role_reads_kms_public_key_only(key, resource):
    _, _, st = D.lambda_role_policy("1", "us-east-1", key)["Statement"]
    assert st["Action"] == "kms:GetPublicKey" and st["Resource"] == resource      # never kms:Sign
    if key.startswith("alias/"):
        assert st["Condition"] == {"StringEquals": {"kms:RequestAlias": key}}
    blob = json.dumps(D.plan("us-east-1", kms_key=key), default=str)
    assert "kms:GetPublicKey" in blob and "kms:Sign" not in blob


def test_target_create_waits_for_gateway_role_invoke_grant(monkeypatch):
    """Live run 2026-10-31: CreateGatewayTarget failed once while the new invoke grant propagated."""
    monkeypatch.setattr(D.time, "sleep", lambda s: None)
    calls = []

    def create():
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("Gateway execution role lacks permission to invoke Lambda function")
        return {"targetId": "t1"}

    assert D.Deployer.retry(create, "target") == {"targetId": "t1"} and len(calls) == 2


def test_policy_update_request_matches_installed_api():
    """Live deploy 2026-10-31 failed: botocore 1.43 wants UpdatePolicy.description as {"optionalValue": ...}."""
    shape = model("bedrock-agentcore-control").operation_model("UpdatePolicy").input_shape
    for req in D.policy_requests("al_netops-abcdef1234", "arn:aws:bedrock-agentcore:us-east-1:1:gateway/g"):
        up = D.update_policy_request("F1-abcdef123456", req, shape)
        report = ParamValidator().validate(up, shape)
        assert not report.has_errors(), report.generate_report()
        assert "name" not in up and up["definition"] == req["definition"]


def test_existing_policies_read_across_pages():
    pages = {None: {"policies": [{"name": "P1"}], "nextToken": "t2"}, "t2": {"policies": [{"name": "F1"}]}}
    seen = []

    def fake(policyEngineId, nextToken=None):
        seen.append((policyEngineId, nextToken))
        return pages[nextToken]
    assert [p["name"] for p in D.all_items(fake, "policies", policyEngineId="e")] == ["P1", "F1"]
    assert seen == [("e", None), ("e", "t2")]
