"""Deploy the smoke-test stack (S1-S3): three Lambdas, Cognito M2M identity, AgentCore Policy engine with
the Cedar set, and the NetOps Gateway with its Lambda target and request interceptor.

  python -m aws.infra.deploy plan                       # print every request; touches nothing
  python -m aws.infra.deploy apply                      # create or update, attach policy in LOG_ONLY
  python -m aws.infra.deploy mode ENFORCE               # S2: switch the policy engine to ENFORCE
  python -m aws.infra.deploy status
  python -m aws.infra.deploy licence status|revoke     # shared registry: a revoke reaches every Lambda at once

Request bodies come from the pure *_request() functions below, which tests/test_deploy_requests.py validates
offline against botocore's service models, so a shape AWS would reject fails locally first.

Idempotent: each step looks resources up by name and updates them. dist/aws_state.json keeps ids and ARNs
only. Secrets never touch disk: the caller-attestation key is generated per deploy and lives only in the
Lambda environment; Cognito client secrets stay in Cognito (smoke.py reads them at run time).

Costs: Lambda, Gateway, Policy and Cognito are pay per request (cents for the smoke test). No idle cost
except CloudWatch log storage. Cognito M2M token requests are billed per request.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import time

from aws.cedar.gen_policies import policy_statements
from aws.cedar.schema import gateway_tool_schemas, validate

NAMES = {
    "lambda_role": "al-lambda-exec", "gateway_role": "al-gateway-exec",
    "tools_fn": "al-netops-tools", "interceptor_fn": "al-netops-interceptor", "pretoken_fn": "al-netops-pretoken",
    "pool": "al-netops", "resource_server": "netops", "scope": "invoke",
    "agent_client": "al-netops-agent", "engineer_client": "al-netops-engineer",
    "engine": "al_netops", "gateway": "al-netops", "target": "NetOps",
}
HANDLERS = {"tools_fn": "aws.tool_lambda.handler.lambda_handler",
            "interceptor_fn": "aws.interceptor.handler.lambda_handler",
            "pretoken_fn": "aws.pretoken.handler.lambda_handler"}
STATE = os.path.join("dist", "aws_state.json")
DDB_PREFIX = "al"
TABLES = {"licences": "jti", "warnings": "nonce",     # shared registry (license/registry_ddb.py)
          "changes": "incident_id"}                    # cells changed per incident (aws/tool_lambda/ledger.py)
AUDIT_TABLE = f"{DDB_PREFIX}-audit"                    # lasting decision records (aws/audit.py), append-only
ROLE_PATH = "/bb26/"                                   # hackathon accounts accept service roles only here,
BOUNDARY = "policy/bb26-boundary/bb26-Boundary"        # and only with this permissions boundary


# ---------------------------------------------------------------- pure request builders
def lambda_trust() -> dict:
    return {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                                                     "Action": "sts:AssumeRole"}]}


def gateway_trust(account: str, region: str) -> dict:
    return {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "bedrock-agentcore.amazonaws.com"}, "Action": "sts:AssumeRole",
        "Condition": {"StringEquals": {"aws:SourceAccount": account},
                      "ArnLike": {"aws:SourceArn": f"arn:aws:bedrock-agentcore:{region}:{account}:*"}}}]}


def table_request(table: str) -> dict:
    return {"TableName": f"{DDB_PREFIX}-{table}", "BillingMode": "PAY_PER_REQUEST",
            "AttributeDefinitions": [{"AttributeName": TABLES[table], "AttributeType": "S"}],
            "KeySchema": [{"AttributeName": TABLES[table], "KeyType": "HASH"}]}


def kms_statement(account: str, region: str, kms_key: str) -> dict:
    """Read the issuer public key only (verify, never sign). An alias is matched by kms:RequestAlias."""
    if kms_key.startswith("arn:"):
        return {"Effect": "Allow", "Action": "kms:GetPublicKey", "Resource": kms_key}
    if kms_key.startswith("alias/"):
        return {"Effect": "Allow", "Action": "kms:GetPublicKey", "Resource": f"arn:aws:kms:{region}:{account}:key/*",
                "Condition": {"StringEquals": {"kms:RequestAlias": kms_key}}}
    return {"Effect": "Allow", "Action": "kms:GetPublicKey", "Resource": f"arn:aws:kms:{region}:{account}:key/{kms_key}"}


def audit_table_request() -> dict:
    """pk run_id, sk "<UTC time>#<source>#<rec_id>": one run's records in a time window are one key range."""
    return {"TableName": AUDIT_TABLE, "BillingMode": "PAY_PER_REQUEST",
            "AttributeDefinitions": [{"AttributeName": "run_id", "AttributeType": "S"},
                                     {"AttributeName": "sk", "AttributeType": "S"}],
            "KeySchema": [{"AttributeName": "run_id", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}]}


def role_request(name: str, trust: dict, account: str, boundary: bool) -> dict:
    req = {"RoleName": name, "AssumeRolePolicyDocument": json.dumps(trust), "Description": "Autonomy License"}
    if boundary:
        req.update(Path=ROLE_PATH, PermissionsBoundary=f"arn:aws:iam::{account}:{BOUNDARY}")
    return req


def lambda_role_policy(account: str, region: str, kms_key: str | None = None) -> dict:
    """Lambdas read and update the shared registry, append to the audit table (PutItem only: they can never
    change or delete a record) and, for a real licence, read the issuer public key."""
    tables = [f"arn:aws:dynamodb:{region}:{account}:table/{DDB_PREFIX}-{t}" for t in TABLES]
    stmts = [{"Effect": "Allow", "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem",
                                            "dynamodb:Scan"], "Resource": tables},
             {"Effect": "Allow", "Action": "dynamodb:PutItem",
              "Resource": f"arn:aws:dynamodb:{region}:{account}:table/{AUDIT_TABLE}"}]
    if kms_key:
        stmts.append(kms_statement(account, region, kms_key))
    return {"Version": "2012-10-17", "Statement": stmts}


def gateway_role_policy(account: str, region: str, fn_arns: list[str], engine_arn: str) -> dict:
    """Invoke the target and interceptor; evaluate Cedar (AgentCore policy-permissions guide)."""
    gateways = f"arn:aws:bedrock-agentcore:{region}:{account}:gateway/*"
    return {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn_arns},
        {"Effect": "Allow", "Action": "bedrock-agentcore:GetPolicyEngine", "Resource": [engine_arn]},
        {"Effect": "Allow", "Action": ["bedrock-agentcore:AuthorizeAction",
                                       "bedrock-agentcore:PartiallyAuthorizeActions"],
         "Resource": [engine_arn, gateways]}]}


def function_request(key: str, role_arn: str, env: dict, zip_bytes: bytes) -> dict:
    return {"FunctionName": NAMES[key], "Runtime": "python3.12", "Role": role_arn, "Handler": HANDLERS[key],
            "Code": {"ZipFile": zip_bytes}, "Timeout": 30, "MemorySize": 512, "Architectures": ["x86_64"],
            "Environment": {"Variables": env}}


def user_pool_request(pretoken_arn: str) -> dict:
    return {"PoolName": NAMES["pool"], "UserPoolTier": "ESSENTIALS",      # V3_0 (M2M claims) needs Essentials
            "LambdaConfig": {"PreTokenGenerationConfig": {"LambdaVersion": "V3_0", "LambdaArn": pretoken_arn}}}


def resource_server_request(pool_id: str) -> dict:
    return {"UserPoolId": pool_id, "Identifier": NAMES["resource_server"], "Name": "NetOps gateway",
            "Scopes": [{"ScopeName": NAMES["scope"], "ScopeDescription": "Call NetOps tools through the gateway"}]}


def client_request(pool_id: str, key: str) -> dict:
    return {"UserPoolId": pool_id, "ClientName": NAMES[key], "GenerateSecret": True,
            "AllowedOAuthFlows": ["client_credentials"], "AllowedOAuthFlowsUserPoolClient": True,
            "AllowedOAuthScopes": [f"{NAMES['resource_server']}/{NAMES['scope']}"],
            "AccessTokenValidity": 5, "TokenValidityUnits": {"AccessToken": "minutes"}}


def issuer_url(region: str, pool_id: str) -> str:
    return f"https://cognito-idp.{region}.amazonaws.com/{pool_id}"


def gateway_request(role_arn: str, region: str, pool_id: str, client_ids: list[str], interceptor_arn: str) -> dict:
    return {"name": NAMES["gateway"], "roleArn": role_arn, "protocolType": "MCP",
            "description": "Autonomy License NetOps gateway (smoke test)",
            "authorizerType": "CUSTOM_JWT",
            "authorizerConfiguration": {"customJWTAuthorizer": {
                "discoveryUrl": issuer_url(region, pool_id) + "/.well-known/openid-configuration",
                "allowedClients": client_ids}},
            "interceptorConfigurations": [{
                "interceptor": {"lambda": {"arn": interceptor_arn}}, "interceptionPoints": ["REQUEST"],
                "inputConfiguration": {"passRequestHeaders": True}}],    # the interceptor re-verifies the token
            "exceptionLevel": "DEBUG"}


def target_request(gateway_id: str, tools_arn: str) -> dict:
    return {"gatewayIdentifier": gateway_id, "name": NAMES["target"],
            "description": "NetOps tools (simulated network)",
            "targetConfiguration": {"mcp": {"lambda": {"lambdaArn": tools_arn,
                                                       "toolSchema": {"inlinePayload": gateway_tool_schemas()}}}},
            "credentialProviderConfigurations": [{"credentialProviderType": "GATEWAY_IAM_ROLE"}]}


def policy_requests(engine_id: str, gateway_arn: str) -> list[dict]:
    errors = validate(gateway_arn)
    if errors:
        raise SystemExit("policy set fails strict validation:\n" + "\n".join(errors))
    return [{"policyEngineId": engine_id, "name": name, "description": f"Autonomy License {name}",
             "definition": {"cedar": {"statement": text}}, "validationMode": "FAIL_ON_ANY_FINDINGS"}
            for name, text in policy_statements(gateway_arn)]


def all_items(list_fn, key: str, **kw) -> list:
    """Every page of an AgentCore list call (nextToken). The policy list pages; reading only the first page
    made the 2026-10-31 redeploy try to re-create an existing policy (ConflictException)."""
    items, token = [], None
    while True:
        page = list_fn(**kw, **({"nextToken": token} if token else {}))
        items += page.get(key, [])
        token = page.get("nextToken")
        if not token:
            return items


def update_policy_request(policy_id: str, req: dict, input_shape) -> dict:
    """CreatePolicy fields reshaped for UpdatePolicy: botocore 1.43 models optional update fields such as
    description as {"optionalValue": ...} while CreatePolicy keeps the plain string."""
    out = {"policyId": policy_id}
    for k, v in req.items():
        member = input_shape.members.get(k)
        if k == "name" or member is None:
            continue
        wrap = member.type_name == "structure" and list(member.members) == ["optionalValue"] and not isinstance(v, dict)
        out[k] = {"optionalValue": v} if wrap else v
    return out


def attach_request(gw: dict, engine_arn: str, mode: str) -> dict:
    """UpdateGateway needs the full configuration back, plus the policy engine."""
    assert mode in ("LOG_ONLY", "ENFORCE")
    keep = ("name", "description", "roleArn", "protocolType", "protocolConfiguration", "authorizerType",
            "authorizerConfiguration", "kmsKeyArn", "interceptorConfigurations", "exceptionLevel")
    req = {k: gw[k] for k in keep if gw.get(k) is not None}
    req.update(gatewayIdentifier=gw["gatewayId"], policyEngineConfiguration={"arn": engine_arn, "mode": mode})
    return req


def function_env(base: dict, extra: dict) -> dict:
    env = {**base, **extra}
    if len(json.dumps(env)) > 4000:
        raise SystemExit("Lambda environment over 4 KB")
    return env


# ---------------------------------------------------------------- AWS side (needs credentials)
class Deployer:   # pragma: no cover - needs AWS
    def __init__(self, region: str | None, profile: str | None, bundle: str, zip_path: str):
        import boto3
        self.s = boto3.session.Session(profile_name=profile, region_name=region)
        self.region = self.s.region_name or "us-east-2"
        if region is None and self.s.region_name is None:
            self.s = boto3.session.Session(profile_name=profile, region_name=self.region)
        self.account = self.s.client("sts").get_caller_identity()["Account"]
        self.iam, self.lam = self.s.client("iam"), self.s.client("lambda")
        self.cog, self.ac = self.s.client("cognito-idp"), self.s.client("bedrock-agentcore-control")
        self.bundle = bundle
        self.bundle_env = json.load(open(os.path.join(bundle, "lambda_env.json")))
        self.zip_path = zip_path
        self.state = json.load(open(STATE)) if os.path.exists(STATE) else {}
        self.state.update(region=region, account=self.account)

    def save(self):
        os.makedirs(os.path.dirname(STATE), exist_ok=True)
        json.dump(self.state, open(STATE, "w"), indent=1)

    @staticmethod
    def wait(get, ok, bad, what, timeout=300):
        t0 = time.time()
        while True:
            r = get()
            st = r.get("status")
            if st in ok:
                return r
            if st in bad:
                raise SystemExit(f"{what}: {st} {r.get('statusReasons')}")
            if time.time() - t0 > timeout:
                raise SystemExit(f"{what}: still {st} after {timeout}s")
            time.sleep(5)

    @staticmethod
    def retry(fn, what, tries=12):
        """IAM roles take a few seconds to become assumable by Lambda / AgentCore."""
        for i in range(tries):
            try:
                return fn()
            except Exception as e:      # noqa: BLE001 - surfaced after the last try
                if i == tries - 1 or "assum" not in str(e).lower() and "role" not in str(e).lower():
                    raise
                print(f"  {what}: waiting for IAM ({e.__class__.__name__})")
                time.sleep(5)

    def needs_boundary(self) -> bool:
        """Hackathon team accounts refuse service roles outside /bb26/ or without their boundary."""
        try:
            self.iam.get_policy(PolicyArn=f"arn:aws:iam::{self.account}:{BOUNDARY}")
            return True
        except self.iam.exceptions.NoSuchEntityException:
            return False

    # 1 roles
    def roles(self):
        boundary = self.needs_boundary()
        for key, trust, managed in (("lambda_role", lambda_trust(), "service-role/AWSLambdaBasicExecutionRole"),
                                    ("gateway_role", gateway_trust(self.account, self.region), None)):
            name = NAMES[key]
            try:
                arn = self.iam.get_role(RoleName=name)["Role"]["Arn"]
                self.iam.update_assume_role_policy(RoleName=name, PolicyDocument=json.dumps(trust))
            except self.iam.exceptions.NoSuchEntityException:
                arn = self.iam.create_role(**role_request(name, trust, self.account, boundary))["Role"]["Arn"]
            if managed:
                self.iam.attach_role_policy(RoleName=name, PolicyArn=f"arn:aws:iam::aws:policy/{managed}")
                self.iam.put_role_policy(RoleName=name, PolicyName="al-registry",
                                         PolicyDocument=json.dumps(lambda_role_policy(
                                             self.account, self.region, self.bundle_env.get("AL_ISSUER_KMS_KEY"))))
            self.state[key] = arn
            print("role", name)

    # 1b shared registry
    def tables(self):
        ddb = self.s.client("dynamodb")
        for req in [table_request(t) for t in TABLES] + [audit_table_request()]:
            try:
                ddb.describe_table(TableName=req["TableName"])
            except ddb.exceptions.ResourceNotFoundException:
                ddb.create_table(**req)
            ddb.get_waiter("table_exists").wait(TableName=req["TableName"])
            print("table", req["TableName"])
        self.publish_licence()

    def publish_licence(self):
        """Copy the bundle's licence (stub now, calibrated for S5) into the shared registry."""
        import sqlite3
        from license.registry_ddb import DynamoRegistry
        db = sqlite3.connect(os.path.join(self.bundle, "al.db"))
        rows = db.execute("SELECT jti, token, status FROM licences ORDER BY issued_at").fetchall()
        reg = DynamoRegistry(self.s.client("dynamodb"), DDB_PREFIX)
        for jti, token, status in rows:
            if reg.status(jti) == "unknown":
                reg.put(jti, token, status)
        self.state["licence_jti"] = rows[-1][0] if rows else None
        print("licence published", self.state["licence_jti"])

    # 2 + 4 functions
    def functions(self, extra: dict | None = None):
        code = open(self.zip_path, "rb").read()
        for key in HANDLERS:
            env = function_env({**self.bundle_env, "AL_DDB_PREFIX": DDB_PREFIX, "AL_AUDIT_TABLE": AUDIT_TABLE,
                                "AL_RUN_ID": "undeclared"}, (extra or {}).get(key, {}))
            req = function_request(key, self.state["lambda_role"], env, code)
            name = req["FunctionName"]
            try:
                self.lam.get_function(FunctionName=name)
                if extra is None:
                    self.lam.update_function_code(FunctionName=name, ZipFile=code)
                    self.lam.get_waiter("function_updated_v2").wait(FunctionName=name)
                cfg = {k: req[k] for k in ("Role", "Handler", "Runtime", "Timeout", "MemorySize", "Environment")}
                arn = self.lam.update_function_configuration(FunctionName=name, **cfg)["FunctionArn"]
            except self.lam.exceptions.ResourceNotFoundException:
                arn = self.retry(lambda: self.lam.create_function(**req), name)["FunctionArn"]
            self.lam.get_waiter("function_updated_v2" if extra else "function_active_v2").wait(FunctionName=name)
            self.state[key] = arn
            print("lambda", name)

    # 3 cognito
    def cognito(self):
        pools = [p for p in self.cog.list_user_pools(MaxResults=60)["UserPools"] if p["Name"] == NAMES["pool"]]
        req = user_pool_request(self.state["pretoken_fn"])
        if pools:
            pool_id = pools[0]["Id"]
            self.cog.update_user_pool(UserPoolId=pool_id, UserPoolTier=req["UserPoolTier"],
                                      LambdaConfig=req["LambdaConfig"])
        else:
            pool_id = self.cog.create_user_pool(**req)["UserPool"]["Id"]
        pool_arn = f"arn:aws:cognito-idp:{self.region}:{self.account}:userpool/{pool_id}"
        try:
            self.lam.add_permission(FunctionName=NAMES["pretoken_fn"], StatementId="cognito-pretoken",
                                    Action="lambda:InvokeFunction", Principal="cognito-idp.amazonaws.com",
                                    SourceArn=pool_arn)
        except self.lam.exceptions.ResourceConflictException:
            pass
        domain = f"al-netops-{self.account}"
        if not self.cog.describe_user_pool(UserPoolId=pool_id)["UserPool"].get("Domain"):
            self.cog.create_user_pool_domain(Domain=domain, UserPoolId=pool_id)
        try:
            self.cog.describe_resource_server(UserPoolId=pool_id, Identifier=NAMES["resource_server"])
        except self.cog.exceptions.ResourceNotFoundException:
            self.cog.create_resource_server(**resource_server_request(pool_id))
        existing = {c["ClientName"]: c["ClientId"]
                    for c in self.cog.list_user_pool_clients(UserPoolId=pool_id, MaxResults=60)["UserPoolClients"]}
        for key in ("agent_client", "engineer_client"):
            cid = existing.get(NAMES[key]) or \
                self.cog.create_user_pool_client(**client_request(pool_id, key))["UserPoolClient"]["ClientId"]
            self.state[key] = cid
        self.state.update(pool_id=pool_id, domain=domain,
                          token_url=f"https://{domain}.auth.{self.region}.amazoncognito.com/oauth2/token",
                          scope=f"{NAMES['resource_server']}/{NAMES['scope']}")
        print("cognito", pool_id)

    def wire_env(self):
        iss = issuer_url(self.region, self.state["pool_id"])
        clients = [self.state["agent_client"], self.state["engineer_client"]]
        key = secrets.token_hex(32)                     # never written to disk
        roles = {self.state["agent_client"]: "netops-agent", self.state["engineer_client"]: "noc-engineer"}
        self.functions(extra={
            "tools_fn": {"AL_CALLER_KEY": key},
            "interceptor_fn": {"AL_CALLER_KEY": key, "AL_JWKS_URL": iss + "/.well-known/jwks.json",
                               "AL_JWT_ISSUER": iss, "AL_ALLOWED_CLIENTS": ",".join(clients)},
            "pretoken_fn": {"AL_CLIENT_ROLES": json.dumps(roles)}})

    # 5 policy engine
    def engine(self):
        found = [e for e in self.ac.list_policy_engines().get("policyEngines", []) if e["name"] == NAMES["engine"]]
        e = found[0] if found else self.ac.create_policy_engine(name=NAMES["engine"],
                                                                description="Autonomy License NetOps")
        e = self.wait(lambda: self.ac.get_policy_engine(policyEngineId=e["policyEngineId"]),
                      {"ACTIVE"}, {"CREATE_FAILED"}, "policy engine")
        self.state.update(engine_id=e["policyEngineId"], engine_arn=e["policyEngineArn"])
        print("policy engine", e["policyEngineId"])

    # 6 gateway role permissions
    def gateway_permissions(self):
        doc = gateway_role_policy(self.account, self.region, [self.state["tools_fn"], self.state["interceptor_fn"]],
                                  self.state["engine_arn"])
        self.iam.put_role_policy(RoleName=NAMES["gateway_role"], PolicyName="netops-gateway",
                                 PolicyDocument=json.dumps(doc))
        print("gateway role policy")

    # 7 gateway
    def gateway(self):
        found = [g for g in self.ac.list_gateways().get("items", []) if g["name"] == NAMES["gateway"]]
        req = gateway_request(self.state["gateway_role"], self.region, self.state["pool_id"],
                              [self.state["agent_client"], self.state["engineer_client"]], self.state["interceptor_fn"])
        if found:
            gid = found[0]["gatewayId"]
            cur = self.ac.get_gateway(gatewayIdentifier=gid)
            upd = {k: v for k, v in req.items()}
            if cur.get("policyEngineConfiguration"):
                upd["policyEngineConfiguration"] = cur["policyEngineConfiguration"]
            self.retry(lambda: self.ac.update_gateway(gatewayIdentifier=gid, **upd), "gateway")
        else:
            gid = self.retry(lambda: self.ac.create_gateway(**req), "gateway")["gatewayId"]
        g = self.wait(lambda: self.ac.get_gateway(gatewayIdentifier=gid), {"READY"},
                      {"FAILED", "UPDATE_UNSUCCESSFUL"}, "gateway")
        self.state.update(gateway_id=gid, gateway_arn=g["gatewayArn"], gateway_url=g["gatewayUrl"])
        print("gateway", g["gatewayUrl"])

    # 8 target
    def target(self):
        gid = self.state["gateway_id"]
        found = [t for t in self.ac.list_gateway_targets(gatewayIdentifier=gid).get("items", [])
                 if t["name"] == NAMES["target"]]
        req = target_request(gid, self.state["tools_fn"])
        if found:
            tid = found[0]["targetId"]
            self.retry(lambda: self.ac.update_gateway_target(targetId=tid, **req), "target")
        else:   # the gateway role's invoke grant was just written; AgentCore checks it on create
            tid = self.retry(lambda: self.ac.create_gateway_target(**req), "target")["targetId"]
        self.wait(lambda: self.ac.get_gateway_target(gatewayIdentifier=gid, targetId=tid), {"READY"},
                  {"FAILED", "UPDATE_UNSUCCESSFUL"}, "target")
        self.state["target_id"] = tid
        print("target", NAMES["target"])

    # 9 policies
    def policies(self):
        eid = self.state["engine_id"]
        existing = {p["name"]: p["policyId"] for p in all_items(self.ac.list_policies, "policies", policyEngineId=eid)}
        for req in policy_requests(eid, self.state["gateway_arn"]):
            if req["name"] in existing:
                pid = existing[req["name"]]
                shape = self.ac.meta.service_model.operation_model("UpdatePolicy").input_shape
                self.ac.update_policy(**update_policy_request(pid, req, shape))
            else:
                pid = self.ac.create_policy(**req)["policyId"]
            self.wait(lambda: self.ac.get_policy(policyEngineId=eid, policyId=pid), {"ACTIVE"},
                      {"CREATE_FAILED", "UPDATE_FAILED"}, f"policy {req['name']}")
            print("policy", req["name"])

    # 10 attach / switch mode
    def attach(self, mode: str):
        gid = self.state["gateway_id"]
        gw = self.ac.get_gateway(gatewayIdentifier=gid)
        self.retry(lambda: self.ac.update_gateway(**attach_request(gw, self.state["engine_arn"], mode)), "attach")
        self.wait(lambda: self.ac.get_gateway(gatewayIdentifier=gid), {"READY"}, {"FAILED", "UPDATE_UNSUCCESSFUL"},
                  "gateway")
        self.state["policy_mode"] = mode
        print("policy engine attached in", mode)

    def apply(self):
        for step in (self.roles, self.tables, self.functions, self.cognito, self.wire_env, self.engine, self.gateway_permissions,
                     self.gateway, self.target, self.policies):
            step()
            self.save()
        self.attach(self.state.get("policy_mode", "LOG_ONLY"))
        self.save()


def plan(region: str, account: str = "123456789012", kms_key: str | None = None) -> list[tuple[str, dict]]:
    """Every request the deployer will send, with placeholder ids (no AWS calls)."""
    arn = lambda kind, name: f"arn:aws:{kind}:{region}:{account}:{name}"  # noqa: E731
    fns = {k: arn("lambda", f"function:{NAMES[k]}") for k in HANDLERS}
    engine_arn = arn("bedrock-agentcore", "policy-engine/al_netops-PLACEHOLDER")
    gw_arn = arn("bedrock-agentcore", "gateway/al-netops-PLACEHOLDER")
    role = f"arn:aws:iam::{account}:role/"
    out = [("iam.create_role", role_request(NAMES["lambda_role"], lambda_trust(), account, True)),
           ("iam.create_role", role_request(NAMES["gateway_role"], gateway_trust(account, region), account, True))]
    out += [("dynamodb.create_table", table_request(t)) for t in TABLES]
    out.append(("dynamodb.create_table", audit_table_request()))
    out.append(("iam.put_role_policy", {"RoleName": NAMES["lambda_role"], "PolicyName": "al-registry",
                                        "PolicyDocument": json.dumps(lambda_role_policy(account, region, kms_key))}))
    out += [("lambda.create_function", function_request(k, role + NAMES["lambda_role"], {"AL_X": "1"}, b"zip"))
            for k in HANDLERS]
    out += [("cognito-idp.create_user_pool", user_pool_request(fns["pretoken_fn"])),
            ("cognito-idp.create_resource_server", resource_server_request("us-east-1_POOL")),
            ("cognito-idp.create_user_pool_client", client_request("us-east-1_POOL", "agent_client")),
            ("cognito-idp.create_user_pool_client", client_request("us-east-1_POOL", "engineer_client")),
            ("bedrock-agentcore-control.create_policy_engine", {"name": NAMES["engine"]}),
            ("iam.put_role_policy", {"RoleName": NAMES["gateway_role"], "PolicyName": "netops-gateway",
                                     "PolicyDocument": json.dumps(gateway_role_policy(
                                         account, region, [fns["tools_fn"], fns["interceptor_fn"]], engine_arn))}),
            ("bedrock-agentcore-control.create_gateway",
             gateway_request(role + NAMES["gateway_role"], region, "us-east-1_POOL", ["agentclient", "engclient"],
                             fns["interceptor_fn"])),
            ("bedrock-agentcore-control.create_gateway_target", target_request("al-netops-PLACEHOLDER", fns["tools_fn"]))]
    out += [("bedrock-agentcore-control.create_policy", r) for r in policy_requests("al_netops-PLACEHOLDER", gw_arn)]
    gw = {"gatewayId": "al-netops-PLACEHOLDER", **gateway_request(role + NAMES["gateway_role"], region,
                                                                  "us-east-1_POOL", ["agentclient"], fns["interceptor_fn"])}
    out.append(("bedrock-agentcore-control.update_gateway", attach_request(gw, engine_arn, "LOG_ONLY")))
    return out


def warn(d, arg, keys_dir="state/keys", sender="B"):   # pragma: no cover - needs AWS
    """P1 moment 6 on AWS: operator B signs a reviewer-confirmed warning; the receiver verifies it against the
    federation key registry and writes it to the shared table, so every Lambda masks that category."""
    from federation.warnings import make_warning, verify_warning
    from license.registry_ddb import DynamoRegistry
    from license.signer import LocalSigner
    reg, receiver = DynamoRegistry(d.s.client("dynamodb"), DDB_PREFIX), d.bundle_env.get("OPERATOR", "A")
    if arg == "clear":
        return {"cleared": reg.clear_warnings(receiver)}
    if arg not in ("k1", "k2", "k3", "k4"):
        raise SystemExit("warn k1|k2|k3|k4|clear")
    b = LocalSigner.load_or_create(os.path.join(keys_dir, f"operator-{sender}.pem"), f"op-{sender}")
    tok = make_warning(b, sender, arg, "hard_rule_deny", "aws.infra.deploy warn", reviewer="sec-reviewer-1")
    c = verify_warning(tok, {sender: b.public_key()})
    reg.add_warning(c, receiver)
    return {"receiver": receiver, "category": arg, "exp": c["exp"], "warned": sorted(reg.warned_categories(receiver))}


def main():   # pragma: no cover - CLI
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["plan", "apply", "mode", "status", "licence", "warn"])
    ap.add_argument("arg", nargs="?", help="mode: LOG_ONLY|ENFORCE; licence: status|revoke; warn: k1..k4|clear")
    ap.add_argument("--region", help="default: the profile's region, else us-east-2")
    ap.add_argument("--profile")
    ap.add_argument("--bundle", default="dist/bundle")
    ap.add_argument("--zip", default="dist/netops_lambda.zip")
    a = ap.parse_args()
    if a.cmd == "plan":
        env_file = os.path.join(a.bundle, "lambda_env.json")
        kms = json.load(open(env_file)).get("AL_ISSUER_KMS_KEY") if os.path.exists(env_file) else None
        for op, req in plan(a.region or "us-east-2", kms_key=kms):
            shown = {k: ("<zip bytes>" if k == "Code" else v) for k, v in req.items()}
            print(f"--- {op}\n{json.dumps(shown, indent=1, default=str)[:1500]}")
        return
    if a.cmd == "status":
        print(json.dumps(json.load(open(STATE)) if os.path.exists(STATE) else {}, indent=1))
        return
    d = Deployer(a.region, a.profile, a.bundle, a.zip)
    if a.cmd == "licence":
        from license.registry_ddb import DynamoRegistry
        reg = DynamoRegistry(d.s.client("dynamodb"), DDB_PREFIX)
        cur = reg.current()
        if cur and a.arg == "revoke":
            reg.set_status(cur[0], "revoked", "operator revoke (aws.infra.deploy)")
        print(json.dumps({"jti": cur[0] if cur else None, "status": reg.status(cur[0]) if cur else "none"}))
        return
    if a.cmd == "warn":
        print(json.dumps(warn(d, a.arg)))
        return
    if a.cmd == "apply":
        d.apply()
    else:
        if a.arg not in ("LOG_ONLY", "ENFORCE"):
            raise SystemExit("mode LOG_ONLY|ENFORCE")
        d.attach(a.arg)
        d.save()
    print(json.dumps({k: v for k, v in d.state.items() if not k.endswith("_role")}, indent=1))


if __name__ == "__main__":
    main()
