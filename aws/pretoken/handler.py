"""Cognito pre token generation trigger (Path A on AWS), event version V3_0.

Cognito calls this before it issues an access token, including client-credentials (M2M) tokens,
which only reach a V3_0 trigger (Essentials or Plus feature plan). The role comes from the app
client that authenticated (event.callerContext.clientId), never from the request: AL_CLIENT_ROLES
maps app client ids to roles. For the agent, the licence and warnings are verified and the tags are
added as string claims; the Gateway's JWT authorizer turns them into Cedar principal tags.

Fail closed: an unknown client raises, so Cognito issues no token at all. A licence that does not
verify yields lic_state "none", so no P2 permit can match (Paths B and C re-check every call anyway).
"""
import json
import os

from aws.lambda_bootstrap import log_shape, trusted_from_env
from gateway.idp import pre_token_tags

ROLES = ("netops-agent", "noc-engineer")


def client_role(client_id: str, env=os.environ) -> str:
    roles = json.loads(env.get("AL_CLIENT_ROLES", "{}"))
    role = roles.get(client_id)
    if role not in ROLES:
        raise PermissionError("pretoken: app client has no NetOps role")
    return role


def lambda_handler(event, context):
    log_shape("pretoken", event, context)
    role = client_role(event["callerContext"]["clientId"])
    tags = pre_token_tags(trusted_from_env(), role, os.environ.get("OPERATOR", "A"))
    event.setdefault("response", {})["claimsAndScopeOverrideDetails"] = {
        "accessTokenGeneration": {"claimsToAddOrOverride": {k: str(v) for k, v in tags.items()}}}
    return event
