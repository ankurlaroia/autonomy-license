"""Trusted verifier (spec 9.3). FAILS CLOSED: any exception means no autonomy.

Used by: the token-minting step (Path A tags), the Gateway interceptor (Path C) and the tool
Lambda (Path B). The expected fingerprint comes from the deployment registry, never the agent.
"""
from __future__ import annotations

import jwt

from license.issuer import PROFILE, TYP

REQUIRED = ["exp", "iat", "nbf", "jti", "aud", "iss", "sub", "cfg", "profile", "scope", "risk"]


def verify_licence(token: str, public_key, *, issuer: str, audience: str, expected_fingerprint: str,
                   status_lookup, operator: str, requested_category: str | None = None,
                   requested_action: str | None = None, warned_categories=frozenset()) -> dict:
    if jwt.get_unverified_header(token).get("typ") != TYP:
        raise PermissionError("unexpected token type")
    claims = jwt.decode(token, public_key, algorithms=["ES256"], issuer=issuer, audience=audience,
                        leeway=60, options={"require": REQUIRED})
    if claims["profile"] != PROFILE:
        raise PermissionError("unknown evaluation profile")
    if claims["cfg"] != expected_fingerprint:
        raise PermissionError("configuration changed: licence invalid (recertify)")
    state = status_lookup(claims["jti"])
    if state != "active":
        raise PermissionError(f"licence {state}")
    scope = claims["scope"]
    if operator not in scope["operators"]:
        raise PermissionError("operator not covered by this licence")
    if requested_category is not None and (requested_category not in scope["categories"]
                                           or requested_category in warned_categories):
        raise PermissionError("category not licensed or under warning")
    if requested_action is not None and requested_action not in scope["actions"]:
        raise PermissionError("action outside licensed scope")
    return claims
