"""Identity provider stand-in (Cognito on AWS) with the Path A pre-token-generation verifier.

mint_access_token() mimics Cognito client-credentials + a pre-token Lambda: for the agent it
verifies the licence and warnings and adds string tags (role, lic_state, lic_cats, warned, lic_jti).
Tags can be stale for the token lifetime (>= 5 min on Cognito), which is why Paths B and C re-check
the live registry on every call.
"""
from __future__ import annotations

import time

import jwt

from license.signer import LocalSigner
from license.verifier import verify_licence

GATEWAY_AUD = "netops-gateway"


def pre_token_tags(trusted, role: str, operator: str) -> dict:
    """Path A tags, shared with the Cognito pre-token Lambda (aws/pretoken/handler.py)."""
    tags = {"role": role, "operator": operator, "lic_state": "none", "lic_cats": "||", "warned": "||"}
    if role != "netops-agent":
        return tags
    try:
        tok = trusted.registry.current()
        if tok is None:
            raise PermissionError("no licence")
        claims = verify_licence(tok[1], trusted.issuer_public_key, issuer=trusted.issuer,
                                audience=trusted.audience, expected_fingerprint=trusted.expected_fingerprint,
                                status_lookup=trusted.registry.status, operator=operator)
        warned = sorted(trusted.registry.warned_categories(operator))
        cats = [c for c in claims["scope"]["categories"] if c not in warned]
        tags.update(lic_state="active", lic_cats="|" + "|".join(cats) + "|",
                    warned="|" + "|".join(warned) + "|", lic_jti=claims["jti"])
    except Exception as e:                                   # fail closed: no autonomy tags
        tags["lic_error"] = str(e)[:80]
    return tags


class LocalIdP:
    def __init__(self, trusted, signer: LocalSigner | None = None, token_ttl_s: int = 300):
        self.t = trusted
        self.signer = signer or LocalSigner(kid="local-idp")
        self.ttl = token_ttl_s

    def pre_token_tags(self, role: str, operator: str) -> dict:
        return pre_token_tags(self.t, role, operator)

    def mint_access_token(self, sub: str, role: str, operator: str = "A") -> str:
        now = int(time.time())
        claims = {"sub": sub, "aud": GATEWAY_AUD, "iss": "local-idp", "iat": now, "exp": now + self.ttl,
                  **self.pre_token_tags(role, operator)}
        return self.signer.sign({"alg": "ES256", "typ": "JWT"}, claims)

    def decode(self, token: str) -> dict:
        return jwt.decode(token, self.signer.public_key(), algorithms=["ES256"], audience=GATEWAY_AUD,
                          issuer="local-idp")
