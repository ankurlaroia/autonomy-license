"""Caller identity for Path B on AWS.

The Gateway does not pass the caller's identity to a Lambda target: the documented context carries
only the tool name, gateway, target and request ids. The request interceptor does see the request
headers (passRequestHeaders=true), so it re-verifies the caller's Cognito access token and attaches a
short-lived HMAC attestation, `caller`, bound to role, tool and incident. The tool Lambda accepts a
role only from a valid attestation (or from a Gateway context key, if one is ever configured).

The agent cannot forge an attestation: it has no HMAC key and no direct lambda:InvokeFunction (T13),
and the interceptor strips any agent-supplied `caller` before adding its own.
"""
from __future__ import annotations

import hashlib
import hmac
import time

ROLES = ("netops-agent", "netops-specialist", "noc-engineer")
TTL_S = 60


def _mac(key: bytes, role: str, exp: int, tool: str, incident_id: str) -> str:
    msg = f"{role}|{exp}|{tool}|{incident_id}".encode()
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def attest(key: bytes, role: str, tool: str, incident_id: str, now: int | None = None) -> str:
    if role not in ROLES:
        raise ValueError("unknown role")
    exp = int(now if now is not None else time.time()) + TTL_S
    return f"{role}.{exp}.{_mac(key, role, exp, tool, incident_id)}"


def verify(key: bytes | None, token, tool: str, incident_id, now: int | None = None) -> str | None:
    """Role from a valid, unexpired attestation for this tool and incident; None otherwise (fail closed)."""
    if not key or not isinstance(token, str) or not isinstance(incident_id, str):
        return None
    try:
        role, exp_s, mac = token.split(".")
        exp = int(exp_s)
    except ValueError:
        return None
    if role not in ROLES or exp < int(now if now is not None else time.time()):
        return None
    return role if hmac.compare_digest(mac, _mac(key, role, exp, tool, incident_id)) else None


def role_from_claims(claims: dict, issuer: str, clients: set[str]) -> str | None:
    """Role from an already signature-checked Cognito access token."""
    if claims.get("iss") != issuer or claims.get("token_use") != "access":
        return None
    if claims.get("client_id") not in clients:
        return None
    role = claims.get("role")
    return role if role in ROLES else None
