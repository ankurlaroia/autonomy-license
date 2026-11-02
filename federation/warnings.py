"""P1 signed category warnings (spec 11). Precautionary policy, no statistical claim.

Sender: an operator signs {category, signal, iat, exp<=2h, nonce} with its own key. A warning
triggered by a hard-rule denial needs a security reviewer's confirmation before broadcast.
Receiver: verifies signature against the federation key registry, rejects unknown issuers,
expired/over-long warnings and replayed nonces, applies rate limits, then masks the category
(it leaves lic_cats; incidents in it go to HUMAN). Warnings can only REDUCE autonomy.
"""
from __future__ import annotations

import json
import time
import uuid

import jwt

MAX_TTL = 2 * 3600
MAX_PER_HOUR = 3


class WarningError(Exception):
    pass


def make_warning(signer, issuer: str, category: str, signal: str, evidence_ref: str,
                 reviewer: str | None = None, ttl_s: int = MAX_TTL, now: int | None = None) -> str:
    if signal == "hard_rule_deny" and not reviewer:
        raise WarningError("hard-rule-deny warnings need a security reviewer's confirmation")
    now = now or int(time.time())
    claims = {"v": 1, "type": "category-warning", "issuer": issuer, "category": category, "signal": signal,
              "evidence_ref": evidence_ref, "reviewer": reviewer, "iat": now, "exp": now + ttl_s,
              "nonce": uuid.uuid4().hex}
    return signer.sign({"alg": "ES256", "typ": "category-warning+jwt"}, claims)


def verify_warning(token: str, key_registry: dict) -> dict:
    """Signature, known issuer, exp/iat present, TTL <= 2 h. Storage checks (replay, rate) are the caller's."""
    try:
        hdr_claims = jwt.decode(token, options={"verify_signature": False})
        issuer = hdr_claims["issuer"]
        if issuer not in key_registry:
            raise WarningError("unknown issuer")
        c = jwt.decode(token, key_registry[issuer], algorithms=["ES256"], options={"require": ["exp", "iat"]},
                       leeway=0)
    except WarningError:
        raise
    except Exception as e:
        raise WarningError(f"invalid warning: {e}") from None
    if c["exp"] - c["iat"] > MAX_TTL:
        raise WarningError("warning TTL exceeds 2 h")
    return c


def receive_warning(store, token: str, receiver: str, key_registry: dict, now: int | None = None) -> dict:
    now = now or int(time.time())
    c = verify_warning(token, key_registry)
    issuer = c["issuer"]
    if store.q("SELECT 1 FROM warnings WHERE nonce=?", (c["nonce"],)):
        raise WarningError("replayed nonce")
    if store.q("SELECT 1 FROM warnings WHERE issuer=? AND category=? AND receiver=? AND status='active' AND exp>?",
               (issuer, c["category"], receiver, now)):
        raise WarningError("rate limit: one active warning per (issuer, category)")
    recent = store.q("SELECT COUNT(*) FROM warnings WHERE issuer=? AND receiver=? AND iat>?",
                     (issuer, receiver, now - 3600))[0][0]
    if recent >= MAX_PER_HOUR:
        raise WarningError("rate limit: at most 3 warnings per issuer per hour")
    store.x("INSERT INTO warnings VALUES (?,?,?,?,?,?,?,?,?)",
            (c["nonce"], issuer, receiver, c["category"], c["signal"], c["iat"], c["exp"], json.dumps(c), "active"))
    store.audit("warning_received", {"issuer": issuer, "category": c["category"], "signal": c["signal"],
                                     "exp": c["exp"]}, receiver)
    return c


def clear_warning(store, nonce: str):
    store.x("UPDATE warnings SET status='cleared' WHERE nonce=?", (nonce,))
