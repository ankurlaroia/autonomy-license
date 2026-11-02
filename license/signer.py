"""Signers for ES256 JWS. LocalSigner for development; KmsSigner for AWS (spec 9.2).

KMS returns a DER-encoded ECDSA signature; JWS ES256 needs raw r||s (64 bytes).
"""
from __future__ import annotations

import base64
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _jws(header: dict, claims: dict, sign_der) -> str:
    si = f"{b64u(json.dumps(header, separators=(',', ':')).encode())}." \
         f"{b64u(json.dumps(claims, separators=(',', ':')).encode())}".encode()
    r, s = decode_dss_signature(sign_der(si))
    return si.decode() + "." + b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


class LocalSigner:
    def __init__(self, key: ec.EllipticCurvePrivateKey | None = None, kid: str = "local-dev"):
        self.key = key or ec.generate_private_key(ec.SECP256R1())
        self.kid = kid

    def public_key(self):
        return self.key.public_key()

    def public_pem(self) -> bytes:
        return self.public_key().public_bytes(serialization.Encoding.PEM,
                                              serialization.PublicFormat.SubjectPublicKeyInfo)

    def sign(self, header: dict, claims: dict) -> str:
        return _jws({**header, "kid": self.kid},
                    claims, lambda m: self.key.sign(m, ec.ECDSA(hashes.SHA256())))

    def private_pem(self) -> bytes:
        return self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption())

    @classmethod
    def load_or_create(cls, path: str, kid: str):
        import os
        if os.path.exists(path):
            return cls(serialization.load_pem_private_key(open(path, "rb").read(), None), kid)
        s = cls(kid=kid)
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        open(path, "wb").write(s.private_pem())
        os.chmod(path, 0o600)
        return s


class KmsSigner:   # pragma: no cover - needs AWS
    """Asymmetric KMS key: KeySpec ECC_NIST_P256, KeyUsage SIGN_VERIFY."""

    def __init__(self, key_id: str, region: str | None = None):
        import boto3
        self.kms = boto3.client("kms", region_name=region)
        self.key_id = key_id
        self.kid = key_id

    def public_key(self):
        der = self.kms.get_public_key(KeyId=self.key_id)["PublicKey"]
        return serialization.load_der_public_key(der)

    def sign(self, header: dict, claims: dict) -> str:
        return _jws({**header, "kid": self.kid}, claims,
                    lambda m: self.kms.sign(KeyId=self.key_id, Message=m, MessageType="RAW",
                                            SigningAlgorithm="ECDSA_SHA_256")["Signature"])
