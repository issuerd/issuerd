"""DPoP (RFC 9449) key management and proof signing.

The app owns a single EC P-256 key, persisted at DPOP_KEY_PATH so restarts
keep the key (and therefore the ``cnf.jkt`` binding of every issued token).
Every proof carries a fresh ``jti`` — replay caches server-side are single-use.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import time
import uuid

import jwt  # PyJWT
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


class DPoPKey:
    def __init__(self, private_key: EllipticCurvePrivateKey):
        self._private_key = private_key

    @classmethod
    def load_or_create(cls, path: str) -> "DPoPKey":
        if os.path.exists(path):
            with open(path, "rb") as fh:
                key = serialization.load_pem_private_key(fh.read(), password=None)
            if not isinstance(key, EllipticCurvePrivateKey):
                raise TypeError(f"{path} does not contain an EC private key")
            return cls(key)
        key = ec.generate_private_key(ec.SECP256R1())
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass  # Windows: POSIX modes are advisory only
        return cls(key)

    def public_jwk(self) -> dict:
        """Public JWK for the proof header — never includes private fields."""
        numbers = self._private_key.public_key().public_numbers()
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": b64url(numbers.x.to_bytes(32, "big")),
            "y": b64url(numbers.y.to_bytes(32, "big")),
        }

    def jkt(self) -> str:
        """RFC 7638 JWK SHA-256 thumbprint — what tokens carry as ``cnf.jkt``."""
        canonical = json.dumps(self.public_jwk(), separators=(",", ":"), sort_keys=True)
        return b64url(hashlib.sha256(canonical.encode("utf-8")).digest())

    def proof(self, htu: str, htm: str = "POST", access_token: str | None = None) -> str:
        payload = {
            "jti": uuid.uuid4().hex,
            "htm": htm,
            "htu": htu,
            "iat": int(time.time()),
        }
        if access_token is not None:
            payload["ath"] = b64url(hashlib.sha256(access_token.encode("ascii")).digest())
        pem = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return jwt.encode(
            payload,
            pem,
            algorithm="ES256",
            headers={"typ": "dpop+jwt", "jwk": self.public_jwk()},
        )
