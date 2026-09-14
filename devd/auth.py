"""Per-request token verification (doc §9.3). devd trusts nothing about its
caller merely for arriving on the loopback socket (B5) -- every request
carries a short-lived token signed by a key devd holds only the PUBLIC half
of. This is the second independent factor alongside the SSH tunnel itself.
"""

from __future__ import annotations

from dataclasses import dataclass

import jwt
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from fastapi import Header, HTTPException

from devd import config


class TokenError(Exception):
    pass


@dataclass
class TokenClaims:
    sub: str
    approval_id: str
    operation_id: str
    manifest_version: int
    aud: str


_public_key = None


def _get_public_key():
    global _public_key
    if _public_key is None:
        pem = config.TOKEN_PUBLIC_KEY_PATH.read_bytes()
        _public_key = load_pem_public_key(pem)
    return _public_key


def verify_token(token: str, *, expected_audience: str) -> TokenClaims:
    try:
        payload = jwt.decode(token, _get_public_key(), algorithms=["EdDSA"], audience=expected_audience)
    except jwt.PyJWTError as exc:
        raise TokenError(str(exc)) from exc
    try:
        return TokenClaims(
            sub=payload["sub"],
            approval_id=payload["approval_id"],
            operation_id=payload["operation_id"],
            manifest_version=payload["manifest_ver"],
            aud=payload["aud"],
        )
    except KeyError as exc:
        raise TokenError(f"missing claim: {exc}") from exc


async def token_dependency(authorization: str = Header(default="")) -> TokenClaims:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing_bearer_token")
    token = authorization.removeprefix("Bearer ")
    try:
        return verify_token(token, expected_audience=config.AUDIENCE_PREFIX + config.TARGET_ID)
    except TokenError as exc:
        raise HTTPException(status_code=401, detail=f"invalid_token:{exc}") from exc
