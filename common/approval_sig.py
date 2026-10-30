"""Human approval signatures, checked by devd (closes ROADMAP Known gap #4).

The approval store and the token-signing key both live on the MCP server
host, where an agent with a shell running as the same OS user can read or
write them. So neither one can be what proves a human said yes. Instead:

  - each approver has a FIDO2 security key (a YubiKey or similar). The
    private key never leaves the device, and every signature needs a touch,
    plus the key's PIN when it has one (scripts/approver_keys.py);
  - `decide approve` has the security key sign a statement binding the
    approval id, the proposal hash, the hash of the effect text the human
    was shown, and an expiry;
  - devd holds only the approvers' PUBLIC keys and, for every operation
    whose manifest requires approval, recomputes the proposal hash and the
    effect hash from its own manifest and the request, then verifies the
    signatures. No valid signature means nothing runs.

Each approver key belongs to exactly one OS user: the key is named after
the user (`alice.pub` is user `os:alice`), `approver_keys init` only
creates a key for the user running it, and only root can enroll a key into
the directory devd trusts. That gives four-eyes two rules devd
can check on its own:
  - two approvals means two different users, not two keys of one person;
  - the requester can't be one of them. The requester is bound into the
    proposal hash the human signed, so it can't be swapped afterwards.
For single-approval operations the requester may approve: in the local
topology the agent runs as the human's own OS user, so the requester is
always the person approving.

A security key turns "the agent captured the passphrase once" into "the
agent can get at most one signature per touch, and only while the human is
there". The terminal that shows the request is still the human's own, so
an agent controlling it could show one request and have the key sign
another; only a separate trusted display (e.g. approving on a phone)
closes that.

Passphrase keys (an Ed25519 key in a passphrase-encrypted file, signed
in software) are still accepted for setups without a security key, but
they are opt-in at enrollment: `enroll --passphrase-key`.

FIDO2 signatures are WebAuthn assertions: the authenticator signs
`authenticator_data || sha256(client_data)`, where client_data is JSON
whose `challenge` is sha256 of the statement. devd checks them with the
`cryptography` package alone; python-fido2 is only needed by the human's
side, to talk to the device.

Shared by both planes: the server signs with it, devd verifies with it.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from common.canonical import canonicalize, content_hash

STATEMENT_KIND = "mcp-devvm-approval"
STATEMENT_VERSION = 1
DEFAULT_TTL_S = 600

# How long an APPROVED request may wait to start running. The store sets it
# when the last approval arrives; signatures must stay valid until then.
EXECUTION_WINDOW_S = 120

log = logging.getLogger(__name__)

# Risk classes that need two distinct human approvers no matter what the
# control plane's policy file says (devd enforces this on its own).
FOUR_EYES_RISKS = frozenset({"DESTRUCTIVE", "PRIVILEGE"})

APPROVER_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")

# The WebAuthn relying party and origin approvals are made for. Not a real
# site: they only scope the credential, so a key enrolled here can't be
# asked to sign for anything else and vice versa.
FIDO_RP_ID = "mcp-devvm.invalid"
FIDO_ORIGIN = "https://mcp-devvm.invalid"

SCHEME_PASSPHRASE = "ed25519"
SCHEME_FIDO2 = "fido2"

# WebAuthn authenticator data flags.
_FLAG_UP = 0x01  # user present (touched)
_FLAG_UV = 0x04  # user verified (PIN or biometric)


def approver_user(approver: str) -> str:
    """The principal (`os:<user>`) an approver key belongs to."""
    return f"os:{approver}"


class ApprovalSignatureError(Exception):
    pass


@dataclass(frozen=True)
class SignedApproval:
    approver: str
    not_after: int
    sig: str  # base64 signature
    scheme: str = SCHEME_PASSPHRASE
    # FIDO2 only, base64: what the authenticator signed, together with sig.
    authenticator_data: str | None = None
    client_data: str | None = None

    def as_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"approver": self.approver, "not_after": self.not_after, "sig": self.sig}
        if self.scheme != SCHEME_PASSPHRASE:
            d.update(scheme=self.scheme, authenticator_data=self.authenticator_data, client_data=self.client_data)
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> SignedApproval:
        try:
            approver, not_after, sig = d["approver"], d["not_after"], d["sig"]
            scheme = d.get("scheme", SCHEME_PASSPHRASE)
        except (KeyError, TypeError, AttributeError) as exc:
            raise ApprovalSignatureError("malformed signed approval") from exc
        if (not isinstance(approver, str) or type(not_after) is not int or not isinstance(sig, str)
                or scheme not in (SCHEME_PASSPHRASE, SCHEME_FIDO2)):
            raise ApprovalSignatureError("malformed signed approval")
        auth_data = client_data = None
        if scheme == SCHEME_FIDO2:
            auth_data, client_data = d.get("authenticator_data"), d.get("client_data")
            if not isinstance(auth_data, str) or not isinstance(client_data, str):
                raise ApprovalSignatureError("malformed signed approval")
        return cls(approver=approver, not_after=not_after, sig=sig, scheme=scheme,
                   authenticator_data=auth_data, client_data=client_data)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


@dataclass(frozen=True)
class FidoCredential:
    """An approver's enrolled security-key credential: the public key, and
    the credential id the device needs to find its private key."""
    credential_id: bytes
    public_key: Any  # EllipticCurvePublicKey (P-256) or Ed25519PublicKey
    user_verification: bool  # require the PIN flag, not just a touch
    rp_id: str = FIDO_RP_ID

    def to_json(self) -> str:
        pem = self.public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        return json.dumps({
            "kind": "fido2", "rp_id": self.rp_id, "credential_id": _b64url(self.credential_id),
            "public_key": pem.decode("ascii"), "user_verification": self.user_verification,
        }, indent=2) + "\n"

    @classmethod
    def from_json(cls, text: str | bytes) -> FidoCredential:
        try:
            d = json.loads(text)
            if d.get("kind") != "fido2" or d.get("rp_id") != FIDO_RP_ID:
                raise ValueError("not a credential for this relying party")
            key = serialization.load_pem_public_key(d["public_key"].encode("ascii"))
            if not (isinstance(key, Ed25519PublicKey)
                    or (isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1))):
                raise ValueError("unsupported key type (need P-256 or Ed25519)")
            uv = d["user_verification"]
            if not isinstance(uv, bool):
                raise ValueError("user_verification must be true or false")
            return cls(credential_id=_b64url_decode(d["credential_id"]), public_key=key, user_verification=uv)
        except (KeyError, TypeError, AttributeError, UnicodeError) as exc:
            raise ValueError(f"malformed credential file: {exc}") from exc

    def same_key(self, other: FidoCredential) -> bool:
        return self.to_json() == other.to_json()


def fido_challenge(statement: bytes) -> bytes:
    return hashlib.sha256(statement).digest()


def check_fido_assertion(
    cred: FidoCredential, statement: bytes, *, authenticator_data: bytes, client_data: bytes, signature: bytes,
) -> None:
    """Raises ValueError unless this is a WebAuthn assertion by `cred`, for
    our relying party, over `statement`, with the touch (and PIN, if the
    credential was enrolled with one) flags set."""
    try:
        cd = json.loads(client_data)
    except ValueError as exc:
        raise ValueError("client_data is not JSON") from exc
    if not isinstance(cd, dict) or cd.get("type") != "webauthn.get":
        raise ValueError("client_data is not an assertion")
    if cd.get("challenge") != _b64url(fido_challenge(statement)):
        raise ValueError("signed a different statement")
    if cd.get("origin") != FIDO_ORIGIN or cd.get("crossOrigin") not in (None, False):
        raise ValueError("wrong origin")
    if len(authenticator_data) < 37:
        raise ValueError("authenticator_data too short")
    if authenticator_data[:32] != hashlib.sha256(cred.rp_id.encode()).digest():
        raise ValueError("wrong relying party")
    flags = authenticator_data[32]
    if not flags & _FLAG_UP:
        raise ValueError("user_not_present")
    if cred.user_verification and not flags & _FLAG_UV:
        raise ValueError("user_not_verified")
    signed = authenticator_data + hashlib.sha256(client_data).digest()
    try:
        if isinstance(cred.public_key, Ed25519PublicKey):
            cred.public_key.verify(signature, signed)
        else:
            cred.public_key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise ValueError("bad signature") from exc


def effect_hash(effect: dict[str, Any]) -> str:
    return content_hash(effect)


def statement_bytes(*, approval_id: str, proposal_hash: str, effect_hash: str, approver: str, not_after: int) -> bytes:
    return canonicalize({
        "kind": STATEMENT_KIND,
        "v": STATEMENT_VERSION,
        "approval_id": approval_id,
        "proposal_hash": proposal_hash,
        "effect_hash": effect_hash,
        "approver": approver,
        "not_after": not_after,
    })


def sign_approval(
    private_key: Ed25519PrivateKey, *, approver: str, approval_id: str, proposal_hash: str,
    effect_hash: str, ttl_s: int = DEFAULT_TTL_S, not_after: int | None = None, now: float | None = None,
) -> SignedApproval:
    """`not_after` wins over `ttl_s` when given. `decide` passes the
    approval's own deadline (see signature_deadline), so the first of two
    four-eyes signatures can't expire while the request is still open."""
    if not_after is None:
        not_after = int(now if now is not None else time.time()) + ttl_s
    msg = statement_bytes(
        approval_id=approval_id, proposal_hash=proposal_hash, effect_hash=effect_hash,
        approver=approver, not_after=not_after,
    )
    sig = base64.b64encode(private_key.sign(msg)).decode("ascii")
    return SignedApproval(approver=approver, not_after=not_after, sig=sig)


def fido_signed_approval(*, approver: str, not_after: int, signed: dict[str, bytes]) -> SignedApproval:
    """Package what scripts/fido.sign_statement returned."""
    b64 = lambda b: base64.b64encode(b).decode("ascii")
    return SignedApproval(
        approver=approver, not_after=not_after, sig=b64(signed["signature"]), scheme=SCHEME_FIDO2,
        authenticator_data=b64(signed["authenticator_data"]), client_data=b64(signed["client_data"]),
    )


def verify_approvals(
    signed: list[dict[str, Any]], *, public_keys: dict[str, Ed25519PublicKey | FidoCredential], approval_id: str,
    proposal_hash: str, effect_hash: str, required: int, requester: str, now: float | None = None,
) -> list[str]:
    """Returns the distinct approvers whose signatures verified. Raises
    ApprovalSignatureError unless at least `required` distinct approvers did.
    Invalid entries are not skipped silently: any bad signature fails the
    whole request, since a forged entry is itself a security event.

    When `required` > 1 (four-eyes), a signature by the requester's own key
    is refused too, so the requester can neither approve nor fill one of
    the two slots."""
    now = now if now is not None else time.time()
    approvers: set[str] = set()
    for raw in signed:
        sa = SignedApproval.from_dict(raw)
        key = public_keys.get(sa.approver)
        if key is None:
            raise ApprovalSignatureError(f"unknown_approver:{sa.approver}")
        if now > sa.not_after:
            raise ApprovalSignatureError(f"approval_signature_expired:{sa.approver}")
        msg = statement_bytes(
            approval_id=approval_id, proposal_hash=proposal_hash, effect_hash=effect_hash,
            approver=sa.approver, not_after=sa.not_after,
        )
        # The scheme must match how the key was enrolled: a security-key
        # approver can't be satisfied by a software signature, or vice versa.
        try:
            if isinstance(key, FidoCredential):
                if sa.scheme != SCHEME_FIDO2:
                    raise ValueError("scheme_mismatch")
                check_fido_assertion(
                    key, msg, authenticator_data=base64.b64decode(sa.authenticator_data or "", validate=True),
                    client_data=base64.b64decode(sa.client_data or "", validate=True),
                    signature=base64.b64decode(sa.sig, validate=True),
                )
            else:
                if sa.scheme != SCHEME_PASSPHRASE:
                    raise ValueError("scheme_mismatch")
                key.verify(base64.b64decode(sa.sig, validate=True), msg)
        except (InvalidSignature, ValueError) as exc:
            raise ApprovalSignatureError(f"bad_approval_signature:{sa.approver}:{exc}") from exc
        if required > 1 and approver_user(sa.approver) == requester:
            raise ApprovalSignatureError(f"self_approval:{sa.approver}")
        approvers.add(sa.approver)
    if len(approvers) < required:
        raise ApprovalSignatureError(f"approval_signatures_required:{required}:got:{len(approvers)}")
    return sorted(approvers)


def signature_deadline(approval_expires_at: float) -> int:
    """The latest moment a signature on this approval can be needed: the
    last approval may arrive just before the decision window closes, and the
    run then has EXECUTION_WINDOW_S to start."""
    return int(approval_expires_at) + EXECUTION_WINDOW_S + 1


def required_approvers(risk: str, requested: int = 1) -> int:
    floor = 2 if risk in FOUR_EYES_RISKS else 1
    return max(floor, requested)


def load_public_keys(directory: Path) -> dict[str, Ed25519PublicKey | FidoCredential]:
    """`<approver>.fido` (security key, JSON) and `<approver>.pub`
    (passphrase key, PEM) files. Read fresh on every call so a key added or
    removed on the VM takes effect without restarting devd.

    A file that can't be read or parsed is skipped with a warning, so one
    bad file doesn't block every other approver. An approver with both
    kinds of file is skipped entirely: one key per person, and guessing
    which one is meant could pick the weaker one."""
    keys: dict[str, Ed25519PublicKey | FidoCredential] = {}
    if not directory.is_dir():
        return keys
    conflicts: set[str] = set()
    for path in sorted([*directory.glob("*.fido"), *directory.glob("*.pub")]):
        name = path.stem
        if not APPROVER_NAME_RE.match(name):
            continue
        try:
            if path.suffix == ".fido":
                key: Ed25519PublicKey | FidoCredential = FidoCredential.from_json(path.read_bytes())
            else:
                pem_key = serialization.load_pem_public_key(path.read_bytes())
                if not isinstance(pem_key, Ed25519PublicKey):
                    log.warning("skipping approver key %s: not an Ed25519 public key", path)
                    continue
                key = pem_key
        except (OSError, ValueError, TypeError) as exc:
            log.warning("skipping unreadable approver key %s: %s", path, exc)
            continue
        if name in keys:
            conflicts.add(name)
        keys[name] = key
    for name in conflicts:
        log.warning("skipping approver %s: has both a .fido and a .pub key", name)
        del keys[name]
    return keys
