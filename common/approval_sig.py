"""Human approval signatures, checked by devd (closes ROADMAP Known gap #4).

The approval store and the token-signing key both live on the MCP server
host, where an agent with a shell running as the same OS user can read or
write them. So neither one can be what proves a human said yes. Instead:

  - each approver has an Ed25519 key whose private half is encrypted with a
    passphrase that only the human knows (scripts/approver_keys.py);
  - `decide approve` asks for that passphrase and signs a statement binding
    the approval id, the proposal hash, the hash of the effect text the human
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

Shared by both planes: the server signs with it, devd verifies with it.
"""

from __future__ import annotations

import base64
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from common.canonical import canonicalize, content_hash

STATEMENT_KIND = "mcp-devvm-approval"
STATEMENT_VERSION = 1
DEFAULT_TTL_S = 600

# Risk classes that need two distinct human approvers no matter what the
# control plane's policy file says (devd enforces this on its own).
FOUR_EYES_RISKS = frozenset({"DESTRUCTIVE", "PRIVILEGE"})

APPROVER_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")


def approver_user(approver: str) -> str:
    """The principal (`os:<user>`) an approver key belongs to."""
    return f"os:{approver}"


class ApprovalSignatureError(Exception):
    pass


@dataclass(frozen=True)
class SignedApproval:
    approver: str
    not_after: int
    sig: str  # base64 Ed25519 signature over statement_bytes(...)

    def as_dict(self) -> dict[str, Any]:
        return {"approver": self.approver, "not_after": self.not_after, "sig": self.sig}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SignedApproval":
        try:
            approver, not_after, sig = d["approver"], d["not_after"], d["sig"]
        except (KeyError, TypeError) as exc:
            raise ApprovalSignatureError("malformed signed approval") from exc
        if not isinstance(approver, str) or not isinstance(not_after, int) or not isinstance(sig, str):
            raise ApprovalSignatureError("malformed signed approval")
        return cls(approver=approver, not_after=not_after, sig=sig)


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
    effect_hash: str, ttl_s: int = DEFAULT_TTL_S, now: float | None = None,
) -> SignedApproval:
    not_after = int(now if now is not None else time.time()) + ttl_s
    msg = statement_bytes(
        approval_id=approval_id, proposal_hash=proposal_hash, effect_hash=effect_hash,
        approver=approver, not_after=not_after,
    )
    sig = base64.b64encode(private_key.sign(msg)).decode("ascii")
    return SignedApproval(approver=approver, not_after=not_after, sig=sig)


def verify_approvals(
    signed: list[dict[str, Any]], *, public_keys: dict[str, Ed25519PublicKey], approval_id: str,
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
        try:
            key.verify(base64.b64decode(sa.sig, validate=True), msg)
        except (InvalidSignature, ValueError) as exc:
            raise ApprovalSignatureError(f"bad_approval_signature:{sa.approver}") from exc
        if required > 1 and approver_user(sa.approver) == requester:
            raise ApprovalSignatureError(f"self_approval:{sa.approver}")
        approvers.add(sa.approver)
    if len(approvers) < required:
        raise ApprovalSignatureError(f"approval_signatures_required:{required}:got:{len(approvers)}")
    return sorted(approvers)


def required_approvers(risk: str, requested: int = 1) -> int:
    floor = 2 if risk in FOUR_EYES_RISKS else 1
    return max(floor, requested)


def load_public_keys(directory: Path) -> dict[str, Ed25519PublicKey]:
    """`<approver>.pub` files in PEM form. Read fresh on every call so a key
    added or removed on the VM takes effect without restarting devd."""
    keys: dict[str, Ed25519PublicKey] = {}
    if not directory.is_dir():
        return keys
    for path in sorted(directory.glob("*.pub")):
        name = path.stem
        if not APPROVER_NAME_RE.match(name):
            continue
        key = serialization.load_pem_public_key(path.read_bytes())
        if isinstance(key, Ed25519PublicKey):
            keys[name] = key
    return keys
