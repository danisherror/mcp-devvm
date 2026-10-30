"""Signed human approvals (common/approval_sig.py) and devd's check of them."""

from __future__ import annotations

import time
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from common.approval_sig import (
    EXECUTION_WINDOW_S,
    ApprovalSignatureError,
    approver_user,
    effect_hash,
    load_public_keys,
    required_approvers,
    sign_approval,
    signature_deadline,
    verify_approvals,
)
from scripts.approver_keys import (
    create_approver_key,
    current_approver_name,
    enroll_approver_key,
    enrolled_key_matches,
    load_private_key,
    untrusted_dir_reason,
)

APPROVAL_ID = "appr_0123456789abcdef"
PHASH = "a" * 64
EHASH = "b" * 64


@pytest.fixture
def alice():
    return Ed25519PrivateKey.generate()


@pytest.fixture
def bob():
    return Ed25519PrivateKey.generate()


def _sign(key, name="alice", **kw):
    args = dict(approver=name, approval_id=APPROVAL_ID, proposal_hash=PHASH, effect_hash=EHASH)
    args.update(kw)
    return sign_approval(key, **args).as_dict()


def _verify(signed, keys, **kw):
    args = dict(public_keys=keys, approval_id=APPROVAL_ID, proposal_hash=PHASH, effect_hash=EHASH, required=1,
                requester="os:requester")
    args.update(kw)
    return verify_approvals(signed, **args)


class TestVerify:
    def test_valid_signature_verifies(self, alice):
        assert _verify([_sign(alice)], {"alice": alice.public_key()}) == ["alice"]

    def test_no_signature_is_rejected(self, alice):
        with pytest.raises(ApprovalSignatureError, match="required"):
            _verify([], {"alice": alice.public_key()})

    @pytest.mark.parametrize("field,value", [
        ("approval_id", "appr_ffffffffffffffff"),
        ("proposal_hash", "c" * 64),
        ("effect_hash", "d" * 64),
    ])
    def test_signature_is_bound_to_each_field(self, alice, field, value):
        with pytest.raises(ApprovalSignatureError, match="bad_approval_signature"):
            _verify([_sign(alice)], {"alice": alice.public_key()}, **{field: value})

    def test_unknown_approver_is_rejected(self, alice):
        with pytest.raises(ApprovalSignatureError, match="unknown_approver"):
            _verify([_sign(alice, name="mallory")], {"alice": alice.public_key()})

    def test_signature_under_another_name_is_rejected(self, alice, bob):
        # bob's key signing a statement that claims to be from alice
        with pytest.raises(ApprovalSignatureError, match="bad_approval_signature"):
            _verify([_sign(bob, name="alice")], {"alice": alice.public_key()})

    def test_extended_expiry_is_rejected(self, alice):
        signed = _sign(alice)
        signed["not_after"] += 3600  # not_after is inside the signed statement
        with pytest.raises(ApprovalSignatureError, match="bad_approval_signature"):
            _verify([signed], {"alice": alice.public_key()})

    def test_expired_signature_is_rejected(self, alice):
        signed = _sign(alice, ttl_s=10, now=time.time() - 100)
        with pytest.raises(ApprovalSignatureError, match="expired"):
            _verify([signed], {"alice": alice.public_key()})

    def test_four_eyes_needs_two_distinct_approvers(self, alice, bob):
        keys = {"alice": alice.public_key(), "bob": bob.public_key()}
        with pytest.raises(ApprovalSignatureError, match="required:2:got:1"):
            _verify([_sign(alice), _sign(alice)], keys, required=2)
        assert _verify([_sign(alice), _sign(bob, name="bob")], keys, required=2) == ["alice", "bob"]

    def test_requester_cannot_approve_four_eyes(self, alice, bob):
        keys = {"alice": alice.public_key(), "bob": bob.public_key()}
        signed = [_sign(alice), _sign(bob, name="bob")]
        with pytest.raises(ApprovalSignatureError, match="self_approval:alice"):
            _verify(signed, keys, required=2, requester="os:alice")
        assert _verify(signed, keys, required=2, requester="os:carol") == ["alice", "bob"]

    def test_requester_may_approve_single_approval(self, alice):
        # Local topology: the agent runs as the human's OS user, so the
        # requester is the approver for every ordinary approval.
        assert _verify([_sign(alice)], {"alice": alice.public_key()}, requester="os:alice") == ["alice"]

    def test_key_name_is_the_owner(self):
        assert approver_user("alice") == "os:alice"

    def test_malformed_entry_is_rejected(self, alice):
        with pytest.raises(ApprovalSignatureError, match="malformed"):
            _verify([{"approver": "alice"}], {"alice": alice.public_key()})

    def test_signature_outlives_the_approval_window(self, alice, bob):
        # Four-eyes: alice signs as soon as the request opens (900s window),
        # bob signs at the last second, and the run starts at the end of the
        # execution window. alice's signature must still be valid then.
        opened = time.time() - 900 - EXECUTION_WINDOW_S
        expires_at = opened + 900
        deadline = signature_deadline(expires_at)
        first = _sign(alice, not_after=deadline, now=opened)
        second = _sign(bob, "bob", not_after=deadline, now=expires_at)
        keys = {"alice": alice.public_key(), "bob": bob.public_key()}
        assert _verify([first, second], keys, required=2) == ["alice", "bob"]

    def test_signature_expires_after_the_execution_window(self, alice):
        expires_at = time.time() - EXECUTION_WINDOW_S - 10
        signed = _sign(alice, not_after=signature_deadline(expires_at))
        with pytest.raises(ApprovalSignatureError, match="expired"):
            _verify([signed], {"alice": alice.public_key()})

    def test_destructive_always_needs_two(self):
        assert required_approvers("MUTATING_LOCAL") == 1
        assert required_approvers("DESTRUCTIVE") == 2
        assert required_approvers("PRIVILEGE", requested=1) == 2


class TestKeyFiles:
    def test_roundtrip_with_passphrase(self, tmp_path):
        trusted = tmp_path / "trusted"
        create_approver_key("alice", "correct horse battery", tmp_path)
        enroll_approver_key("alice", "correct horse battery", base=tmp_path, trusted=trusted)
        key = load_private_key("alice", "correct horse battery", tmp_path)
        assert set(load_public_keys(trusted)) == {"alice"}
        assert enrolled_key_matches("alice", key, trusted)
        signed = sign_approval(key, approver="alice", approval_id=APPROVAL_ID, proposal_hash=PHASH, effect_hash=EHASH)
        assert _verify([signed.as_dict()], load_public_keys(trusted)) == ["alice"]

    def test_malformed_public_key_is_skipped(self, tmp_path, caplog):
        trusted = tmp_path / "trusted"
        create_approver_key("alice", "correct horse battery", tmp_path)
        enroll_approver_key("alice", "correct horse battery", base=tmp_path, trusted=trusted)
        (trusted / "bob.pub").write_text("not a key")
        assert set(load_public_keys(trusted)) == {"alice"}
        assert "bob.pub" in caplog.text

    def test_init_does_not_make_the_key_trusted(self, tmp_path):
        create_approver_key("alice", "correct horse battery", tmp_path)
        assert list(tmp_path.rglob("*.pub")) == []

    def test_enroll_needs_the_passphrase(self, tmp_path):
        create_approver_key("alice", "correct horse battery", tmp_path)
        with pytest.raises(ValueError):
            enroll_approver_key("alice", "wrong", base=tmp_path, trusted=tmp_path / "trusted")
        assert not (tmp_path / "trusted" / "alice.pub").exists()

    def test_enroll_derives_the_public_key_from_the_private_key(self, tmp_path, alice):
        # A swapped .pub lying around in the repo doesn't get enrolled: the
        # trusted key always comes from the key the passphrase unlocked.
        (tmp_path / "public").mkdir()
        (tmp_path / "public" / "alice.pub").write_bytes(alice.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        create_approver_key("alice", "correct horse battery", tmp_path)
        enroll_approver_key("alice", "correct horse battery", base=tmp_path, trusted=tmp_path / "trusted")
        mine = load_private_key("alice", "correct horse battery", tmp_path)
        assert enrolled_key_matches("alice", mine, tmp_path / "trusted")
        assert not enrolled_key_matches("alice", alice, tmp_path / "trusted")

    def test_one_enrolled_key_per_user_unless_replaced(self, tmp_path):
        trusted = tmp_path / "trusted"
        create_approver_key("alice", "correct horse battery", tmp_path)
        enroll_approver_key("alice", "correct horse battery", base=tmp_path, trusted=trusted)
        with pytest.raises(FileExistsError):
            enroll_approver_key("alice", "correct horse battery", base=tmp_path, trusted=trusted)
        enroll_approver_key("alice", "correct horse battery", base=tmp_path, trusted=trusted, replace=True)

    def test_user_writable_dir_is_not_trusted(self, tmp_path):
        assert "not owned by root" in untrusted_dir_reason(tmp_path)
        assert untrusted_dir_reason(Path("/usr/bin")) is None

    def test_wrong_passphrase_fails(self, tmp_path):
        create_approver_key("alice", "correct horse battery", tmp_path)
        with pytest.raises(ValueError):
            load_private_key("alice", "wrong", tmp_path)

    def test_private_key_is_encrypted_and_private(self, tmp_path):
        priv = create_approver_key("alice", "correct horse battery", tmp_path)
        assert b"ENCRYPTED PRIVATE KEY" in priv.read_bytes()
        assert priv.stat().st_mode & 0o077 == 0

    def test_approver_name_is_the_os_user(self, monkeypatch):
        import getpass

        monkeypatch.setattr(getpass, "getuser", lambda: "alice")
        assert current_approver_name() == "alice"
        # Not lower-cased: it must equal the user part of "os:<user>" exactly.
        monkeypatch.setattr(getpass, "getuser", lambda: "Alice")
        with pytest.raises(ValueError):
            current_approver_name()

    def test_one_key_per_user(self, tmp_path):
        create_approver_key("alice", "correct horse battery", tmp_path)
        with pytest.raises(FileExistsError):
            create_approver_key("alice", "another passphrase!", tmp_path)

    def test_empty_passphrase_and_bad_names_refused(self, tmp_path):
        with pytest.raises(ValueError):
            create_approver_key("alice", "", tmp_path)
        with pytest.raises(ValueError):
            create_approver_key("../evil", "correct horse battery", tmp_path)


class TestDevdEnforcement:
    """devd's /run endpoint must refuse approval-required operations without
    a valid human signature, even when the server token itself is valid --
    that token's signing key is readable by anything on the server host."""

    @pytest.fixture
    def client(self, tmp_path, monkeypatch):
        from fastapi.testclient import TestClient

        import devd.auth
        from devd import app as devd_app
        from devd import config

        token_key = Ed25519PrivateKey.generate()
        monkeypatch.setattr(devd.auth, "_public_key", token_key.public_key())
        approvers = tmp_path / "approvers"
        approvers.mkdir()
        monkeypatch.setattr(config, "APPROVERS_DIR", approvers)
        return TestClient(devd_app.app), token_key, approvers

    @staticmethod
    def _token(key, *, operation_id="git.checkout", approval_id=APPROVAL_ID):
        from devd import config

        return jwt.encode({
            "sub": "os:someone", "approval_id": approval_id, "operation_id": operation_id,
            "manifest_ver": 1, "aud": config.AUDIENCE_PREFIX + config.TARGET_ID, "exp": int(time.time()) + 60,
        }, key, algorithm="EdDSA")

    @staticmethod
    def _body(**extra):
        from devd.app import registry

        op = registry.get("git.checkout")
        body = {"params": {"repo": "api", "branch": "main"}, "preconditions": {},
                "manifest_version": op.version, "manifest_hash": op.content_hash}
        body.update(extra)
        return body

    def test_valid_token_without_signature_is_refused(self, client):
        c, token_key, _ = client
        resp = c.post("/operations/git.checkout/run", json=self._body(),
                      headers={"Authorization": f"Bearer {self._token(token_key)}", "Idempotency-Key": APPROVAL_ID})
        assert resp.status_code == 403
        assert resp.json()["detail"].startswith("approval_signature_invalid")

    def test_non_approval_token_is_refused(self, client):
        c, token_key, _ = client
        tok = self._token(token_key, approval_id="n/a:direct-read")
        resp = c.post("/operations/git.checkout/run", json=self._body(),
                      headers={"Authorization": f"Bearer {tok}", "Idempotency-Key": "direct_x"})
        assert resp.status_code == 403
        assert resp.json()["detail"] == "approval_required"

    def test_signature_for_different_params_is_refused(self, client):
        from devd.app import PROPOSAL_SCHEMA_VERSION, registry
        from devd import config
        from common.canonical import proposal_hash

        c, token_key, approvers = client
        human = Ed25519PrivateKey.generate()
        (approvers / "alice.pub").write_bytes(human.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        op = registry.get("git.checkout")
        approved_params = {"repo": "api", "branch": "main"}
        h = proposal_hash(v=PROPOSAL_SCHEMA_VERSION, principal="os:someone", target_id=config.TARGET_ID,
                          operation_id=op.id, manifest_version=op.version, manifest_hash=op.content_hash,
                          params=approved_params, preconditions={})
        signed = sign_approval(human, approver="alice", approval_id=APPROVAL_ID, proposal_hash=h,
                               effect_hash=effect_hash(op.effect.render(approved_params)))
        # The human approved branch "main"; the request asks for another branch.
        body = self._body(approvals=[signed.as_dict()])
        body["params"] = {"repo": "api", "branch": "evil"}
        resp = c.post("/operations/git.checkout/run", json=body,
                      headers={"Authorization": f"Bearer {self._token(token_key)}", "Idempotency-Key": APPROVAL_ID})
        assert resp.status_code == 403
        assert "bad_approval_signature" in resp.json()["detail"]

    def test_read_only_operation_needs_no_signature(self, client):
        from devd.app import registry

        c, token_key, _ = client
        op = registry.get("git.status")
        tok = self._token(token_key, operation_id="git.status", approval_id="n/a:direct-read")
        resp = c.post("/operations/git.status/run",
                      json={"params": {"repo": "api"}, "preconditions": {},
                            "manifest_version": op.version, "manifest_hash": op.content_hash},
                      headers={"Authorization": f"Bearer {tok}", "Idempotency-Key": "direct_y"})
        assert resp.status_code != 403


class TestKeyLocation:
    """Each approver's key lives in their own home directory."""

    @pytest.fixture
    def homes(self, tmp_path, monkeypatch):
        import os
        import pwd

        import scripts.approver_keys as ak

        def fake_getpwnam(name):
            if name not in ("alice", "bob"):
                raise KeyError(name)
            return type("P", (), {"pw_dir": str(tmp_path / "home" / name), "pw_uid": os.getuid()})()

        monkeypatch.setattr(pwd, "getpwnam", fake_getpwnam)
        monkeypatch.setattr(ak, "LEGACY_APPROVERS_DIR", tmp_path / "repo" / "data" / "approvers")
        return tmp_path

    def test_new_keys_go_in_the_users_home(self, homes):
        from scripts.approver_keys import private_key_path

        path = create_approver_key("bob", "correct horse battery")
        assert path == homes / "home" / "bob" / ".mcp-devvm" / "approver" / "bob.key"
        assert private_key_path("bob") == path
        assert (path.parent.stat().st_mode & 0o777) == 0o700
        assert load_private_key("bob", "correct horse battery") is not None

    def test_old_repo_key_is_still_found(self, homes):
        from scripts.approver_keys import private_key_path

        legacy = create_approver_key("alice", "correct horse battery", homes / "repo" / "data" / "approvers")
        assert private_key_path("alice") == legacy
        with pytest.raises(FileExistsError):
            create_approver_key("alice", "correct horse battery")  # still one key per user

    def test_symlinked_key_is_refused(self, homes):
        from scripts.approver_keys import home_key_path

        real = create_approver_key("alice", "correct horse battery", homes / "elsewhere")
        link = home_key_path("alice")
        link.parent.mkdir(parents=True)
        link.symlink_to(real)
        with pytest.raises(OSError):
            load_private_key("alice", "correct horse battery")

    def test_key_owned_by_someone_else_is_refused(self, homes):
        import os

        create_approver_key("bob", "correct horse battery")
        with pytest.raises(ValueError, match="not owned"):
            load_private_key("bob", "correct horse battery", owner_uid=os.getuid() + 1)
