"""Security-key (FIDO2) approvals: devd's verification, and init -> enroll
-> sign through the real python-fido2 client against a software key
(tests/soft_fido.py)."""

from __future__ import annotations

import base64
import getpass
import hashlib
import json
import time
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from common.approval_sig import (
    FIDO_ORIGIN,
    FIDO_RP_ID,
    ApprovalSignatureError,
    FidoCredential,
    check_fido_assertion,
    fido_challenge,
    fido_signed_approval,
    load_public_keys,
    sign_approval,
    statement_bytes,
    verify_approvals,
)
from scripts import fido
from scripts.approver_keys import (
    create_approver_key,
    create_fido_credential,
    enroll_approver_key,
    enroll_fido_credential,
    enrolled_kind,
    fido_credential_path,
    load_enrolled_credential,
)
from tests.soft_fido import SoftAuthenticator, client_for

APPROVAL_ID = "appr_0123456789abcdef"
PHASH = "a" * 64
EHASH = "b" * 64
PIN = "4321"


@pytest.fixture(autouse=True)
def pin_prompt(monkeypatch):
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": PIN)


def _statement(approver="alice", not_after=None):
    not_after = not_after or int(time.time()) + 600
    return not_after, statement_bytes(approval_id=APPROVAL_ID, proposal_hash=PHASH, effect_hash=EHASH,
                                      approver=approver, not_after=not_after)


def _verify(signed, keys, **kw):
    args = dict(public_keys=keys, approval_id=APPROVAL_ID, proposal_hash=PHASH, effect_hash=EHASH, required=1,
                requester="os:requester")
    args.update(kw)
    return verify_approvals(signed, **args)


# ── devd's check of a WebAuthn assertion, with hand-built assertions ────────

def _assertion(key, statement, *, flags=0x05, rp_id=FIDO_RP_ID, origin=FIDO_ORIGIN, typ="webauthn.get",
               challenge=None):
    client_data = json.dumps({
        "type": typ, "origin": origin,
        "challenge": base64.urlsafe_b64encode(challenge or fido_challenge(statement)).rstrip(b"=").decode(),
    }).encode()
    auth_data = hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + (7).to_bytes(4, "big")
    msg = auth_data + hashlib.sha256(client_data).digest()
    sig = key.sign(msg) if isinstance(key, Ed25519PrivateKey) else key.sign(msg, ec.ECDSA(hashes.SHA256()))
    return {"authenticator_data": auth_data, "client_data": client_data, "signature": sig}


@pytest.fixture(params=["p256", "ed25519"])
def device_key(request):
    return ec.generate_private_key(ec.SECP256R1()) if request.param == "p256" else Ed25519PrivateKey.generate()


def _cred(key, uv=True):
    return FidoCredential(credential_id=b"cred-1", public_key=key.public_key(), user_verification=uv)


class TestAssertionCheck:
    def test_valid_assertion(self, device_key):
        _, st = _statement()
        check_fido_assertion(_cred(device_key), st, **_assertion(device_key, st))

    @pytest.mark.parametrize("kw,reason", [
        (dict(challenge=b"\x00" * 32), "different statement"),
        (dict(origin="https://evil.example"), "wrong origin"),
        (dict(typ="webauthn.create"), "not an assertion"),
        (dict(rp_id="evil.example"), "wrong relying party"),
        (dict(flags=0x04), "user_not_present"),
        (dict(flags=0x01), "user_not_verified"),
    ])
    def test_rejected(self, device_key, kw, reason):
        _, st = _statement()
        with pytest.raises(ValueError, match=reason):
            check_fido_assertion(_cred(device_key), st, **_assertion(device_key, st, **kw))

    def test_touch_only_is_enough_without_pin_requirement(self, device_key):
        _, st = _statement()
        check_fido_assertion(_cred(device_key, uv=False), st, **_assertion(device_key, st, flags=0x01))

    def test_tampered_authenticator_data(self, device_key):
        _, st = _statement()
        a = _assertion(device_key, st)
        a["authenticator_data"] = a["authenticator_data"][:33] + (8).to_bytes(4, "big")
        with pytest.raises(ValueError, match="bad signature"):
            check_fido_assertion(_cred(device_key), st, **a)

    def test_another_keys_signature(self, device_key):
        _, st = _statement()
        other = ec.generate_private_key(ec.SECP256R1())
        with pytest.raises(ValueError):
            check_fido_assertion(_cred(device_key), st, **_assertion(other, st))


class TestVerifyApprovals:
    def test_fido_signature_verifies(self, device_key):
        not_after, st = _statement()
        signed = fido_signed_approval(approver="alice", not_after=not_after, signed=_assertion(device_key, st))
        assert _verify([signed.as_dict()], {"alice": _cred(device_key)}) == ["alice"]

    def test_extended_expiry_is_rejected(self, device_key):
        not_after, st = _statement()
        signed = fido_signed_approval(approver="alice", not_after=not_after + 3600, signed=_assertion(device_key, st))
        with pytest.raises(ApprovalSignatureError, match="different statement"):
            _verify([signed.as_dict()], {"alice": _cred(device_key)})

    def test_software_signature_cant_stand_in_for_a_security_key(self):
        # Even with a matching Ed25519 key: the enrolled kind decides the scheme.
        key = Ed25519PrivateKey.generate()
        signed = sign_approval(key, approver="alice", approval_id=APPROVAL_ID, proposal_hash=PHASH, effect_hash=EHASH)
        with pytest.raises(ApprovalSignatureError, match="scheme_mismatch"):
            _verify([signed.as_dict()], {"alice": _cred(key)})

    def test_security_key_signature_cant_match_a_passphrase_key(self):
        key = Ed25519PrivateKey.generate()
        not_after, st = _statement()
        signed = fido_signed_approval(approver="alice", not_after=not_after, signed=_assertion(key, st))
        with pytest.raises(ApprovalSignatureError, match="scheme_mismatch"):
            _verify([signed.as_dict()], {"alice": key.public_key()})

    @pytest.mark.parametrize("change", [{"scheme": "rot13"}, {"authenticator_data": None}, {"client_data": 5}])
    def test_malformed_fido_entry(self, device_key, change):
        not_after, st = _statement()
        d = fido_signed_approval(approver="alice", not_after=not_after, signed=_assertion(device_key, st)).as_dict()
        d.update(change)
        with pytest.raises(ApprovalSignatureError, match="malformed"):
            _verify([d], {"alice": _cred(device_key)})


class TestCredentialFiles:
    def test_roundtrip(self, device_key):
        cred = _cred(device_key)
        assert FidoCredential.from_json(cred.to_json()).same_key(cred)

    @pytest.mark.parametrize("change", [
        {"kind": "ssh"}, {"rp_id": "evil.example"}, {"user_verification": "yes"}, {"public_key": "nope"},
    ])
    def test_malformed(self, device_key, change):
        d = json.loads(_cred(device_key).to_json())
        d.update(change)
        with pytest.raises(ValueError):
            FidoCredential.from_json(json.dumps(d))

    def test_rsa_and_other_curves_refused(self):
        from cryptography.hazmat.primitives import serialization

        d = json.loads(_cred(ec.generate_private_key(ec.SECP256R1())).to_json())
        d["public_key"] = ec.generate_private_key(ec.SECP384R1()).public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        with pytest.raises(ValueError, match="unsupported"):
            FidoCredential.from_json(json.dumps(d))

    def test_trusted_dir_loads_both_kinds_and_skips_conflicts(self, tmp_path, caplog):
        trusted = tmp_path / "trusted"
        trusted.mkdir()
        p256 = ec.generate_private_key(ec.SECP256R1())
        (trusted / "alice.fido").write_text(_cred(p256).to_json())
        create_approver_key("bob", "correct horse battery", tmp_path)
        enroll_approver_key("bob", "correct horse battery", base=tmp_path, trusted=trusted)
        (trusted / "carol.fido").write_text(_cred(p256).to_json())
        (trusted / "carol.pub").write_bytes((trusted / "bob.pub").read_bytes())
        keys = load_public_keys(trusted)
        assert isinstance(keys["alice"], FidoCredential)
        assert set(keys) == {"alice", "bob"}
        assert "carol" in caplog.text


# ── init -> enroll -> sign, through the real python-fido2 client ───────────

@pytest.fixture
def use_device(monkeypatch):
    """Route scripts/fido.py's default client to a software key."""
    def plug_in(device):
        monkeypatch.setattr(fido, "_make_client", lambda device_=None: client_for(device))
        return device
    return plug_in


class TestEndToEnd:
    def test_init_enroll_sign_verify(self, tmp_path, use_device):
        use_device(SoftAuthenticator(pin=PIN))
        trusted = tmp_path / "trusted"
        path, cred = create_fido_credential("alice", tmp_path)
        assert path == fido_credential_path("alice", tmp_path) and cred.user_verification
        assert (path.stat().st_mode & 0o777) == 0o600
        enroll_fido_credential("alice", base=tmp_path, trusted=trusted)
        assert enrolled_kind("alice", trusted) == "fido2"

        enrolled = load_enrolled_credential("alice", trusted)
        not_after, st = _statement()
        signed = fido_signed_approval(approver="alice", not_after=not_after, signed=fido.sign_statement(enrolled, st))
        assert _verify([signed.as_dict()], load_public_keys(trusted)) == ["alice"]

    def test_enroll_requires_the_pin_by_default(self, tmp_path, use_device):
        use_device(SoftAuthenticator(pin=None))
        create_fido_credential("alice", tmp_path)
        with pytest.raises(fido.SecurityKeyError):
            enroll_fido_credential("alice", base=tmp_path, trusted=tmp_path / "trusted")
        enroll_fido_credential("alice", base=tmp_path, trusted=tmp_path / "trusted", require_pin=False)
        assert not load_enrolled_credential("alice", tmp_path / "trusted").user_verification

    def test_editing_the_users_file_cant_drop_the_pin(self, tmp_path, use_device):
        use_device(SoftAuthenticator(pin=PIN))
        path, cred = create_fido_credential("alice", tmp_path)
        path.write_text(replace(cred, user_verification=False).to_json())  # the agent's edit
        enroll_fido_credential("alice", base=tmp_path, trusted=tmp_path / "trusted")
        assert load_enrolled_credential("alice", tmp_path / "trusted").user_verification

    def test_credential_not_on_the_plugged_in_key_is_refused(self, tmp_path, use_device):
        use_device(SoftAuthenticator(pin=PIN))
        create_fido_credential("alice", tmp_path)
        use_device(SoftAuthenticator(pin=PIN))  # a different key
        with pytest.raises(fido.SecurityKeyError):
            enroll_fido_credential("alice", base=tmp_path, trusted=tmp_path / "trusted")
        assert enrolled_kind("alice", tmp_path / "trusted") is None

    def test_one_enrolled_key_per_user(self, tmp_path, use_device):
        use_device(SoftAuthenticator(pin=PIN))
        trusted = tmp_path / "trusted"
        create_approver_key("alice", "correct horse battery", tmp_path)
        enroll_approver_key("alice", "correct horse battery", base=tmp_path, trusted=trusted)
        create_fido_credential("alice", tmp_path)
        with pytest.raises(FileExistsError):
            enroll_fido_credential("alice", base=tmp_path, trusted=trusted)
        enroll_fido_credential("alice", base=tmp_path, trusted=trusted, replace=True)
        assert enrolled_kind("alice", trusted) == "fido2"
        assert not (trusted / "alice.pub").exists()

    def test_four_eyes_with_two_security_keys(self, tmp_path, use_device):
        trusted = tmp_path / "trusted"
        devices = {}
        for name in ("alice", "bob"):
            devices[name] = use_device(SoftAuthenticator(pin=PIN))
            create_fido_credential(name, tmp_path)
            enroll_fido_credential(name, base=tmp_path, trusted=trusted)
        signed = []
        for name in ("alice", "bob"):
            use_device(devices[name])
            not_after, st = _statement(approver=name)
            raw = fido.sign_statement(load_enrolled_credential(name, trusted), st)
            signed.append(fido_signed_approval(approver=name, not_after=not_after, signed=raw).as_dict())
        assert _verify(signed, load_public_keys(trusted), required=2) == ["alice", "bob"]
        with pytest.raises(ApprovalSignatureError, match="self_approval"):
            _verify(signed, load_public_keys(trusted), required=2, requester="os:alice")

    def test_wrong_pin_signs_nothing(self, tmp_path, use_device, monkeypatch):
        device = use_device(SoftAuthenticator(pin=PIN))
        create_fido_credential("alice", tmp_path)
        enroll_fido_credential("alice", base=tmp_path, trusted=tmp_path / "trusted")
        monkeypatch.setattr(getpass, "getpass", lambda prompt="": "0000")
        before = device.assertions
        with pytest.raises(fido.SecurityKeyError, match="PIN"):
            fido.sign_statement(load_enrolled_credential("alice", tmp_path / "trusted"), _statement()[1])
        assert device.assertions == before


def test_decide_signs_with_the_security_key(tmp_path, use_device, monkeypatch):
    """decide._sign picks the enrolled security key and produces what devd accepts."""
    from server.approvals import decide

    use_device(SoftAuthenticator(pin=PIN))
    trusted = tmp_path / "trusted"
    create_fido_credential("alice", tmp_path)
    enroll_fido_credential("alice", base=tmp_path, trusted=trusted)
    monkeypatch.setattr(decide, "enrolled_kind", lambda name: enrolled_kind(name, trusted))
    monkeypatch.setattr(decide, "load_enrolled_credential", lambda name: load_enrolled_credential(name, trusted))

    approval = type("A", (), {"id": APPROVAL_ID, "expires_at": time.time() + 600, "effect_summary": {"x": 1}})()
    signed = decide._sign("alice", approval, PHASH)
    from common.approval_sig import effect_hash

    assert verify_approvals([signed.as_dict()], public_keys=load_public_keys(trusted), approval_id=APPROVAL_ID,
                            proposal_hash=PHASH, effect_hash=effect_hash({"x": 1}), required=1,
                            requester="os:requester") == ["alice"]
