"""A software FIDO2 authenticator for tests, so the real python-fido2
client code (scripts/fido.py) runs end to end without a hardware key.

It speaks just enough CTAP2 over the CtapDevice interface: getInfo,
makeCredential, getAssertion, and the CTAP2.0 PIN protocol (v1) when
`pin` is set -- the path a real YubiKey with a PIN takes. Every request
counts as touched; a request carrying a valid PIN token also sets the
user-verified flag. NEVER use outside tests: the keys are in memory.
"""

from __future__ import annotations

import hashlib
import os
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2 import cbor
from fido2.cose import ES256
from fido2.ctap import CtapDevice
from fido2.ctap2.pin import ClientPin, PinProtocolV1
from fido2.hid import CAPABILITY, CTAPHID
from fido2.webauthn import AttestedCredentialData, AuthenticatorData

AAGUID = b"\x00" * 16
_OK = b"\x00"
_ERR_NO_CREDENTIALS = b"\x2e"
_ERR_INVALID_COMMAND = b"\x01"
_ERR_PIN_INVALID = b"\x31"
_ERR_PIN_AUTH_INVALID = b"\x33"


class SoftAuthenticator(CtapDevice):
    def __init__(self, *, pin: str | None = None):
        self.pin = pin
        self._pin_token: bytes | None = None
        self._key_agreement = ec.generate_private_key(ec.SECP256R1())
        self._pin_protocol = PinProtocolV1()
        self.counter = 0
        self.credentials: dict[bytes, tuple[ec.EllipticCurvePrivateKey, str]] = {}
        self.assertions = 0

    @property
    def capabilities(self) -> int:
        return CAPABILITY.CBOR

    @classmethod
    def list_devices(cls):
        return iter(())

    def call(self, cmd: int, data: bytes = b"", event: Any = None, on_keepalive: Any = None) -> bytes:
        if cmd != CTAPHID.CBOR:
            return _ERR_INVALID_COMMAND
        command, params = data[0], (cbor.decode(data[1:]) if len(data) > 1 else {})
        handler = {0x04: self._get_info, 0x01: self._make_credential, 0x02: self._get_assertion,
                   0x06: self._client_pin}.get(command)
        if handler is None:
            return _ERR_INVALID_COMMAND
        return handler(params)

    def _get_info(self, params: dict) -> bytes:
        info = {1: ["FIDO_2_0"], 3: AAGUID, 4: {"rk": False, "up": True, "plat": False}}
        if self.pin is not None:
            info[4]["clientPin"] = True
            info[6] = [1]  # pinUvAuthProtocols
        return _OK + cbor.encode(info)

    def _client_pin(self, params: dict) -> bytes:
        sub = params.get(2)
        if sub == ClientPin.CMD.GET_PIN_RETRIES:
            return _OK + cbor.encode({3: 8})
        if sub == ClientPin.CMD.GET_KEY_AGREEMENT:
            pn = self._key_agreement.public_key().public_numbers()
            cose = {1: 2, 3: -25, -1: 1, -2: pn.x.to_bytes(32, "big"), -3: pn.y.to_bytes(32, "big")}
            return _OK + cbor.encode({1: cose})
        if sub == ClientPin.CMD.GET_TOKEN_USING_PIN_LEGACY and self.pin is not None:
            peer = params[3]
            peer_key = ec.EllipticCurvePublicNumbers(
                int.from_bytes(peer[-2], "big"), int.from_bytes(peer[-3], "big"), ec.SECP256R1()
            ).public_key()
            shared = self._pin_protocol.kdf(self._key_agreement.exchange(ec.ECDH(), peer_key))
            pin_hash = self._pin_protocol.decrypt(shared, params[6])
            if pin_hash != hashlib.sha256(self.pin.encode()).digest()[:16]:
                return _ERR_PIN_INVALID
            self._pin_token = os.urandom(32)
            return _OK + cbor.encode({2: self._pin_protocol.encrypt(shared, self._pin_token)})
        return _ERR_INVALID_COMMAND

    def _flags(self, client_data_hash: bytes, pin_auth: bytes | None) -> AuthenticatorData.FLAG | None:
        """UP always; UV when the request carries a valid PIN token. None
        means a PIN auth was sent but is wrong."""
        flags = AuthenticatorData.FLAG.UP
        if pin_auth is not None:
            if self._pin_token is None or pin_auth != self._pin_protocol.authenticate(self._pin_token, client_data_hash):
                return None
            flags |= AuthenticatorData.FLAG.UV
        return flags

    def _make_credential(self, params: dict) -> bytes:
        rp_id = params[2]["id"]
        if not any(p["alg"] == -7 for p in params[4]):
            return b"\x26"  # UNSUPPORTED_ALGORITHM
        flags = self._flags(params[1], params.get(8))
        if flags is None:
            return _ERR_PIN_AUTH_INVALID
        key = ec.generate_private_key(ec.SECP256R1())
        cred_id = os.urandom(32)
        self.credentials[cred_id] = (key, rp_id)
        self.counter += 1
        cred_data = AttestedCredentialData.create(AAGUID, cred_id, ES256.from_cryptography_key(key.public_key()))
        auth_data = AuthenticatorData.create(
            hashlib.sha256(rp_id.encode()).digest(),
            flags | AuthenticatorData.FLAG.AT, self.counter, bytes(cred_data),
        )
        return _OK + cbor.encode({1: "none", 2: bytes(auth_data), 3: {}})

    def _get_assertion(self, params: dict) -> bytes:
        rp_id, client_data_hash = params[1], params[2]
        for desc in params.get(3) or []:
            entry = self.credentials.get(desc["id"])
            if entry and entry[1] == rp_id:
                key, cred_id = entry[0], desc["id"]
                break
        else:
            return _ERR_NO_CREDENTIALS
        flags = self._flags(client_data_hash, params.get(6))
        if flags is None:
            return _ERR_PIN_AUTH_INVALID
        self.counter += 1
        self.assertions += 1
        auth_data = bytes(AuthenticatorData.create(
            hashlib.sha256(rp_id.encode()).digest(), flags, self.counter,
        ))
        sig = key.sign(auth_data + client_data_hash, ec.ECDSA(hashes.SHA256()))
        return _OK + cbor.encode({1: {"type": "public-key", "id": cred_id}, 2: auth_data, 3: sig})


from scripts.fido import _make_client as _real_make_client


def client_for(device: SoftAuthenticator) -> Any:
    """The real Fido2Client from scripts/fido.py, on top of `device`."""
    return _real_make_client(device)

