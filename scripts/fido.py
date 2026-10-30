"""Talking to the approver's FIDO2 security key (a YubiKey or similar).

Used by `approver-keys init` (create a credential), `approver-keys enroll`
(prove the credential is on a key plugged into this machine) and `decide
approve` (sign an approval). Verification lives in common/approval_sig.py
and doesn't need this module or python-fido2.

Credentials are non-resident: the device keeps no state for us. The
credential id it returns is the private key, wrapped by the device so only
that device can use it; it's useless anywhere else and isn't secret.
"""

from __future__ import annotations

import getpass
import secrets
import sys
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from common.approval_sig import (
    FIDO_ORIGIN,
    FIDO_RP_ID,
    FidoCredential,
    check_fido_assertion,
    fido_challenge,
)

COSE_ES256 = -7
COSE_EDDSA = -8


class SecurityKeyError(Exception):
    pass


def _make_client(device: Any = None) -> Any:
    from fido2.client import DefaultClientDataCollector, Fido2Client, UserInteraction
    from fido2.hid import CtapHidDevice

    if device is None:
        devices = list(CtapHidDevice.list_devices())
        if not devices:
            raise SecurityKeyError("no security key found -- plug it in and try again")
        if len(devices) > 1:
            raise SecurityKeyError("more than one security key plugged in -- leave only yours")
        device = devices[0]

    class CliInteraction(UserInteraction):
        def prompt_up(self) -> None:
            print("Touch your security key now.", file=sys.stderr, flush=True)

        def request_pin(self, permissions: Any, rp_id: str | None) -> str | None:
            return getpass.getpass("Security key PIN: ") or None

        def request_uv(self, permissions: Any, rp_id: str | None) -> bool:
            return True

    return Fido2Client(device, DefaultClientDataCollector(FIDO_ORIGIN), user_interaction=CliInteraction())


def _cose_to_cryptography(cose: Any) -> Any:
    """The COSE public key the device returned, as a cryptography key."""
    alg = cose.get(3)
    if alg == COSE_ES256:
        return ec.EllipticCurvePublicNumbers(
            int.from_bytes(cose[-2], "big"), int.from_bytes(cose[-3], "big"), ec.SECP256R1()
        ).public_key()
    if alg == COSE_EDDSA:
        return Ed25519PublicKey.from_public_bytes(cose[-2])
    raise SecurityKeyError(f"security key returned an unsupported key type (COSE alg {alg})")


def _fido_error(exc: Exception) -> SecurityKeyError:
    from fido2.client import ClientError

    if isinstance(exc, ClientError):
        cause = getattr(exc, "cause", None)
        return SecurityKeyError(f"security key refused: {exc.code.name}{f' ({cause})' if cause else ''}")
    return SecurityKeyError(f"security key error: {exc}")


def create_credential(name: str, *, client: Any = None) -> FidoCredential:
    """Make a new credential on the plugged-in key for approver `name`.
    Asks for a touch, and for the PIN if the key has one."""
    from fido2.webauthn import (
        AttestationConveyancePreference,
        AuthenticatorSelectionCriteria,
        PublicKeyCredentialCreationOptions,
        PublicKeyCredentialParameters,
        PublicKeyCredentialRpEntity,
        PublicKeyCredentialType,
        PublicKeyCredentialUserEntity,
        ResidentKeyRequirement,
        UserVerificationRequirement,
    )

    client = client or _make_client()
    options = PublicKeyCredentialCreationOptions(
        rp=PublicKeyCredentialRpEntity(id=FIDO_RP_ID, name="mcp-devvm approvals"),
        user=PublicKeyCredentialUserEntity(id=name.encode("utf-8"), name=name, display_name=name),
        challenge=secrets.token_bytes(32),
        pub_key_cred_params=[
            PublicKeyCredentialParameters(type=PublicKeyCredentialType.PUBLIC_KEY, alg=COSE_ES256),
            PublicKeyCredentialParameters(type=PublicKeyCredentialType.PUBLIC_KEY, alg=COSE_EDDSA),
        ],
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.DISCOURAGED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
        attestation=AttestationConveyancePreference.NONE,
    )
    try:
        result = client.make_credential(options)
    except Exception as exc:
        raise _fido_error(exc) from exc
    auth_data = result.response.attestation_object.auth_data
    cred_data = auth_data.credential_data
    if cred_data is None:
        raise SecurityKeyError("security key returned no credential")
    return FidoCredential(
        credential_id=bytes(cred_data.credential_id),
        public_key=_cose_to_cryptography(cred_data.public_key),
        user_verification=auth_data.is_user_verified(),
    )


def sign_statement(cred: FidoCredential, statement: bytes, *, client: Any = None) -> dict[str, bytes]:
    """Have the security key sign `statement`. Asks for a touch, and for the
    PIN when the credential was enrolled with one. Checks the result the
    same way devd will before returning it."""
    from fido2.webauthn import (
        PublicKeyCredentialDescriptor,
        PublicKeyCredentialRequestOptions,
        PublicKeyCredentialType,
        UserVerificationRequirement,
    )

    client = client or _make_client()
    options = PublicKeyCredentialRequestOptions(
        challenge=fido_challenge(statement),
        rp_id=FIDO_RP_ID,
        allow_credentials=[
            PublicKeyCredentialDescriptor(type=PublicKeyCredentialType.PUBLIC_KEY, id=cred.credential_id)
        ],
        user_verification=(
            UserVerificationRequirement.REQUIRED if cred.user_verification
            else UserVerificationRequirement.DISCOURAGED
        ),
    )
    try:
        response = client.get_assertion(options).get_response(0).response
    except Exception as exc:
        raise _fido_error(exc) from exc
    signed = {
        "authenticator_data": bytes(response.authenticator_data),
        "client_data": bytes(response.client_data),
        "signature": bytes(response.signature),
    }
    try:
        check_fido_assertion(cred, statement, **signed)
    except ValueError as exc:
        raise SecurityKeyError(f"the security key's signature doesn't verify ({exc}) -- is it the enrolled key?") from exc
    return signed
