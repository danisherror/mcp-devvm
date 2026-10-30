"""Approver keys (see common/approval_sig.py for why they exist).

    /opt/mcp-devvm-approve/bin/approver-keys init           as you, key plugged in
    sudo /opt/mcp-devvm-approve/bin/approver-keys enroll    as root, once per person
    /opt/mcp-devvm-approve/bin/approver-keys list

(`python -m scripts.approver_keys` runs the same thing from the repo; use the
protected copy from scripts/install_decide.sh, since you type your PIN
into it.)

Each approver uses a FIDO2 security key (a YubiKey or similar), ideally
with a PIN set. `init` creates a credential on the key and saves its
public half and credential id to ~/.mcp-devvm/approver/<user>.fido. The
private key never leaves the device. A key is always named after the OS
user who creates it, one per user: devd treats `<user>.fido` as belonging
to `os:<user>`, which is how four-eyes counts people and spots
self-approval.

`enroll` is what makes devd trust the key. It needs root, because devd only
trusts /etc/mcp-devvm/approvers/, a root-owned directory mounted read-only
into the VM; if your user could write it, an agent running as you could
drop in a key of its own. `enroll` doesn't just copy your .fido file, which
the agent could have swapped: it has the plugged-in key sign a fresh
challenge (touch + PIN) and checks it, so only a credential that really
lives on a key in front of you gets enrolled. It requires the PIN unless
you pass --no-pin. Revoke with `sudo rm /etc/mcp-devvm/approvers/<user>.fido`.

Without a security key: `init --passphrase` creates an Ed25519 key in a
passphrase-encrypted file instead (~/.mcp-devvm/approver/<user>.key), and
`sudo approver-keys enroll --passphrase-key` enrolls it as <user>.pub. That
is weaker: an agent that captures the passphrase once can sign forever.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import os
import pwd
import secrets
import stat
import sys
from dataclasses import replace as dc_replace
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from common.approval_sig import APPROVER_NAME_RE, FidoCredential

# Where keys lived before they moved to each user's home directory. Relative
# to the repo: the launchers from install_decide.sh run from there.
LEGACY_APPROVERS_DIR = Path("data/approvers")
HOME_KEY_DIR = Path(".mcp-devvm") / "approver"
MAX_KEY_FILE_BYTES = 64 * 1024
# The only public keys devd trusts. Mounted at /etc/devd/approvers in the VM
# by scripts/setup_dev_vm.py; created by scripts/install_decide.sh.
TRUSTED_PUBLIC_DIR = Path("/etc/mcp-devvm/approvers")
MIN_PASSPHRASE_LEN = 12


def home_key_path(name: str) -> Path:
    """`name`'s key in their own home directory. The home comes from the
    user database, not $HOME, so `sudo enroll --user bob` finds bob's."""
    return Path(pwd.getpwnam(name).pw_dir) / HOME_KEY_DIR / f"{name}.key"


def private_key_path(name: str, base: Path | None = None) -> Path:
    """With `base` (tests), `<base>/private/<name>.key`. Otherwise the key in
    the user's home directory, or the old repo location if only that exists."""
    if base is not None:
        return base / "private" / f"{name}.key"
    legacy = LEGACY_APPROVERS_DIR / "private" / f"{name}.key"
    try:
        home = home_key_path(name)
    except KeyError:  # no such OS user
        return legacy
    if home.exists() or not legacy.exists():
        return home
    return legacy


def read_key_file(path: Path, *, owner_uid: int | None = None) -> bytes:
    """Read a private key file without following a symlink at the last
    component, refusing anything but a small regular file. `enroll` runs as
    root and reads a file from the user's home, so it passes `owner_uid`
    to make sure the file belongs to that user."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"{path} is not a regular file")
        if owner_uid is not None and st.st_uid != owner_uid:
            raise ValueError(f"{path} is not owned by the approver")
        if st.st_size > MAX_KEY_FILE_BYTES:
            raise ValueError(f"{path} is too large to be a key")
        return os.read(fd, MAX_KEY_FILE_BYTES + 1)
    finally:
        os.close(fd)


def trusted_key_path(name: str, trusted: Path = TRUSTED_PUBLIC_DIR) -> Path:
    """A passphrase key's enrolled public half."""
    return trusted / f"{name}.pub"


def fido_credential_path(name: str, base: Path | None = None) -> Path:
    """The user's own copy of their security-key credential (not trusted)."""
    if base is not None:
        return base / "private" / f"{name}.fido"
    return Path(pwd.getpwnam(name).pw_dir) / HOME_KEY_DIR / f"{name}.fido"


def trusted_fido_path(name: str, trusted: Path = TRUSTED_PUBLIC_DIR) -> Path:
    return trusted / f"{name}.fido"


def enrolled_kind(name: str, trusted: Path = TRUSTED_PUBLIC_DIR) -> str | None:
    """"fido2", "passphrase", "conflict" (both; devd ignores the approver)
    or None."""
    fido, pub = trusted_fido_path(name, trusted).is_file(), trusted_key_path(name, trusted).is_file()
    if fido and pub:
        return "conflict"
    return "fido2" if fido else "passphrase" if pub else None


def load_enrolled_credential(name: str, trusted: Path = TRUSTED_PUBLIC_DIR) -> FidoCredential:
    """The credential devd trusts for `name`. `decide` signs with this one,
    not the user's own copy, so the PIN requirement is what root enrolled."""
    return FidoCredential.from_json(read_key_file(trusted_fido_path(name, trusted)))


def _public_pem(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def fingerprint(key: Any) -> str:
    """For a passphrase key (Ed25519PrivateKey) or a FidoCredential."""
    pub = key.public_key if isinstance(key, FidoCredential) else key.public_key()
    der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return "SHA256:" + hashlib.sha256(der).hexdigest()[:32]


def untrusted_dir_reason(path: Path) -> str | None:
    """Why `path` can't hold trusted keys, or None if it can: it and every
    directory above it must be owned by root and not group/world-writable,
    or a non-root process could add, swap or rename keys."""
    p = path.resolve()
    for d in (p, *p.parents):
        if not d.exists():
            return f"{d} does not exist"
        st = d.stat()
        if st.st_uid != 0:
            return f"{d} is not owned by root"
        if st.st_mode & 0o022:
            return f"{d} is group- or world-writable"
    return None


def _private_dir(path: Path, base: Path | None) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    if base is None:
        path.parent.parent.chmod(0o700)  # ~/.mcp-devvm


def _write_atomic(dest: Path, data: bytes, mode: int) -> None:
    tmp = dest.with_name(f".{dest.name}.tmp")
    tmp.unlink(missing_ok=True)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.chmod(tmp, mode)
    os.replace(tmp, dest)


def create_fido_credential(name: str, base: Path | None = None, *, client: Any = None) -> tuple[Path, FidoCredential]:
    """Creates a credential on the plugged-in security key and saves its
    public half. devd doesn't trust it until root enrolls it."""
    from scripts.fido import create_credential

    if not APPROVER_NAME_RE.match(name):
        raise ValueError(f"approver name must match {APPROVER_NAME_RE.pattern}")
    path = fido_credential_path(name, base)
    if path.exists():
        raise FileExistsError(f"'{name}' already has a security-key credential at {path} (one per OS user)")
    cred = create_credential(name, client=client)
    _private_dir(path, base)
    _write_atomic(path, cred.to_json().encode(), 0o600)
    return path, cred


def enroll_fido_credential(
    name: str, *, base: Path | None = None, trusted: Path = TRUSTED_PUBLIC_DIR, replace: bool = False,
    owner_uid: int | None = None, require_pin: bool = True, client: Any = None,
) -> tuple[Path, str]:
    """Trust `name`'s security key. The user's .fido file only says which
    credential to try: enrolling needs a fresh signature from the plugged-in
    key (touch, plus PIN unless require_pin is False), and the PIN rule
    written to the trusted file is decided here, not read from the user's
    file. Returns the written path and the key's fingerprint."""
    from scripts.fido import sign_statement

    if not APPROVER_NAME_RE.match(name):
        raise ValueError(f"approver name must match {APPROVER_NAME_RE.pattern}")
    cred = FidoCredential.from_json(read_key_file(fido_credential_path(name, base), owner_uid=owner_uid))
    cred = dc_replace(cred, user_verification=require_pin)
    _check_replace(name, trusted, replace)
    sign_statement(cred, b"mcp-devvm-enroll:" + secrets.token_bytes(32), client=client)
    trusted.mkdir(mode=0o755, parents=True, exist_ok=True)
    dest = trusted_fido_path(name, trusted)
    _write_atomic(dest, cred.to_json().encode(), 0o644)
    trusted_key_path(name, trusted).unlink(missing_ok=True)  # one key per person
    return dest, fingerprint(cred)


def _check_replace(name: str, trusted: Path, replace: bool) -> None:
    if enrolled_kind(name, trusted) is not None and not replace:
        raise FileExistsError(f"'{name}' already has an enrolled key (one key per OS user; --replace to rotate it)")


def create_approver_key(name: str, passphrase: str, base: Path | None = None) -> Path:
    """Creates the encrypted private key only. devd doesn't trust it until
    it's enrolled with enroll_approver_key (as root)."""
    if not APPROVER_NAME_RE.match(name):
        raise ValueError(f"approver name must match {APPROVER_NAME_RE.pattern}")
    if not passphrase:
        raise ValueError("passphrase must not be empty")
    priv_path = private_key_path(name, base)
    if priv_path.exists():
        raise FileExistsError(f"approver key '{name}' already exists (one key per OS user)")
    _private_dir(priv_path, base)

    key = Ed25519PrivateKey.generate()
    priv_path.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode("utf-8")),
    ))
    priv_path.chmod(0o600)
    return priv_path


def enroll_approver_key(
    name: str, passphrase: str, *, base: Path | None = None, trusted: Path = TRUSTED_PUBLIC_DIR,
    replace: bool = False, owner_uid: int | None = None,
) -> tuple[Path, str]:
    """Writes the public half of `name`'s key into the trusted directory.
    Unlocking the private key proves it's the human's: an agent can swap
    the key file, but can't make one that opens with the human's passphrase.
    Returns the written path and the key's fingerprint."""
    if not APPROVER_NAME_RE.match(name):
        raise ValueError(f"approver name must match {APPROVER_NAME_RE.pattern}")
    key = load_private_key(name, passphrase, base, owner_uid=owner_uid)
    _check_replace(name, trusted, replace)
    trusted.mkdir(mode=0o755, parents=True, exist_ok=True)
    dest = trusted_key_path(name, trusted)
    _write_atomic(dest, _public_pem(key), 0o644)
    trusted_fido_path(name, trusted).unlink(missing_ok=True)  # one key per person
    return dest, fingerprint(key)


def enrolled_key_matches(name: str, key: Ed25519PrivateKey, trusted: Path = TRUSTED_PUBLIC_DIR) -> bool:
    path = trusted_key_path(name, trusted)
    return path.is_file() and path.read_bytes() == _public_pem(key)


def load_private_key(
    name: str, passphrase: str, base: Path | None = None, *, owner_uid: int | None = None,
) -> Ed25519PrivateKey:
    pem = read_key_file(private_key_path(name, base), owner_uid=owner_uid)
    key = serialization.load_pem_private_key(pem, password=passphrase.encode("utf-8"))
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("approver key is not Ed25519")
    return key


def current_approver_name() -> str:
    """The approver name for the OS user running this process. Not
    lower-cased or otherwise changed: it has to equal the user part of the
    principal id (`os:<user>`, server/auth/principal.py) exactly, or the
    self-approval check would compare two different strings."""
    name = getpass.getuser()
    if not APPROVER_NAME_RE.match(name):
        raise ValueError(f"OS username '{name}' can't be an approver name (must match {APPROVER_NAME_RE.pattern})")
    return name


def _fail(msg: str) -> None:
    print(msg, file=sys.stderr)
    raise SystemExit(1)


def _enroll(user: str | None, replace: bool, passphrase_key: bool, no_pin: bool) -> None:
    if os.geteuid() != 0:
        _fail("enroll needs root: sudo /opt/mcp-devvm-approve/bin/approver-keys enroll")
    # Running this file as root means it must be a copy only root can edit
    # (scripts/install_decide.sh), or the agent could have changed it.
    here = Path(__file__).resolve()
    if here.stat().st_uid != 0 or here.stat().st_mode & 0o022 or untrusted_dir_reason(here.parent):
        _fail("refusing to run enroll as root from a copy your user can edit -- "
              "use the protected copy: sudo /opt/mcp-devvm-approve/bin/approver-keys enroll")
    name = user or os.environ.get("SUDO_USER")
    if not name or name == "root":
        _fail("run through sudo from your own account, or name the user with --user")
    if not APPROVER_NAME_RE.match(name):
        _fail(f"'{name}' can't be an approver name (must match {APPROVER_NAME_RE.pattern})")
    try:
        owner_uid = pwd.getpwnam(name).pw_uid
    except KeyError:
        _fail(f"no OS user named '{name}'")
    key_file = private_key_path(name) if passphrase_key else fido_credential_path(name)
    if not key_file.is_file():
        hint = ("approver-keys init --passphrase" if passphrase_key else
                "approver-keys init (with their security key plugged in)")
        extra = ""
        if not passphrase_key and private_key_path(name).is_file():
            extra = ("\n(they have a passphrase key; enroll it with --passphrase-key if they have no security key, "
                     "but a security key is much stronger)")
        _fail(f"no {'passphrase key' if passphrase_key else 'security-key credential'} for '{name}' at {key_file} "
              f"-- they run `{hint}` first{extra}")
    # Check the parents before creating the directory, so we never create
    # it under a directory a non-root user could rename.
    reason = untrusted_dir_reason(TRUSTED_PUBLIC_DIR.parent)
    if reason:
        _fail(f"refusing to enroll into {TRUSTED_PUBLIC_DIR}: {reason}")
    if passphrase_key:
        passphrase = getpass.getpass(f"Passphrase for approver '{name}' (they type it, not the admin): ")
        try:
            dest, fp = enroll_approver_key(name, passphrase, replace=replace, owner_uid=owner_uid)
        except FileExistsError as exc:
            _fail(str(exc))
        except OSError as exc:
            _fail(f"can't read {key_file}: {exc.strerror or exc}")
        except (ValueError, TypeError):
            _fail("wrong passphrase, or the key file isn't a regular file owned by that user -- not enrolled")
    else:
        from scripts.fido import SecurityKeyError

        print(f"Enrolling {name}'s security key: they touch it{'' if no_pin else ' and type its PIN'}.", flush=True)
        try:
            dest, fp = enroll_fido_credential(name, replace=replace, owner_uid=owner_uid, require_pin=not no_pin)
        except FileExistsError as exc:
            _fail(str(exc))
        except OSError as exc:
            _fail(f"can't read {key_file}: {exc.strerror or exc}")
        except ValueError as exc:
            _fail(f"{key_file}: {exc} -- not enrolled")
        except SecurityKeyError as exc:
            msg = str(exc)
            if not no_pin and ("PIN" in msg or "UV" in msg or "verif" in msg.lower()):
                msg += ("\nIs a PIN set on the key? Set one (e.g. `ykman fido access change-pin`), or enroll "
                        "with --no-pin to accept a touch alone.")
            _fail(f"{msg}\n-- not enrolled")
    reason = untrusted_dir_reason(TRUSTED_PUBLIC_DIR)
    if reason:
        _fail(f"enrolled, but devd shouldn't trust {TRUSTED_PUBLIC_DIR}: {reason}")
    print(f"enrolled approver '{name}' ({fp})\n  {dest}")
    print("A running VM reads this directory live -- no restart needed.")


def _list() -> None:
    """Your own key, then every key devd trusts."""
    try:
        me = current_approver_name()
    except ValueError as exc:
        _fail(str(exc))
    kind = enrolled_kind(me)
    if kind == "fido2":
        pin = "touch + PIN" if load_enrolled_credential(me).user_verification else "touch only"
        print(f"you ({me}): security key enrolled ({pin})")
    elif kind == "passphrase":
        print(f"you ({me}): passphrase key enrolled (consider a security key: approver-keys init, then "
              "sudo approver-keys enroll --replace)")
    elif kind == "conflict":
        print(f"you ({me}): BOTH a .fido and a .pub are enrolled, so devd ignores you -- re-enroll with --replace")
    elif fido_credential_path(me).is_file():
        print(f"you ({me}): security-key credential created, NOT ENROLLED (sudo approver-keys enroll)")
    elif private_key_path(me).is_file():
        print(f"you ({me}): passphrase key created, NOT ENROLLED (sudo approver-keys enroll --passphrase-key)")
    else:
        print(f"you ({me}): no approver key -- plug in your security key and run: approver-keys init")
    if TRUSTED_PUBLIC_DIR.is_dir():
        rows = sorted({p.stem for p in [*TRUSTED_PUBLIC_DIR.glob("*.fido"), *TRUSTED_PUBLIC_DIR.glob("*.pub")]})
        labels = {"fido2": "security key", "passphrase": "passphrase", "conflict": "CONFLICT (ignored)"}
        enrolled = [f"{n} ({labels[enrolled_kind(n) or 'conflict']})" for n in rows]
    else:
        enrolled = []
    print(f"enrolled in {TRUSTED_PUBLIC_DIR}: {', '.join(enrolled) if enrolled else 'none'}")


def main() -> None:
    parser = argparse.ArgumentParser(prog="approver-keys")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_init = sub.add_parser("init", help="create your approver credential on your security key")
    p_init.add_argument("--passphrase", action="store_true",
                        help="no security key: make a passphrase-encrypted software key instead (weaker)")
    p_enroll = sub.add_parser("enroll", help="(root) make devd trust a user's key")
    p_enroll.add_argument("--user", default=None, help="whose key to enroll (default: the user who ran sudo)")
    p_enroll.add_argument("--replace", action="store_true", help="replace an enrolled key (key rotation)")
    p_enroll.add_argument("--passphrase-key", action="store_true",
                          help="enroll a passphrase key (init --passphrase) instead of a security key")
    p_enroll.add_argument("--no-pin", action="store_true",
                          help="accept a security key without a PIN: a touch alone signs")
    sub.add_parser("list", help="show your approver key and which keys devd trusts")
    args = parser.parse_args()

    if args.cmd == "list":
        _list()
        return
    if args.cmd == "enroll":
        if args.passphrase_key and args.no_pin:
            _fail("--no-pin is for security keys, not --passphrase-key")
        _enroll(args.user, args.replace, args.passphrase_key, args.no_pin)
        return

    if os.geteuid() == 0:
        _fail("run init as yourself, not with sudo")
    try:
        name = current_approver_name()
    except ValueError as exc:
        _fail(str(exc))
    if not args.passphrase:
        _init_security_key(name)
        return
    passphrase = getpass.getpass(f"New passphrase for approver '{name}' (min {MIN_PASSPHRASE_LEN} chars): ")
    if len(passphrase) < MIN_PASSPHRASE_LEN:
        print(f"passphrase too short (need at least {MIN_PASSPHRASE_LEN} characters)", file=sys.stderr)
        raise SystemExit(1)
    if getpass.getpass("Repeat passphrase: ") != passphrase:
        print("passphrases did not match", file=sys.stderr)
        raise SystemExit(1)
    try:
        priv = create_approver_key(name, passphrase)
    except (ValueError, FileExistsError) as exc:
        _fail(str(exc))
    print(f"created approver key '{name}' (encrypted): {priv}")
    print("devd won't trust it until it's enrolled:\n"
          "  sudo /opt/mcp-devvm-approve/bin/approver-keys enroll --passphrase-key")


def _init_security_key(name: str) -> None:
    from scripts.fido import SecurityKeyError

    print(f"Creating the approver credential for '{name}' on your security key.", flush=True)
    try:
        path, cred = create_fido_credential(name)
    except (ValueError, FileExistsError, SecurityKeyError) as exc:
        _fail(str(exc))
    print(f"created ({fingerprint(cred)}): {path}")
    if not cred.user_verification:
        print("Note: your key has no PIN, so enrolling will fail unless the admin passes --no-pin. "
              "Setting a PIN is better: `ykman fido access change-pin` for a YubiKey.")
    print("devd won't trust it until it's enrolled (keep the key plugged in):\n"
          "  sudo /opt/mcp-devvm-approve/bin/approver-keys enroll")


if __name__ == "__main__":
    main()
