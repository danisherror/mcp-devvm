"""Approver signing keys (see common/approval_sig.py for why they exist).

    /opt/mcp-devvm-approve/bin/approver-keys init           as you
    sudo /opt/mcp-devvm-approve/bin/approver-keys enroll    as root, once per key
    /opt/mcp-devvm-approve/bin/approver-keys list

(`python -m scripts.approver_keys` runs the same thing from the repo; use the
protected copy from scripts/install_decide.sh, since you type your
passphrase into it.)

`init` creates your private key, encrypted with a passphrase, at
~/.mcp-devvm/approver/<user>.key in your own home directory, so several
approvers on one machine each keep their own key. (A key from before this
change at data/approvers/private/<user>.key in the repo is still used if
there is none in your home directory.) A key is always named after the OS
user who creates it, one per user: devd treats `<user>.pub` as belonging to
`os:<user>`, which is how four-eyes counts people and spots self-approval.

`enroll` is what makes devd trust the key. It writes the public half to
/etc/mcp-devvm/approvers/, a root-owned directory mounted read-only into the
VM. It needs root because that directory must not be writable by your OS
user: if it were, an agent running as you could drop in a key of its own
and sign its own approvals. `enroll` asks for the passphrase and derives the
public key from the private key, rather than copying a `.pub` file an agent
could have swapped. Revoke a key with `sudo rm /etc/mcp-devvm/approvers/<user>.pub`.

The passphrase is the part the agent can't get: it is never written to disk.
Use a real one; an agent can read the encrypted key file, so its strength
is what stands between the agent and a forged approval.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import os
import pwd
import stat
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from common.approval_sig import APPROVER_NAME_RE

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
    return trusted / f"{name}.pub"


def _public_pem(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def fingerprint(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    return "SHA256:" + hashlib.sha256(raw).hexdigest()[:32]


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
    priv_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    priv_path.parent.chmod(0o700)
    if base is None:
        priv_path.parent.parent.chmod(0o700)  # ~/.mcp-devvm

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
    dest = trusted_key_path(name, trusted)
    if dest.exists() and not replace:
        raise FileExistsError(f"'{name}' already has an enrolled key (one key per OS user; --replace to rotate it)")
    trusted.mkdir(mode=0o755, parents=True, exist_ok=True)
    tmp = dest.with_name(f".{dest.name}.tmp")
    tmp.write_bytes(_public_pem(key))
    tmp.chmod(0o644)
    os.replace(tmp, dest)
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


def _enroll(user: str | None, replace: bool) -> None:
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
    if not private_key_path(name).is_file():
        _fail(f"no private key for '{name}' at {private_key_path(name)} -- they run `approver-keys init` first")
    # Check the parents before creating the directory, so we never create
    # it under a directory a non-root user could rename.
    reason = untrusted_dir_reason(TRUSTED_PUBLIC_DIR.parent)
    if reason:
        _fail(f"refusing to enroll into {TRUSTED_PUBLIC_DIR}: {reason}")
    passphrase = getpass.getpass(f"Passphrase for approver '{name}' (they type it, not the admin): ")
    try:
        dest, fp = enroll_approver_key(name, passphrase, replace=replace, owner_uid=owner_uid)
    except FileExistsError as exc:
        _fail(str(exc))
    except OSError as exc:
        _fail(f"can't read {private_key_path(name)}: {exc.strerror or exc}")
    except (ValueError, TypeError):
        _fail("wrong passphrase, or the key file isn't a regular file owned by that user -- not enrolled")
    reason = untrusted_dir_reason(TRUSTED_PUBLIC_DIR)
    if reason:
        _fail(f"enrolled, but devd shouldn't trust {TRUSTED_PUBLIC_DIR}: {reason}")
    print(f"enrolled approver '{name}' ({fp})\n  {dest}")
    print("A running VM reads this directory live -- no restart needed.")


def _list() -> None:
    """Your own key, then every key devd trusts. Other users' private keys
    live in their home directories, so they aren't listed here."""
    try:
        me = current_approver_name()
    except ValueError as exc:
        _fail(str(exc))
    path = private_key_path(me)
    if not path.is_file():
        print(f"you ({me}): no approver key -- run: approver-keys init")
    elif trusted_key_path(me).is_file():
        print(f"you ({me}): {path}, enrolled")
    else:
        print(f"you ({me}): {path}, NOT ENROLLED (sudo approver-keys enroll)")
    enrolled = sorted(p.stem for p in TRUSTED_PUBLIC_DIR.glob("*.pub")) if TRUSTED_PUBLIC_DIR.is_dir() else []
    print(f"enrolled in {TRUSTED_PUBLIC_DIR}: {', '.join(enrolled) if enrolled else 'none'}")


def main() -> None:
    parser = argparse.ArgumentParser(prog="approver-keys")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init", help="create the private approver key for your OS user")
    p_enroll = sub.add_parser("enroll", help="(root) make devd trust a user's key")
    p_enroll.add_argument("--user", default=None, help="whose key to enroll (default: the user who ran sudo)")
    p_enroll.add_argument("--replace", action="store_true", help="replace an enrolled key (key rotation)")
    sub.add_parser("list", help="show your approver key and which keys devd trusts")
    args = parser.parse_args()

    if args.cmd == "list":
        _list()
        return
    if args.cmd == "enroll":
        _enroll(args.user, args.replace)
        return

    if os.geteuid() == 0:
        _fail("run init as yourself, not with sudo")
    try:
        name = current_approver_name()
    except ValueError as exc:
        _fail(str(exc))
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
    print("devd won't trust it until it's enrolled:\n  sudo /opt/mcp-devvm-approve/bin/approver-keys enroll")


if __name__ == "__main__":
    main()
