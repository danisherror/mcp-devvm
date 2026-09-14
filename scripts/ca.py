"""A real (software, non-HSM) SSH certificate authority for the tunnel
account (doc §9.4). Production hardening would put this key in an HSM/KMS;
here it's a 0600 file, which the doc's own fallback ladder for topology A
without CA infra explicitly allows -- we build the real CA mechanics on top
of that file instead of skipping to the `authorized_keys` fallback, because
the mechanics (short TTL, source-address pin, force-command, principal
attribution) are the part worth having in a reference implementation.

Usage:
    python -m scripts.ca init-ca <ca_dir>
    python -m scripts.ca mint <ca_dir> <out_prefix> --principal usr_x --tunnel-user devd-tunnel \
        --ttl +10m --source-address 127.0.0.1
"""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


def init_ca(ca_dir: Path) -> None:
    ca_dir.mkdir(parents=True, exist_ok=True)
    ca_key = ca_dir / "ca_key"
    if ca_key.exists():
        return
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", "mcp-devvm-ca", "-f", str(ca_key)],
        check=True, capture_output=True,
    )
    ca_key.chmod(0o600)


def mint_certificate(
    *,
    ca_dir: Path,
    out_prefix: Path,
    principal: str,
    tunnel_user: str,
    ttl: str,
    source_address: str,
) -> tuple[Path, Path]:
    """Returns (private_key_path, certificate_path)."""
    ca_key = ca_dir / "ca_key"
    out_prefix.parent.mkdir(parents=True, exist_ok=True)

    # ssh-keygen names the signed certificate by stripping ".pub" from the
    # public key filename and appending "-cert.pub" -- Path.with_suffix()
    # can't express that (it requires a leading dot), so build it directly.
    priv_path = out_prefix
    pub_path = Path(str(out_prefix) + ".pub")
    cert_path = Path(str(out_prefix) + "-cert.pub")

    if priv_path.exists():
        priv_path.unlink()
    if pub_path.exists():
        pub_path.unlink()
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", f"mcp:{principal}", "-f", str(priv_path)],
        check=True, capture_output=True,
    )
    priv_path.chmod(0o600)

    identity = f"mcp:{principal}"
    subprocess.run(
        [
            "ssh-keygen", "-s", str(ca_key),
            "-I", identity,
            "-n", tunnel_user,
            "-V", ttl,
            "-O", "clear",
            "-O", "permit-port-forwarding",
            "-O", f"source-address={source_address}",
            str(pub_path),
        ],
        check=True, capture_output=True,
    )
    return priv_path, cert_path


def ca_public_key(ca_dir: Path) -> str:
    return (ca_dir / "ca_key.pub").read_text().strip()


def _main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init-ca")
    p_init.add_argument("ca_dir", type=Path)

    p_mint = sub.add_parser("mint")
    p_mint.add_argument("ca_dir", type=Path)
    p_mint.add_argument("out_prefix", type=Path)
    p_mint.add_argument("--principal", required=True)
    p_mint.add_argument("--tunnel-user", required=True)
    p_mint.add_argument("--ttl", default="+10m")
    p_mint.add_argument("--source-address", required=True)

    args = parser.parse_args()
    if args.cmd == "init-ca":
        init_ca(args.ca_dir)
        print(f"CA ready at {args.ca_dir}/ca_key(.pub)")
    elif args.cmd == "mint":
        priv, cert = mint_certificate(
            ca_dir=args.ca_dir, out_prefix=args.out_prefix, principal=args.principal,
            tunnel_user=args.tunnel_user, ttl=args.ttl, source_address=args.source_address,
        )
        print(f"minted {priv} / {cert}")


if __name__ == "__main__":
    _main()
