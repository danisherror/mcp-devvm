"""Sandbox spec derivation FROM THE MANIFEST -- and nowhere else (doc §5.2, §14.2).

This is the module that makes the approval prompt trustworthy: the bwrap
argv below is built exclusively from `effect.reads` / `effect.writes` /
`effect.network`, the same fields rendered into the text a human approves.
There is no other input. An operation cannot request additional mounts,
capabilities, or network at runtime (§5.2 checklist).
"""

from __future__ import annotations

import os

# Base system paths every sandboxed operation needs read access to, so that
# git/python/coreutils and their shared libraries actually run. This list is
# NOT derived from any manifest -- it is the fixed "operating system" every
# operation sees, independent of what any operation declares.
_BASE_RO_BINDS = [
    "/usr",
    "/bin",
    "/lib",
    "/lib64",
    "/sbin",
    "/etc/ssl",
    "/etc/alternatives",
    "/etc/passwd",
    "/etc/group",
    "/etc/nsswitch.conf",
    "/etc/resolv.conf",
    "/etc/gitconfig",
]


def build_bwrap_argv(
    *,
    reads: list[str],
    writes: list[str],
    network: bool,
    cwd: str | None = None,
    extra_env: dict[str, str] | None = None,
) -> list[str]:
    argv = [
        "bwrap",
        "--unshare-all",
        "--die-with-parent",
        "--new-session",  # no TTY -> no TIOCSTI injection into the controlling terminal
        "--proc", "/proc",
        "--dev", "/dev",
        "--tmpfs", "/tmp",
    ]

    for path in _BASE_RO_BINDS:
        if os.path.exists(path):
            argv += ["--ro-bind", path, path]

    # From the manifest's effect declaration -- the ONLY source for these.
    for path in reads:
        argv += ["--ro-bind", path, path]
    for path in writes:
        argv += ["--bind", path, path]

    if network:
        argv += ["--share-net"]
    # else: no --share-net -> no network at all, enforced by the kernel (§14.2)

    if cwd:
        argv += ["--chdir", cwd]

    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/tmp", "LANG": "C.UTF-8"}
    if extra_env:
        env.update(extra_env)
    for key, value in env.items():
        argv += ["--setenv", key, value]

    return argv
