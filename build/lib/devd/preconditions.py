"""Named precondition capturers (doc §7.1 step 8, §13.3).

Used in two places, both calling the SAME function so the values are
computed identically:
  1. Before proposal, via devd's /preconditions endpoint (a READ_ONLY call)
  2. Inside the operation itself at execution time, adjacent to the effect
     (check-and-act, §13.3) -- see operations/*.py calling ctx.require(...)

Capturers run read-only, sandboxed, with no write access -- capturing state
must never itself mutate anything.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Awaitable, Callable

from devd.sandbox.namespace import run_sandboxed

Capturer = Callable[[Path], Awaitable[Any]]

_CAPTURERS: dict[str, Capturer] = {}


def precondition(name: str) -> Callable[[Capturer], Capturer]:
    def deco(fn: Capturer) -> Capturer:
        _CAPTURERS[name] = fn
        return fn

    return deco


@precondition("git.head_sha")
async def _git_head_sha(repo_root: Path) -> str:
    result = await run_sandboxed(
        ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
        reads=[str(repo_root)], writes=[], network=False, timeout_s=10, max_output_bytes=4096,
    )
    if result.exit_code != 0:
        raise RuntimeError(f"git rev-parse HEAD failed: {result.stderr.decode(errors='replace')}")
    return result.stdout.decode().strip()


@precondition("git.worktree_clean")
async def _git_worktree_clean(repo_root: Path) -> bool:
    result = await run_sandboxed(
        ["git", "-C", str(repo_root), "status", "--porcelain"],
        reads=[str(repo_root)], writes=[], network=False, timeout_s=10, max_output_bytes=4096,
    )
    if result.exit_code != 0:
        raise RuntimeError(f"git status failed: {result.stderr.decode(errors='replace')}")
    return result.stdout.decode().strip() == ""


@precondition("service.is_active")
async def _service_is_active(state_file: Path) -> bool:
    result = await run_sandboxed(
        ["cat", str(state_file)],
        reads=[str(state_file.parent)], writes=[], network=False, timeout_s=5, max_output_bytes=4096,
    )
    if result.exit_code != 0:
        return False
    return result.stdout.decode().strip() == "active"


async def capture(name: str, root: Path) -> Any:
    capturer = _CAPTURERS.get(name)
    if capturer is None:
        raise KeyError(f"unknown precondition capturer: {name}")
    return await capturer(root)
