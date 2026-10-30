"""Executes an argv inside a bubblewrap sandbox built from a manifest's
effect declaration. No shell anywhere -- argv goes straight to execve
inside the sandboxed namespace (doc §5.2, §14.2).
"""

from __future__ import annotations

import asyncio
import os
import signal
from dataclasses import dataclass

from devd.sandbox.builder import build_bwrap_argv


class SandboxConstructionError(RuntimeError):
    """Raised when bwrap itself cannot be invoked. Callers must never fall
    back to running unsandboxed -- doc §19: 'sandbox construction fails ->
    do not run.'"""


@dataclass
class SandboxResult:
    exit_code: int
    stdout: bytes
    stderr: bytes
    timed_out: bool


async def run_sandboxed(
    argv: list[str],
    *,
    reads: list[str],
    writes: list[str],
    network: bool,
    timeout_s: int,
    max_output_bytes: int,
    cwd: str | None = None,
    stdin: bytes | None = None,
) -> SandboxResult:
    """`stdin`, when given, is piped to the process -- the shell-free way to
    get literal content into a sandboxed command (e.g. `tee dest`) without
    ever invoking a shell for redirection."""
    bwrap_argv = build_bwrap_argv(reads=reads, writes=writes, network=network, cwd=cwd)
    full_argv = bwrap_argv + ["--"] + argv

    try:
        proc = await asyncio.create_subprocess_exec(
            *full_argv,
            stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,  # own process group -> a timeout kills the whole tree
        )
    except OSError as exc:
        raise SandboxConstructionError(str(exc)) from exc

    timed_out = False
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(input=stdin), timeout=timeout_s)
    except asyncio.TimeoutError:
        timed_out = True
        await _kill_process_group(proc)
        stdout, stderr = b"", b""

    stdout = stdout[:max_output_bytes]
    stderr = stderr[:max_output_bytes]
    exit_code = 124 if timed_out else (proc.returncode if proc.returncode is not None else -1)
    return SandboxResult(exit_code=exit_code, stdout=stdout, stderr=stderr, timed_out=timed_out)


async def _kill_process_group(proc: asyncio.subprocess.Process) -> None:
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        await asyncio.wait_for(proc.wait(), timeout=5)
        return
    except asyncio.TimeoutError:
        pass
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    await proc.wait()
