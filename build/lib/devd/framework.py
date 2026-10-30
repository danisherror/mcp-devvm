"""The operation framework: OperationContext, Workspace, Precondition.

This module owns the guarantees an operation author cannot opt out of
(doc §22.4): no raw request, no sandbox handle, no way to widen scope beyond
what the manifest declared. `ctx.require()` raising on an undeclared
precondition is deliberate -- it keeps the manifest and the implementation
in lockstep.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable

from common.manifest import ManifestError, OperationManifest
from devd.sandbox.namespace import SandboxResult, run_sandboxed


class SandboxViolation(RuntimeError):
    pass


class PreconditionDrift(RuntimeError):
    def __init__(self, name: str, expected: Any, actual: Any):
        self.name = name
        self.expected = expected
        self.actual = actual
        super().__init__(f"precondition_drift:{name}")


@dataclass
class Precondition:
    name: str
    value: Any


@dataclass
class Result:
    summary: str
    data: dict[str, Any]


class Workspace:
    """A workspace root the operation's sandbox already has access to, per
    the manifest's effect declaration. Every command runs inside that same
    sandbox -- there is no separate shell and no way to widen scope."""

    def __init__(
        self,
        root: Path,
        *,
        reads: list[str],
        writes: list[str],
        network: bool,
        timeout_s: int,
        max_output_bytes: int,
    ):
        self.root = root
        self._reads = reads
        self._writes = writes
        self._network = network
        self._timeout_s = timeout_s
        self._max_output_bytes = max_output_bytes

    async def run(self, argv: list[str], *, stdin: bytes | None = None) -> SandboxResult:
        # argv list, never a shell string (§5.4) -- a param fills a whole element.
        return await run_sandboxed(
            argv,
            reads=self._reads,
            writes=self._writes,
            network=self._network,
            timeout_s=self._timeout_s,
            max_output_bytes=self._max_output_bytes,
            cwd=str(self.root),
            stdin=stdin,
        )

    async def git(self, *args: str) -> str:
        result = await self.run(["git", "-C", str(self.root), *args])
        if result.timed_out:
            raise TimeoutError(f"git {' '.join(args)} timed out inside the sandbox")
        if result.exit_code != 0:
            raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.decode(errors='replace')}")
        return result.stdout.decode(errors="replace")

    async def head_sha(self) -> str:
        return (await self.git("rev-parse", "HEAD")).strip()

    async def is_clean(self) -> bool:
        out = await self.git("status", "--porcelain")
        return out.strip() == ""


class OperationContext:
    """Everything an operation is allowed to touch. No raw request, no
    sandbox handle, no way to widen its own scope."""

    def __init__(
        self,
        op: OperationManifest,
        params: dict[str, Any],
        declared_preconditions: dict[str, Any],
        workspaces: dict[str, Path],
    ):
        self._op = op
        self._params = params
        self._declared = declared_preconditions
        self._workspaces = workspaces
        rendered = op.effect.render(params)
        self._rendered_reads: list[str] = rendered["reads"]
        self._rendered_writes: list[str] = rendered["writes"]
        self._rendered_network: list[str] = rendered["network"]

    def workspace(self, repo: str) -> Workspace:
        if repo not in self._workspaces:
            raise ManifestError(f"unknown workspace {repo!r}")
        root = self._workspaces[repo]
        root_str = str(root)
        if root_str not in self._rendered_writes and root_str not in self._rendered_reads:
            raise SandboxViolation(f"{self._op.id} did not declare access to {root_str}")
        return Workspace(
            root,
            reads=self._rendered_reads,
            writes=self._rendered_writes,
            network=bool(self._rendered_network),
            timeout_s=self._op.sandbox.timeout_s,
            max_output_bytes=self._op.sandbox.max_output_bytes,
        )

    def require(self, actual: Precondition) -> None:
        if actual.name not in self._op.preconditions:
            raise ManifestError(f"{actual.name} not declared by {self._op.id}")
        expected = self._declared.get(actual.name)
        if expected is None:
            raise ManifestError(f"{actual.name} was not captured before execution")
        if expected != actual.value:
            raise PreconditionDrift(actual.name, expected, actual.value)

    async def run_sandboxed(self, argv: list[str], *, cwd: str | None = None, stdin: bytes | None = None) -> SandboxResult:
        """For operations with no natural Workspace (e.g. service control).
        Still bound to exactly this operation's declared reads/writes/network
        -- there is no way to widen it from inside the operation."""
        return await run_sandboxed(
            argv,
            reads=self._rendered_reads,
            writes=self._rendered_writes,
            network=bool(self._rendered_network),
            timeout_s=self._op.sandbox.timeout_s,
            max_output_bytes=self._op.sandbox.max_output_bytes,
            cwd=cwd,
            stdin=stdin,
        )


OperationFunc = Callable[..., Awaitable[Result]]
PreconditionContextFunc = Callable[[dict[str, Any]], Path]

_IMPLEMENTATIONS: dict[str, OperationFunc] = {}
_PRECONDITION_CONTEXT: dict[str, PreconditionContextFunc] = {}


def operation(operation_id: str) -> Callable[[OperationFunc], OperationFunc]:
    def deco(fn: OperationFunc) -> OperationFunc:
        _IMPLEMENTATIONS[operation_id] = fn
        return fn

    return deco


def precondition_context(operation_id: str) -> Callable[[PreconditionContextFunc], PreconditionContextFunc]:
    """Registers, per operation, how to resolve the filesystem root that
    precondition capture should read against before proposal (§7.1 step 8)."""

    def deco(fn: PreconditionContextFunc) -> PreconditionContextFunc:
        _PRECONDITION_CONTEXT[operation_id] = fn
        return fn

    return deco


def get_implementation(operation_id: str) -> OperationFunc | None:
    return _IMPLEMENTATIONS.get(operation_id)


def get_precondition_context(operation_id: str) -> PreconditionContextFunc | None:
    return _PRECONDITION_CONTEXT.get(operation_id)
