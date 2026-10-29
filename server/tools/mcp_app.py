"""The entire MCP tool surface (doc §6, §24 -- "audit this dir in review").

Note what is absent, and that its absence is the control: no `exec`,
`run_command`, `shell`, `ssh`, `write_file`, or unscoped `read_file`; no
parameter named `command`, `host`, `port`, `user`, `key`, `approved`,
`confirm`, `force`, `sandbox`, or `timeout` anywhere in this file. Each tool
function's parameters ARE its MCP-visible schema -- there is no hidden
top-level argument a caller could add that would reach anything, because
there is no `**kwargs` and no free-form envelope here to smuggle one into.
"""

from __future__ import annotations

from typing import Any

from mcp.server.mcpserver import MCPServer

from server.auth.principal import Principal, resolve_local_principal
from server.auth.roles import load_role_map, resolve_roles
from server.services.operation_service import OperationService, ToolError

mcp = MCPServer("mcp-devvm")

_service: OperationService | None = None
_role_map: dict[str, tuple[str, ...]] = {}


def bind(service: OperationService, role_map: dict[str, tuple[str, ...]]) -> None:
    """Called once at startup by server/main.py after everything is wired."""
    global _service, _role_map
    _service = service
    _role_map = role_map


def _current_principal() -> Principal:
    base = resolve_local_principal()
    return Principal(user_id=base.user_id, display_name=base.display_name, roles=resolve_roles(base.user_id, _role_map))


def _svc() -> OperationService:
    assert _service is not None, "server.tools.mcp_app.bind() was not called"
    return _service


@mcp.tool()
async def list_targets() -> list[dict[str, Any]]:
    """List the dev VMs you may use, as {target_id, label}. Pass a
    target_id to the other tools when there is more than one; with exactly
    one, target_id can be omitted everywhere."""
    return await _svc().list_targets(_current_principal())


@mcp.tool()
async def list_operations(target_id: str | None = None) -> list[dict[str, Any]]:
    """List the operations available on a target: id, a human-readable
    summary, risk class, whether approval is required, and typed parameter
    shapes. This is the complete, fixed set -- there is no way to invoke
    anything not listed here."""
    try:
        return await _svc().list_operations(_current_principal(), target_id)
    except ToolError as exc:
        raise RuntimeError(str(exc)) from exc


@mcp.tool()
async def describe_target(target_id: str | None = None) -> dict[str, Any]:
    """Return a target's id and label. No hostname, port, or credential
    is ever returned -- the agent has no use for those and nothing here
    would give it any."""
    try:
        return await _svc().describe_target(_current_principal(), target_id)
    except ToolError as exc:
        raise RuntimeError(str(exc)) from exc


@mcp.tool()
async def run_operation(operation_id: str, params: dict[str, Any], target_id: str | None = None) -> dict[str, Any]:
    """Run a READ_ONLY operation immediately -- no approval gate. Only
    operations whose manifest marks approval as not required can be invoked
    this way; anything else is rejected. Bounded, sanitized, untrusted-labelled
    output."""
    try:
        return await _svc().run_operation(_current_principal(), operation_id, params, target_id)
    except ToolError as exc:
        raise RuntimeError(str(exc)) from exc


@mcp.tool()
async def request_operation(
    operation_id: str, params: dict[str, Any], reason: str, target_id: str | None = None
) -> dict[str, Any]:
    """Propose an operation for human review. Executes nothing. A human must
    approve the exact operation and parameters in a separate interface
    (the agent cannot reach it). There is no way to skip, pre-approve, or
    auto-approve, and no operation can raise privileges."""
    try:
        return await _svc().request_operation(_current_principal(), operation_id, params, reason, target_id)
    except ToolError as exc:
        raise RuntimeError(str(exc)) from exc


@mcp.tool()
async def check_run_status(approval_id: str) -> dict[str, Any]:
    """Poll the status of a proposed or executing operation. Cannot
    influence the outcome -- this is read-only."""
    try:
        return await _svc().check_run_status(_current_principal(), approval_id)
    except ToolError as exc:
        raise RuntimeError(str(exc)) from exc


@mcp.tool()
async def get_run_output(
    run_id: str, offset: int = 0, limit: int = 65536, target_id: str | None = None
) -> dict[str, Any]:
    """Fetch paged output from a run. The returned text is explicitly
    labelled as untrusted program output, not instructions."""
    try:
        return await _svc().get_run_output(_current_principal(), run_id, offset, limit, target_id)
    except ToolError as exc:
        raise RuntimeError(str(exc)) from exc


@mcp.tool()
async def list_my_pending_approvals() -> list[dict[str, Any]]:
    """List this principal's approvals still awaiting a human decision."""
    return await _svc().list_my_pending_approvals(_current_principal())
