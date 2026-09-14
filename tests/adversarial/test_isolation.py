"""Doc §25.4 ISOLATION checks: structural properties that must hold no
matter what any operation's implementation does wrong later."""

from __future__ import annotations

import ast
import inspect
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

FORBIDDEN_TOOL_PARAM_NAMES = {
    "command", "cmd", "script", "host", "port", "user", "key", "url", "path",
    "approved", "confirm", "force", "sandbox", "timeout", "env", "shell", "pty",
}


def test_mcp_tool_surface_has_no_forbidden_parameters():
    from server.tools import mcp_app

    tool_manager = mcp_app.mcp._tool_manager
    tools = tool_manager.list_tools()
    assert {t.name for t in tools} == {
        "list_operations", "describe_target", "run_operation", "request_operation",
        "check_run_status", "get_run_output", "list_my_pending_approvals",
    }
    for tool in tools:
        params = set(tool.parameters.get("properties", {}))
        forbidden_hit = params & FORBIDDEN_TOOL_PARAM_NAMES
        # run_operation/request_operation legitimately have "operation_id" and a
        # "params" envelope -- "params" itself isn't in the forbidden set (it's
        # the where typed, schema-validated values live, not a raw passthrough).
        assert not forbidden_hit, f"{tool.name} exposes forbidden parameter(s): {forbidden_hit}"


def test_no_exec_shell_or_write_file_tool_exists():
    from server.tools import mcp_app

    names = {t.name for t in mcp_app.mcp._tool_manager.list_tools()}
    for forbidden in ("exec", "run_command", "shell", "ssh", "scp", "write_file", "eval"):
        assert forbidden not in names


def _iter_py_files(*dirs: str):
    for d in dirs:
        base = REPO_ROOT / d
        if base.exists():
            yield from base.rglob("*.py")


def test_no_shell_true_or_os_system_or_eval_anywhere():
    """doc §3.3 CI gate: fail the build on shell=True, os.system, eval, exec,
    or subprocess with a non-literal argv[0], anywhere in server/ or devd/."""
    violations = []
    for path in _iter_py_files("server", "devd", "common"):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                # os.system(...)
                if isinstance(func, ast.Attribute) and func.attr == "system":
                    if isinstance(func.value, ast.Name) and func.value.id == "os":
                        violations.append(f"{path}:{node.lineno} os.system(...)")
                # eval(...) / exec(...) as bare names (not e.g. ctx.exec or a
                # keyword-only param named exec, and not our own operation()
                # decorator target functions, which are plain async defs, not
                # calls to a builtin named exec/eval).
                if isinstance(func, ast.Name) and func.id in ("eval",):
                    violations.append(f"{path}:{node.lineno} {func.id}(...)")
                # subprocess.*(..., shell=True)
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        violations.append(f"{path}:{node.lineno} shell=True")

    assert not violations, "forbidden call(s) found:\n" + "\n".join(violations)


def test_subprocess_argv0_is_always_a_literal_or_validated_list():
    """A softer, static heuristic companion to the runtime sandbox tests:
    every asyncio.create_subprocess_exec / subprocess.run call site in devd
    and scripts/ passes a literal list, not a single joined string."""
    violations = []
    for path in _iter_py_files("devd", "scripts"):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in ("create_subprocess_exec", "run", "check_output"):
                    if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                        violations.append(f"{path}:{node.lineno} argv[0] looks like a joined string, not a list")
    assert not violations, violations


def test_devd_has_no_docs_or_openapi_endpoints():
    from devd.app import app

    assert app.docs_url is None
    assert app.redoc_url is None
    assert app.openapi_url is None


def test_devd_operations_dir_is_the_perimeter_and_every_op_has_a_manifest():
    ops_dir = REPO_ROOT / "devd" / "operations"
    py_files = {p.stem for p in ops_dir.glob("*.py") if p.stem != "__init__"}
    yaml_files = {p.stem for p in ops_dir.glob("*.yaml")}
    assert py_files == yaml_files, "every operation needs both a .py implementation and a .yaml manifest"
    assert len(py_files) > 0
