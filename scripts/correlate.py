"""Cross-plane correlation report (doc §18.4): every run devd accepted must
be explained by an approval on the MCP server. A run that isn't means a
bypass -- a stolen token key, a second access path, a forged request.

    python -m scripts.correlate --container mcp-devvm-dev-vm
    python -m scripts.correlate --runs-dir /path/to/shipped/devd/runs

Reads devd's run records (meta.json in each run directory, written before
the operation starts) and the server's approval store (data/approvals.db),
and flags:

  - a run that needs approval but names no approval, or one the server
    doesn't have;
  - a run whose operation, principal or target differs from its approval;
  - a run for an approval that was never approved, or that started
    outside the approval's decision-to-execution window;
  - more than one run for the same approval;
  - a direct (no-approval) run of an operation whose manifest requires
    approval;
  - an approval the server says ran, with no run on devd (lower severity:
    usually a lost record, but worth a look).

Exits 1 when anything is flagged, and 2 when it can't read the records,
so it can run from cron or CI. Read the
runs from a copy shipped off the VM when you can: devd's own copy is only
as trustworthy as the VM.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB = ROOT / "data" / "approvals.db"
DEFAULT_OPERATIONS = ROOT / "devd" / "operations"
DEFAULT_TARGET = "dev-vm-01"
CONTAINER_RUNS_DIR = "/var/lib/devd/runs"

# The approval_id devd records for runs that skipped approval
# (server/services/operation_service.py run_operation).
DIRECT_READ = "n/a:direct-read"

# Approval statuses a devd run can legitimately follow. STALE is here
# because devd records the run before it finds the preconditions drifted.
RAN_STATUSES = frozenset({
    "CLAIMED", "RUNNING", "UNKNOWN", "SUCCEEDED", "OP_FAILED", "TIMED_OUT", "STALE", "NEEDS_HUMAN",
})
# Statuses where the server believes a run happened.
SERVER_SAYS_RAN = frozenset({"RUNNING", "SUCCEEDED", "OP_FAILED", "TIMED_OUT"})

CLOCK_SKEW_S = 30


@dataclass(frozen=True)
class Finding:
    severity: str  # "bypass" or "check"
    run_id: str | None
    approval_id: str | None
    problem: str

    def as_dict(self) -> dict[str, Any]:
        return {"severity": self.severity, "run_id": self.run_id, "approval_id": self.approval_id,
                "problem": self.problem}


def load_runs(runs_dir: Path) -> list[dict[str, Any]]:
    runs = []
    for meta_path in sorted(runs_dir.glob("*/meta.json")):
        try:
            meta = json.loads(meta_path.read_text())
        except (OSError, ValueError):
            meta = {}
        meta["run_id"] = meta_path.parent.name
        runs.append(meta)
    return runs


def load_approvals(db_path: Path) -> dict[str, dict[str, Any]]:
    if not db_path.is_file():
        raise FileNotFoundError(f"no approval store at {db_path}")
    # Read-only, so running the report can never change the store.
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT id, principal_id, target_id, operation_id, status, decided_at, approved_expires_at, run_id "
            "FROM approvals"
        ).fetchall()
    finally:
        conn.close()
    return {row["id"]: dict(row) for row in rows}


def approval_free_operations(operations_dir: Path) -> set[str]:
    """Operations whose manifest lets them run without approval. Same rule
    as common/manifest.py: anything but `approval: not_required` needs it."""
    free = set()
    for path in operations_dir.glob("*.yaml"):
        raw = yaml.safe_load(path.read_text()) or {}
        if raw.get("id") and raw.get("approval", "required") != "required":
            free.add(raw["id"])
    return free


def correlate(
    runs: list[dict[str, Any]], approvals: dict[str, dict[str, Any]], *, target_id: str,
    approval_free_ops: set[str],
) -> list[Finding]:
    findings: list[Finding] = []
    runs_by_approval: dict[str, list[str]] = {}

    for run in runs:
        run_id = run["run_id"]
        approval_id = run.get("approval_id")
        op = run.get("operation_id")

        def flag(problem: str, severity: str = "bypass") -> None:
            findings.append(Finding(severity, run_id, approval_id, problem))

        if not approval_id or not op or "principal" not in run or "started_at" not in run:
            flag("run record is missing fields (meta.json unreadable or incomplete)")
            continue
        if approval_id == DIRECT_READ:
            if op not in approval_free_ops:
                flag(f"{op} ran without approval, but its manifest requires approval")
            continue
        if approval_id.startswith("n/a:"):
            flag(f"{op} ran with a non-run token ({approval_id})")
            continue

        runs_by_approval.setdefault(approval_id, []).append(run_id)
        approval = approvals.get(approval_id)
        if approval is None:
            flag("no matching approval on the server")
            continue
        if approval["operation_id"] != op:
            flag(f"ran {op}, but the approval is for {approval['operation_id']}")
        if approval["principal_id"] != run["principal"]:
            flag(f"ran as {run['principal']}, but the approval was requested by {approval['principal_id']}")
        if approval["target_id"] != target_id:
            flag(f"ran on {target_id}, but the approval is for {approval['target_id']}")
        if approval["status"] not in RAN_STATUSES:
            flag(f"approval is {approval['status']}, which never allows a run")
        started = float(run["started_at"])
        if approval["decided_at"] is not None and started < approval["decided_at"] - CLOCK_SKEW_S:
            flag("run started before the approval was decided")
        if approval["approved_expires_at"] is not None and started > approval["approved_expires_at"] + CLOCK_SKEW_S:
            flag("run started after the approval's execution window closed")
        if approval["run_id"] and approval["run_id"] != run_id:
            flag(f"the server recorded run {approval['run_id']} for this approval, not this one")

    for approval_id, run_ids in runs_by_approval.items():
        if len(run_ids) > 1:
            findings.append(Finding("bypass", ", ".join(run_ids), approval_id,
                                    f"{len(run_ids)} runs for one approval"))

    for approval in approvals.values():
        if (approval["target_id"] == target_id and approval["status"] in SERVER_SAYS_RAN
                and approval["id"] not in runs_by_approval):
            findings.append(Finding("check", approval["run_id"], approval["id"],
                                    f"server says this ran ({approval['status']}), but devd has no run for it"))
    return findings


def _runs_from_container(container: str, dest: Path) -> Path:
    """Copy just the run metadata out of the dev-VM container."""
    tar_path = dest / "runs.tar"
    with tar_path.open("wb") as f:
        subprocess.run(
            ["docker", "exec", container, "sh", "-c",
             f"cd {CONTAINER_RUNS_DIR} && find . -name meta.json -print0 | tar --null -T - -cf -"],
            stdout=f, check=True,
        )
    out = dest / "runs"
    out.mkdir()
    if tar_path.stat().st_size:
        with tarfile.open(tar_path) as tar:
            members = [m for m in tar.getmembers() if m.isfile() and Path(m.name).name == "meta.json"
                       and ".." not in Path(m.name).parts and not Path(m.name).is_absolute()]
            safe = {"filter": "data"} if hasattr(tarfile, "data_filter") else {}
            tar.extractall(out, members=members, **safe)
    return out


def main() -> None:
    parser = argparse.ArgumentParser(prog="correlate", description=__doc__.split("\n\n")[0])
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--runs-dir", type=Path, help="a copy of devd's runs directory")
    source.add_argument("--container", help="read the runs from this dev-VM container via docker")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB, help=f"approval store (default: {DEFAULT_DB})")
    parser.add_argument("--target", default=DEFAULT_TARGET, help="the target the runs came from")
    parser.add_argument("--operations-dir", type=Path, default=DEFAULT_OPERATIONS)
    parser.add_argument("--json", action="store_true", help="print findings as JSON")
    args = parser.parse_args()

    try:
        approvals = load_approvals(args.db)
        with tempfile.TemporaryDirectory() as tmp:
            runs_dir = _runs_from_container(args.container, Path(tmp)) if args.container else args.runs_dir
            if not runs_dir.is_dir():
                raise FileNotFoundError(f"no runs directory at {runs_dir}")
            runs = load_runs(runs_dir)
    except (OSError, sqlite3.Error, subprocess.CalledProcessError, tarfile.TarError) as exc:
        # Exit 2, not 1: the report didn't run, which is different from
        # "it ran and found something".
        print(f"correlate: can't read the records: {exc}", file=sys.stderr)
        sys.exit(2)
    findings = correlate(runs, approvals, target_id=args.target,
                         approval_free_ops=approval_free_operations(args.operations_dir))

    if args.json:
        print(json.dumps([f.as_dict() for f in findings], indent=2))
    else:
        print(f"{len(runs)} devd run(s) on {args.target}, {len(approvals)} approval(s) on the server")
        if not findings:
            print("OK: every run matches an approval")
        for f in findings:
            print(f"[{f.severity.upper()}] run={f.run_id or '-'} approval={f.approval_id or '-'}: {f.problem}")
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
