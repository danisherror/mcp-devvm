# mcp-devvm

A working implementation of the architecture in [`[0] MCP_SERVER_DEVVM.md`](./%5B0%5D%20MCP_SERVER_DEVVM.md):
an MCP server that lets an AI agent do real work on a dev VM — run tests, switch
branches, restart services — while being treated as hostile at every step. The
agent never runs a command. It selects a **typed operation** from a fixed,
reviewed registry; a daemon (`devd`) on the VM re-validates and sandboxes it
from the same declaration a human approves; nothing executes without an
out-of-band human decision.

This covers the doc's Phases 0–5 (§26.3) against a Docker container standing
in for the dev VM, with namespace-mode (bubblewrap) sandboxing. Phase 6's
production hardening — HSM-backed keys, real cloud IaC, external audit
anchoring, paging — needs real infrastructure this sandbox doesn't have; see
[What's simulated](#whats-simulated-and-why) below for the honest accounting.

**Everything described as "working" here was actually run** — the dev-VM
container is built and driven for real, over a real SSH tunnel, through real
bubblewrap sandboxes, with a real approval CLI in a separate process. 107
tests pass, including 7 integration tests against the live container.

See [ARCHITECTURE.md](./ARCHITECTURE.md) for two diagrams — the request
lifecycle end to end, and which file talks to which and when — and
[ROADMAP.md](./ROADMAP.md) for what's done vs. outstanding against the
doc's own build order.

## Architecture

```
🤖 Agent → MCP Client → MCP Server (server/, this host)
                              │
                              ├─ policy · proposals · approvals (SQLite)
                              ├─ audit (hash-chained JSONL)
                              │
                         ══ SSH tunnel, cert auth ══
                    local unix socket → remote unix socket
                              │
                              ▼
                    devd (devd/, the "VM" container)
                              │
                    operation registry · own validation
                    · own policy · sandbox from manifest
                              │
                              ▼
                    bubblewrap namespace · git/tail/tee
                    · run records · local audit
```

Two independent enforcement points (doc's B5): a compromised control plane
still can't exceed the operation set, because `devd` re-validates every
param against its own on-disk manifests and re-checks the per-request token's
operation scope before doing anything.

## Quick start

```bash
uv venv .venv && uv pip install --python .venv/bin/python -e ".[dev]"

# Build + start the demo dev-VM container, mint the CA and token-signing
# keys, and pin the container's real sshd host key into config/targets.yaml.
.venv/bin/python scripts/setup_dev_vm.py

# Run the MCP server (stdio transport) -- wire this into Claude Code / any
# MCP client the same way you would any other stdio server:
#   command: <repo>/.venv/bin/python
#   args:    ["-m", "server.main"]
#   cwd:     <repo>
.venv/bin/python -m server.main
```

From the agent, `request_operation("git.checkout", {"repo": "api", "branch": "..."}, "reason")`
returns `{"approval_id": ..., "status": "PENDING"}` and executes nothing.
Approve or deny it from a **separate terminal** — this is deliberately not
an MCP tool, so the agent cannot reach it (doc §7.2, B4):

```bash
.venv/bin/python -m server.approvals.decide list
.venv/bin/python -m server.approvals.decide show appr_xxxxxxxx
.venv/bin/python -m server.approvals.decide approve appr_xxxxxxxx
```

The running MCP server's background dispatcher notices the approval (a
separate process writing to the same SQLite store) within ~2s and executes
it. `check_run_status(approval_id)` from the agent shows the outcome.

## The shipped operations

Four operations across three risk classes — enough to exercise the whole
pipeline without the scope of NETWORK_EXEC/container-sandboxing or
DESTRUCTIVE/four-eyes, which this build skips (see below):

| operation | risk | approval | what it does |
|---|---|---|---|
| `git.status` | READ_ONLY | none | branch, HEAD, dirty state for a workspace repo |
| `logs.tail` | READ_ONLY | none | last N lines of the demo app log |
| `git.checkout` | MUTATING_LOCAL | required | switch branches locally, with precondition check-and-act |
| `service.restart` | SERVICE_CONTROL | required + step-up | rewrites a state file (stand-in for `systemctl restart`) |

Add a new one by dropping a `<name>.yaml` manifest + `<name>.py`
implementation into `devd/operations/` (see `git_checkout.py` for the
shape) — `devd/registry.py` picks it up automatically.

## What's simulated, and why

Being upfront about every substitution, so nothing here is mistaken for a
production posture:

- **`--privileged` on the dev-VM container.** Bubblewrap needs unprivileged
  user-namespace creation, which this sandbox's own Docker doesn't grant to a
  nested container without it (tested: fails with `pivot_root: Operation not
  permitted` under narrower capability sets). On a real, non-containerized
  dev VM kernel, bubblewrap works unprivileged out of the box — this flag is
  purely an artifact of running the "VM" as a container inside this
  environment's own container.
- **Software SSH CA, not HSM-backed** (`scripts/ca.py`). Real `ssh-keygen -s`
  mechanics — short-lived certs, source-address pinning, principal
  attribution — just with the CA private key as a 0600 file instead of in a
  KMS. The doc's own fallback ladder for topology-A-without-CA-infra
  explicitly allows this.
- **`PermitOpen any` on the tunnel account, not a path-scoped allow.**
  Genuinely tested, not assumed: this OpenSSH build (9.2p1/Debian) treats
  `AllowTcpForwarding no` as a blanket kill-switch that also blocks
  stream-local forwarding, and `PermitOpen` has no syntax here that permits
  one specific unix-socket path while excluding TCP destinations — `any` is
  the only value that unblocks the streamlocal forward we need, and it
  unblocks arbitrary TCP-to-TCP forwarding along with it. Full writeup and
  the exact failure modes we hit are in `vm/sshd_config.d/devd-tunnel.conf`.
  This is a real, open gap versus the doc's intent, mitigated only by the
  container exposing no other meaningful listening service. A production
  build should re-verify against its actual OpenSSH version, or use the
  outbound-job-queue transport (doc §11.4) instead.
- **`devd`'s mutating-call handling runs synchronously**, not backgrounded
  with polling (doc §13.5). Every shipped operation finishes in well under a
  second, so `POST /operations/{id}/run` awaits completion and returns the
  terminal status directly, while still writing a durable run record
  *before* the effect starts with `status` written last — so `GET
  /runs/{id}` and idempotency-key replay behave identically to the fully
  backgrounded design even if the HTTP response never reaches the caller
  (exercised for real in `tests/integration/test_end_to_end.py::TestFaultInjection`).
  A genuinely long-running operation would need `asyncio.create_task` +
  polling; nothing else here would need to change to support that.
- **SQLite control-plane store**, single MCP-server process, single demo
  user/target. The doc says SQLite (WAL, `BEGIN IMMEDIATE`) is adequate for
  the local topology; this just doesn't scale it to Postgres/multi-tenant.
- **CLI approval (`server/approvals/decide.py`), not a web UI.** The doc
  treats the decision path as "the human path — NOT an MCP tool"; a
  terminal satisfies that boundary as well as a browser does, just with a
  plainer rendering of §19/§23's UI rules (never truncate, show
  writes/reads/network/services even when empty, typed confirmation for
  high-risk classes, a rate indicator).
- **No NETWORK_EXEC / container-sandbox mode, no DESTRUCTIVE / four-eyes
  operations.** Deliberately out of scope for this build (namespace-mode
  sandboxing only) — §14.3's ephemeral-container-per-run design for
  `npm install`-style operations is unbuilt, and so is the four-eyes /
  typed-confirmation path for anything actually destructive, though the
  approval store's `approvals_required` mechanism and the CLI's high-risk
  confirmation prompt both already support it structurally.
- **No Phase 6 hardening**: no external audit-chain anchor, no real IaC
  provisioning or quarterly rebuild drill, no HSM/KMS, no paging/monitoring
  stack, no `cgroup`/disk-quota resource limits beyond what bubblewrap's
  namespace isolation gives for free. The hash-chained JSONL audit sink
  (`server/audit/sink.py`) is the local piece such a pipeline would ship
  off-box; nothing here does the shipping.

## What's real and independently verified

Not simplified, not mocked — each of these was driven end-to-end against
the live container and is covered by a passing test:

- Real bubblewrap sandboxing: verified undeclared reads fail (`No such file
  or directory`), undeclared writes land in a throwaway filesystem (never
  the real host path), network is unreachable when undeclared.
- Real SSH: a genuine certificate-authenticated tunnel, a genuine
  local-unix-socket-to-remote-unix-socket forward, a genuine per-request
  JWT devd independently verifies against a key it only holds the public
  half of.
- Real cross-plane enforcement (B5): a token minted for one operation is
  rejected (403) if replayed against a different operation's endpoint.
- Real manifest-version binding: mutating an approval's stored
  `manifest_version` after proposal makes execution settle `STALE`, not
  silently run against different code.
- Real precondition check-and-act: `git.checkout` re-verifies `HEAD` and
  worktree cleanliness *inside the sandboxed operation*, microseconds before
  the mutation; stale preconditions get `409 precondition_drift`.
- Real idempotency: replaying the same `Idempotency-Key` never re-executes,
  whether the original attempt settled or never started.
- Real fault injection: a simulated transport drop mid-call settles
  `UNKNOWN`, never `SUCCEEDED`/`OP_FAILED`; the reconciler (a real polling
  task, not a mock) resolves it via devd's own idempotency-keyed run
  lookup — read-only, never re-executing — and escalates to `NEEDS_HUMAN`
  once genuinely exhausted.
- Real hash-chained audit trail: tampering with any past record breaks
  `verify_chain()`.

## Testing

```bash
.venv/bin/python -m pytest tests/unit -q          # pure logic, no infra
.venv/bin/python -m pytest tests/adversarial -q   # isolation/structural gates
.venv/bin/python scripts/setup_dev_vm.py           # (if not already up)
.venv/bin/python -m pytest tests/integration -q   # against the live container
```

## Project layout

```
server/            control plane: auth, policy, proposals, approvals (CAS
                   store + state machine + CLI decide.py), execution
                   (executor/triage/reconciler/dispatcher), tunnel (the
                   ONLY module that opens SSH), audit, the MCP tool surface
devd/              data plane: FastAPI app, operation framework
                   (OperationContext/Workspace/Precondition), bubblewrap
                   sandbox builder+runner, operations/ (the perimeter)
common/            shared pure logic: param validation, canonical JCS-like
                   hashing, output sanitize/redact -- independently invoked
                   by both planes, never a trust dependency between them
vm/                the container standing in for the dev VM: Dockerfile,
                   sshd hardening, entrypoint, demo data seeding
scripts/           SSH CA, token-signing keypair, dev-VM setup orchestrator
config/            targets.yaml (server-side only), policy.yaml, roles.yaml
tests/             unit, adversarial (isolation/structural), integration
                   (against the real container)
```

## Known limitations to know about before extending this

- Single target, single demo user, roles hardcoded to one principal in
  `config/roles.yaml` — extend that file and `server/main.py`'s
  single-target assumption before treating this as multi-tenant.
- The `PermitOpen any` gap above is the one item worth re-testing against
  your actual OpenSSH version before trusting the tunnel account's scoping
  in anything beyond a single-purpose demo container.
- No egress allowlist / IMDS blocking / disk quota enforcement on the VM
  side beyond what `vm/harden.sh` does (link-local block, permission
  checks) — real §17 blast-radius hardening needs a real VM and IaC.
