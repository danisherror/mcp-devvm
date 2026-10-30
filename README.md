# mcp-devvm

A working implementation of the architecture in [`MCP_SERVER_DEVVM.md`](./MCP_SERVER_DEVVM.md):
an MCP server that lets an AI agent do real work on a dev VM — run tests, switch
branches, restart services — while being treated as hostile at every step. The
agent never runs a command. It selects a **typed operation** from a fixed,
reviewed registry; a daemon (`devd`) on the VM re-validates and sandboxes it
from the same declaration a human approves; nothing executes without an
human decision that `devd` itself verifies: a signature from an approver
key that only the human can unlock.

This covers the doc's Phases 0–5 (§26.3) against a Docker container standing
in for the dev VM, with namespace-mode (bubblewrap) sandboxing. Phase 6's
production hardening — HSM-backed keys, real cloud IaC, external audit
anchoring, paging — needs real infrastructure this sandbox doesn't have; see
[What's simulated](#whats-simulated-and-why) below for the honest accounting.

**Everything described as "working" here was actually run** — the dev-VM
container is built and driven for real, over a real SSH tunnel, through real
bubblewrap sandboxes, with a real approval CLI in a separate process. 145
tests pass, including 12 integration tests against the live container.

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
                         ══ SSH, cert auth, no forwarding ══
              local unix socket → one SSH session per connection
                → forced command pipes it to devd's unix socket
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
param against its own on-disk manifests, re-checks the per-request token's
operation scope, and — for anything that needs approval — verifies a human
approver's signature over the exact proposal before doing anything.

## Quick start

```bash
uv venv .venv && uv pip install --python .venv/bin/python -e ".[dev]"

# Install a root-owned copy of the approval CLI that the agent can't edit
# (it asks you to confirm the git commit it installs from), and create
# /etc/mcp-devvm/approvers/, the root-owned directory of approver public
# keys that devd trusts. It needs a root-owned Python 3.10+; where the
# system one is older (macOS), it downloads a pinned, hash-checked
# python-build-standalone build into /opt/mcp-devvm-approve-python.
sudo scripts/install_decide.sh

# Build + start the demo dev-VM container, mint the CA and token-signing
# keys, and pin the container's real sshd host key into config/targets.yaml.
.venv/bin/python scripts/setup_dev_vm.py

# Create your approver credential on your FIDO2 security key (a YubiKey or
# similar; set a PIN on it first). It's named after your OS user, one per
# user. The private key never leaves the device: every approval needs a
# touch and the PIN.
/opt/mcp-devvm-approve/bin/approver-keys init

# Enroll it, so devd trusts it. This needs root because the trusted key
# directory must not be writable by you (or an agent running as you). It
# has the plugged-in key sign a fresh challenge (touch + PIN), so only a
# credential on a real key in front of you gets enrolled.
sudo /opt/mcp-devvm-approve/bin/approver-keys enroll

# No security key? `approver-keys init --passphrase` and
# `sudo approver-keys enroll --passphrase-key` use a passphrase-encrypted
# software key instead. It's weaker: see Known limitations.

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
an MCP tool (doc §7.2, B4). Approving asks you to touch your security key
and type its PIN, and signs the exact proposal and effect text you were
shown:

```bash
/opt/mcp-devvm-approve/bin/decide list
/opt/mcp-devvm-approve/bin/decide show appr_xxxxxxxx
/opt/mcp-devvm-approve/bin/decide approve appr_xxxxxxxx
```

(`.venv/bin/python -m server.approvals.decide ...` runs the same code from
the repo. That's fine for trying it out with an agent that has no shell,
but an agent that can edit the repo could change that copy to capture your
PIN or show you one request while signing another.)

For `DESTRUCTIVE` and `PRIVILEGE` operations, devd needs two approvals from
two different OS users, and neither can be the user who made the request.

The running MCP server's background dispatcher notices the approval (a
separate process writing to the same SQLite store) within ~2s and executes
it. `check_run_status(approval_id)` from the agent shows the outcome.

## Using this from VS Code (Copilot Chat agent mode)

VS Code's built-in MCP support (via the GitHub Copilot Chat extension's
Agent mode) reads server definitions from a `.vscode/mcp.json` file in the
workspace. Create one at the repo root:

```json
{
  "servers": {
    "mcp-devvm": {
      "type": "stdio",
      "command": "${workspaceFolder}/.venv/bin/python",
      "args": ["-m", "server.main"],
      "cwd": "${workspaceFolder}"
    }
  }
}
```

On Windows, use `"${workspaceFolder}\\.venv\\Scripts\\python.exe"` instead.

**`cwd` matters here specifically**: `server/main.py` resolves `config/` and
`data/` as paths relative to the process's working directory, not the
script's location — without `"cwd": "${workspaceFolder}"`, VS Code may
launch the server from some other directory and every tool call will fail
looking for a `config/targets.yaml` that isn't there.

Then, before using it:

1. Complete the [Quick start](#quick-start) above first (`.venv` created,
   `scripts/setup_dev_vm.py` has built and started the container) — the
   server has nothing to talk to otherwise.
2. Reload or open the Command Palette (`Cmd/Ctrl+Shift+P`) → **MCP: List
   Servers** to confirm VS Code picked up `mcp-devvm`, or **MCP: Add Server**
   if you'd rather click through the setup instead of hand-writing the JSON
   above (choose "Command (stdio)", point it at the same command/args/cwd,
   and save it to the workspace).
3. Open Copilot Chat, switch the mode dropdown at the bottom of the chat box
   from **Ask**/**Edit** to **Agent**.
4. Click the tools icon (🔧) in the chat input and confirm `mcp-devvm`'s
   tools are enabled — `list_targets`, `list_operations`, `describe_target`,
   `run_operation`, `request_operation`, `check_run_status`,
   `get_run_output`, `list_my_pending_approvals`.
5. Chat normally — e.g. "check out feature/login-fix in the api repo." The
   agent calls `request_operation` and stops there; nothing executes.

**The approval step stays outside VS Code's agent loop, on purpose.**
`server/approvals/decide.py` is deliberately not an MCP tool (doc §7.2,
B4 — the decision channel the agent cannot reach), so approving or denying
what the agent proposed happens in an ordinary VS Code integrated terminal
(`` Ctrl+` ``), same commands as the Quick start section:

```bash
/opt/mcp-devvm-approve/bin/decide list
/opt/mcp-devvm-approve/bin/decide approve appr_xxxxxxxx
```

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
- **Approvals use FIDO2 security keys over USB only.** `decide` talks to
  the key with python-fido2 (CTAP2 over HID). Phones as authenticators,
  Touch ID and NFC aren't supported. Passphrase-encrypted software keys
  remain as an opt-in fallback.
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
- **SQLite control-plane store**, single MCP-server process. Several users
  and targets are supported in config, but only one demo target is
  provisioned by `scripts/setup_dev_vm.py`. The doc says SQLite (WAL, `BEGIN IMMEDIATE`) is adequate for
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
- Real SSH: a genuine certificate-authenticated connection, a genuine
  per-request JWT devd independently verifies against a key it only holds
  the public half of. The tunnel account can't forward anything: TCP and
  stream-local forwarding are both refused, and any command it's asked to
  run only ever reaches devd's socket (`TestTunnelAccountScope`).
- Real human-approval signatures: a DB row marked approved by hand (what an
  agent with a shell could do) is refused by devd with 403, and so is a
  real signature when the effect text shown to the human was altered
  (`TestApprovalSignatures`).
- Real cross-plane enforcement (B5): a token minted for one operation is
  rejected (403) if replayed against a different operation's endpoint.
- Real manifest-version binding: a proposal made against an older
  manifest version settles `STALE`, not silently run against different
  code; editing the stored version without a matching hash settles
  `UNAUTHORIZED`.
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
.venv/bin/python scripts/setup_dev_vm.py --test-approvers
.venv/bin/python -m pytest tests/integration -q   # against the live container
```

The integration tests trust throwaway approver keys by writing them into
devd's key directory, so they need a VM set up with `--test-approvers`,
which mounts a directory your user can write. Don't use that VM with an
agent connected. Against a normal VM, the tests that approve something
are skipped.

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
scripts/           SSH CA, token-signing keypair, approver keys, dev-VM setup
config/            targets.yaml (server-side only), policy.yaml, roles.yaml
tests/             unit, adversarial (isolation/structural), integration
                   (against the real container)
```

## Known limitations to know about before extending this

- **The approval CLI is only as safe as the copy you run.** Signed
  approvals stop an agent from approving on its own: writing the DB, or
  using the server's token key (both readable by your OS user), no longer
  gets anything that needs approval past devd. The repo copy of
  `decide.py` can be edited by an agent, so use the root-owned copy from
  `sudo scripts/install_decide.sh`, invoked by its full path. That copy
  still runs as your OS user, in a terminal the agent can tamper with
  (e.g. through your shell startup files). With a security key, that gets
  the agent at most one signature per touch, and only while you're
  approving: it could show you one request while the key signs another,
  but it can't sign on its own or reuse your PIN without the key and your
  touch. Only a separate trusted display (approving on another device)
  closes that last gap. With a passphrase key it's much worse: a captured
  passphrase plus the encrypted key file lets the agent sign forever, so
  use a security key if at all possible.
- **Enrolling approvers needs root.** devd only trusts public keys in
  the root-owned `/etc/mcp-devvm/approvers/`, so an agent running as you
  can't add one of its own. Adding a person means `sudo approver-keys
  enroll`; revoking one means `sudo rm /etc/mcp-devvm/approvers/<user>.fido`
  (or `.pub` for a passphrase key).
  Keys from before this change in `data/approvers/public/` are no longer
  trusted: enroll them again.
- **Multiple users and targets need some setup by hand.** Add users to
  `config/roles.yaml` and give each approver their own key; add targets to
  `config/targets.yaml` and `config/policy.yaml`. The agent passes
  `target_id` when there's more than one. `scripts/setup_dev_vm.py` only
  provisions the one demo container.
- No egress allowlist / IMDS blocking / disk quota enforcement on the VM
  side beyond what `vm/harden.sh` does (link-local block, permission
  checks) — real §17 blast-radius hardening needs a real VM and IaC.

## License

MIT — see [LICENSE](./LICENSE).
