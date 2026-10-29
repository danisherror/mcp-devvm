# TODO

Remaining work, most important first. Details and context for each item
are in [ROADMAP.md](./ROADMAP.md).

## Security gaps (fix first)

- [ ] **Isolate the approval channel from the agent.** Any agent with a shell can run `decide approve` or edit `data/approvals.db`. Run the approval store and CLI as a separate OS user, or require approvals signed with a key the agent can't read. Also makes the proposal hash unforgeable. (ROADMAP Known gap #4)
- [ ] **Scope the SSH tunnel account to devd's socket only.** `PermitOpen any` currently allows forwarding to any TCP host:port. Re-test on your OpenSSH version, or move to the outbound job-queue transport (doc §11.4). (ROADMAP Known gap #1)

## Quick wins (no new infrastructure)

- [ ] **CI:** run `tests/unit` and `tests/adversarial` on every push; integration tests where Docker is available.
- [ ] **Update ROADMAP's "Suggested next step"** — it still lists the hash recompute fix, which is done.
- [ ] **Cross-plane correlation report:** flag any devd run with no matching approval (doc §18.4).

## Features

- [ ] **`NETWORK_EXEC` operations** (`npm install`, running tests) with a per-run container sandbox (doc §14.3).
- [ ] **`DESTRUCTIVE` operations** with four-eyes approval and pre-run snapshots — the approval mechanism already exists.
- [ ] **Push notifications** to the approver when a request arrives (currently pull-only via `decide list`).
- [ ] **Multiple users and targets** — generalize `server/main.py`'s single-target pick and `config/roles.yaml`.

## Hardening (Phase 6)

- [ ] **Effect-conformance tests** under strace/auditd: verify each operation touches only its declared reads/writes (doc §25.2).
- [ ] **External audit anchor** + nightly `verify_chain()` run.
- [ ] **More rate limits:** per-session output-byte cap, concurrent-run cap.
- [ ] **Monitoring and alerts** for audit signals (`RUN_NEEDS_HUMAN`, `SANDBOX_VIOLATION`, unpaired intent) plus runbooks (doc §26.2).
- [ ] **VM resource limits:** disk quota, `noexec` on world-writable mounts, cgroup `TasksMax`/`MemoryMax`.
- [ ] **Production infrastructure:** real IaC provisioning, timed rebuild drill, HSM/KMS for CA and token keys, break-glass procedure.

## Housekeeping

- [ ] Rename the repo folder from `template-mcp-server` to `mcp-devvm`.

## Done

- [x] Recompute the proposal hash at approval and execution time (ROADMAP Known gap #5).
- [x] Rename `[0] MCP_SERVER_DEVVM.md` to `MCP_SERVER_DEVVM.md`.
