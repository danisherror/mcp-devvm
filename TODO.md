# TODO

Remaining work, most important first. Details and context for each item
are in [ROADMAP.md](./ROADMAP.md).

## Security gaps (fix first)

- [ ] **Protect the approval CLI itself.** Approvals are now signed and checked by devd, but an agent that can edit the repo could modify `decide.py` to capture the passphrase. Run `decide` from a copy the agent can't write, or move approver keys to a hardware key / passkey. (ROADMAP Known gap #4)

## Quick wins (no new infrastructure)

- [ ] **CI:** run `tests/unit` and `tests/adversarial` on every push; integration tests where Docker is available.
- [ ] **Cross-plane correlation report:** flag any devd run with no matching approval (doc §18.4).

## Features

- [ ] **`NETWORK_EXEC` operations** (`npm install`, running tests) with a per-run container sandbox (doc §14.3).
- [ ] **`DESTRUCTIVE` operations** with four-eyes approval and pre-run snapshots — the approval mechanism already exists.
- [ ] **Push notifications** to the approver when a request arrives (currently pull-only via `decide list`).
- [ ] **Provision more than one demo target** in `scripts/setup_dev_vm.py` (the server side already supports several).
- [ ] **Demo GIF** of propose → approve → run at the top of the README.

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

- [x] Signed human approvals, verified by devd: a forged DB row or a stolen token key can't run anything that needs approval (ROADMAP Known gap #4).
- [x] SSH tunnel account can no longer forward ports: all forwarding off, every session forced into a pipe to devd's socket (ROADMAP Known gap #1).
- [x] Several users and targets: `target_id` on the MCP tools, `list_targets`, per-user step-up, one approver key per person (ROADMAP Known gap #3).
- [x] Fix `scripts/setup_dev_vm.py` pinning the wrong tunnel source address on Docker Desktop (macOS), which made every SSH login fail there.
- [x] MIT license and GitHub topics.

- [x] Recompute the proposal hash at approval and execution time (ROADMAP Known gap #5).
- [x] Rename `[0] MCP_SERVER_DEVVM.md` to `MCP_SERVER_DEVVM.md`.
