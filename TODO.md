# TODO

Remaining work, most important first. Details and context for each item
are in [ROADMAP.md](./ROADMAP.md).

## Security gaps (fix first)

- [ ] **The protected `decide` still runs in your shell.** `scripts/install_decide.sh` stops repo edits from reaching the CLI, but an agent can edit your shell startup files (e.g. define a function named `/opt/mcp-devvm-approve/bin/decide`). A hardware key / passkey, or approving from a separate OS account, closes this. (ROADMAP Known gap #4)

## Robustness (small)

- [ ] **Second approvers on one machine.** `sudo approver-keys enroll --user bob` reads `data/approvers/private/bob.key` from this repo, so every approver's private key has to sit in one user's checkout. Let each user keep theirs in their own home directory.

## Quick wins (no new infrastructure)

- [ ] **CI:** run `tests/unit` and `tests/adversarial` on every push; integration tests where Docker is available.
- [ ] **Cross-plane correlation report:** flag any devd run with no matching approval (doc §18.4).
- [ ] **Test the root-only paths:** `install_decide.sh` and `approver-keys enroll` were only tested without root. Run them as root in a Linux CI container.

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

- [x] `install_decide.sh` installs its dependencies with `pip --require-hashes` from `scripts/requirements/decide.txt`, read from the commit being installed.
- [x] The tunnel's local socket is bound under a `0177` umask, so it is never connectable by other users, even briefly.
- [x] The tunnel bridge waits for the SSH channel (`drain()`) before reading more, so a large request isn't buffered fully in memory.
- [x] Approver signatures last until the approval's deadline plus the 120s execution window, so the first four-eyes signature can't expire before the second approver signs.
- [x] The server asks for as many approvers as devd (`required_approvers()`): DESTRUCTIVE always needs two, whatever the policy file says, and the store won't mark APPROVED with fewer.
- [x] A malformed approver `.pub` file is skipped with a warning instead of failing every approval.
- [x] Approver keys are enrolled by root: devd trusts only the root-owned `/etc/mcp-devvm/approvers/`, `sudo approver-keys enroll` derives the public key from the passphrase-unlocked private key, and `setup_dev_vm.py` refuses a user-writable key directory (except `--test-approvers`).
- [x] Root-owned copy of the approval CLI: `sudo scripts/install_decide.sh` installs `decide` and `approver-keys` from a reviewed commit into `/opt/mcp-devvm-approve`, run with `python -I`.
- [x] Four-eyes counts people: approver keys are named after one OS user, one key per user.
- [x] No self-approval on four-eyes: devd refuses a signature from the requester's key (`self_approval`), and `decide` and the store refuse it first.
- [x] Fix `decide list` crashing with `'async_generator' object is not iterable`.
- [x] Signed human approvals, verified by devd: a forged DB row or a stolen token key can't run anything that needs approval (ROADMAP Known gap #4).
- [x] SSH tunnel account can no longer forward ports: all forwarding off, every session forced into a pipe to devd's socket (ROADMAP Known gap #1).
- [x] Several users and targets: `target_id` on the MCP tools, `list_targets`, per-user step-up, separate approver keys (ROADMAP Known gap #3).
- [x] Fix `scripts/setup_dev_vm.py` pinning the wrong tunnel source address on Docker Desktop (macOS), which made every SSH login fail there.
- [x] MIT license and GitHub topics.
- [x] Recompute the proposal hash at approval and execution time (ROADMAP Known gap #5).
- [x] Rename `[0] MCP_SERVER_DEVVM.md` to `MCP_SERVER_DEVVM.md`.
