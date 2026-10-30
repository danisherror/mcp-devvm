# TODO

Remaining work, most important first. Details and context for each item
are in [ROADMAP.md](./ROADMAP.md).

## Security gaps (fix first)

- [ ] **`sudo scripts/install_decide.sh` runs the installer from the working tree as root.** The script copies code from a reviewed commit, but the script itself is whatever is in the repo right now, which the agent can edit before you run it. Run it from the reviewed commit instead (e.g. `git show <commit>:scripts/install_decide.sh | sudo sh -s -- <commit>`) and document that, or ship a tiny root-owned bootstrap.
- [ ] **Try the security-key flow with a real YubiKey.** `init`, `enroll` and `decide approve` are tested through the real python-fido2 client against a software authenticator (`tests/soft_fido.py`, including the PIN protocol), but not yet against hardware.
- [ ] **Approve on a separate trusted display.** With a security key, the agent can no longer sign on its own, but it still controls the terminal that shows you the request, so it could show one request while the key signs another (one forged approval per real one). Approving on a phone or other device that renders the effect text itself closes this. (ROADMAP Known gap #4)
- [ ] **Use the security key's signature counter** to spot a cloned key: devd could reject a counter that doesn't increase per approver.

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

- [x] Approvals are signed by a FIDO2 security key (touch + PIN, enforced by devd); the private key never leaves the device, so capturing what you type no longer lets the agent sign by itself. Passphrase keys are opt-in (`init --passphrase`, `enroll --passphrase-key`). `install_decide.sh` falls back to a pinned, hash-checked standalone Python where the system one is older than 3.10 (macOS). (ROADMAP Known gap #4)
- [x] Cross-plane correlation report: `python -m scripts.correlate --container mcp-devvm-dev-vm` flags any devd run the server's approvals don't explain (doc §18.4). Run it on a schedule; the auditd half needs auditd.
- [x] Root-only paths tested as root in an Ubuntu container (`tests/root/`, also in CI). This found two bugs that stopped `install_decide.sh` from running on Linux at all: it read file owners with BSD `stat` syntax, and treated the `/usr/bin/python3` symlink as world-writable.
- [x] CI (`.github/workflows/ci.yml`): unit and adversarial tests on every push and PR (Python 3.11 and 3.12), integration tests against the dev-VM container.
- [x] Approver private keys live in each user's home (`~/.mcp-devvm/approver/<user>.key`), so several approvers can share a machine; `enroll` as root reads them without following symlinks and checks the file belongs to that user. Old keys in `data/approvers/private/` still work.
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
