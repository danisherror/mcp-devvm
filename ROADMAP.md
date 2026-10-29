# Roadmap

Status against the doc's own build order ([`MCP_SERVER_DEVVM.md`](./MCP_SERVER_DEVVM.md) §26.3).
See [ARCHITECTURE.md](./ARCHITECTURE.md) for how the pieces below actually
talk to each other, and the README's "What's simulated" / "What's real"
sections for the honest accounting behind each line here.

**Scope note:** this build deliberately stopped after Phase 5, and within
that, deliberately excluded `NETWORK_EXEC`/container-sandbox operations and
`DESTRUCTIVE`/four-eyes operations — a scoping choice made up front, not a
gap discovered later. Both are called out again below because the
*mechanisms* they'd need are partially already in place.

## Done

### Phase 0 — The VM
- [x] `devd` account: unprivileged, no sudo, not in docker/lxd/disk/adm — verified in `vm/harden.sh`, checked as the `devd` user (not root) so the check can't trivially pass
- [x] Implicitly-executed paths locked (`.bashrc`, `.profile`, `.ssh/`, git hook dirs) — `vm/harden.sh`, `vm/seed_demo_data.sh`
- [x] `devd` cannot write its own operation files — root-owned, read-only tree (`vm/Dockerfile`), verified by `harden.sh` as the `devd` user specifically (a naive `[ -w ]` check as root always passes regardless of permissions — this was caught and fixed during testing)
- [x] Link-local metadata address blocked — `vm/harden.sh` (iptables, best-effort in the container)
- [ ] Disk quota, `noexec` on world-writable mounts, `cgroup` `TasksMax`/`MemoryMax` — not implemented (needs real VM/systemd resource control, not meaningfully testable in this container)
- [x] Forwarding-only tunnel account, `ForceCommand /bin/false` — `vm/sshd_config.d/devd-tunnel.conf`, **with a documented, tested gap** (see Known gaps below)
- [~] Rebuild drill — `scripts/setup_dev_vm.py` recreates the container from scratch on every run (that *is* the rebuild), but it's never been timed/drilled as a discipline the way §26.3 asks

### Phase 1 — The operation framework
- [x] Manifest schema, registry, version + content-hash computation — `common/manifest.py`, `devd/registry.py`
- [x] `OperationContext`, `Workspace`, `Precondition` — `devd/framework.py`
- [x] Sandbox builder deriving specs from manifests, namespace mode — `devd/sandbox/builder.py`, `devd/sandbox/namespace.py`
- [x] Run records, idempotency, output — `devd/runs.py`
- [x] Two-plus `READ_ONLY` operations end to end — `git.status`, `logs.tail`

### Phase 2 — Transport & control plane
- [x] Tunnel manager: local-unix-socket-to-remote-unix-socket forward, host-key pinning, reconnect — `server/tunnel/manager.py`
- [x] Token minting + devd-side verification, operation-scoped — `server/auth/tokens.py`, `devd/auth.py`
- [x] Approval store + atomic CAS claim, tested under real concurrency — `server/approvals/store.py`, `tests/unit/test_approval_store.py::test_two_workers_race_to_claim_exactly_one_wins`
- [x] Audit: intent/outcome, hash chain, write-only sink — `server/audit/`
- [ ] Cross-plane correlation report ("a devd run with no matching approval," §18.4) — not built; would need to parse devd's local run records against the server's approval store

### Phase 3 — Read-only MCP surface
- [x] `list_operations`, `describe_target`, `run_operation` — `server/tools/mcp_app.py`
- [x] Output handler: caps, ANSI/control stripping, secret redaction, untrusted labelling — `common/output.py`

### Phase 4 — Proposals and the human gate
- [x] Precondition capture, canonical hashing with a real test matrix — `common/canonical.py`, `tests/unit/test_canonical.py`
- [x] `request_operation`, approval state machine (every illegal transition asserted rejected) — `server/approvals/state_machine.py`, `tests/unit/test_state_machine.py`
- [x] Approval CLI with §19/§23 rendering rules (never truncate, show effect fields even when empty, typed confirmation for high-risk, rate indicator) — `server/approvals/decide.py`
- [ ] Push notifications to the human's own channels — none; the CLI's `list`/`show` is pull-only

### Phase 5 — Mutating operations
- [x] Executor: claim → intent → token → call → triage — `server/execution/executor.py`
- [x] Reconciler + `UNKNOWN` handling, built alongside the executor, not after — `server/execution/reconciler.py`, exercised in `tests/integration/test_end_to_end.py::TestFaultInjection`
- [x] `MUTATING_LOCAL` (`git.checkout`) and `SERVICE_CONTROL` (`service.restart`, step-up gated) operations
- [ ] Container sandbox mode + `NETWORK_EXEC` operations — explicitly out of scope for this build (needs Docker-in-Docker inside the already-nested demo container)
- [ ] `DESTRUCTIVE` operations, four-eyes, pre-run snapshots — explicitly out of scope; `approvals_required`/four-eyes *mechanism* exists and is tested (`test_four_eyes_same_human_approving_twice_counts_once`), just nothing uses it yet

## Known gaps (found by testing, not by inspection)

1. **`PermitOpen any` on the tunnel account, not path-scoped.** This
   OpenSSH build (9.2p1/Debian) treats `AllowTcpForwarding no` as a blanket
   kill-switch that also blocks the stream-local forward `devd` needs, and
   has no `PermitOpen` syntax that permits one unix-socket path while
   excluding TCP destinations. The tunnel account can currently reach any
   TCP host:port from inside the container, not just `devd`'s socket.
   Full writeup in `vm/sshd_config.d/devd-tunnel.conf`. **Priority: revisit
   before this touches anything beyond a single-purpose demo container.**
2. **`--privileged` on the dev-VM container**, needed only because
   bubblewrap's unprivileged user namespaces don't work nested inside this
   sandbox's own Docker. Not a gap on a real VM; a gap in this demo's
   fidelity to "the VM runs unprivileged."
3. **Single target, single user.** `server/main.py` picks
   `next(iter(targets.values()))`; `config/roles.yaml` has one entry. Real
   multi-user support needs the target-resolution and role-lookup paths
   generalized.
4. **The agent can reach the approval channel in the local topology.**
   Found in review, not by testing. `server/approvals/decide.py` runs as
   the same OS user as the MCP server, and `data/approvals.db` is
   readable and writable by that user. Any agent with a terminal tool can
   approve its own request or rewrite the DB, which breaks B4 ("the
   decision channel the agent cannot reach"). `devd` still limits this to
   the shipped operations with valid params. Fix options, cheapest first:
   - run the approval store and `decide.py` as a dedicated OS user, with
     the DB at mode 0600 and the MCP server reaching it only through a
     narrow local socket API that has no "approve" verb;
   - require an approval signed by a key the agent can't read (hardware
     key / passkey, or a phone confirmation), and have the executor verify
     that signature instead of trusting a DB row;
   - at minimum, state in the docs that the guarantee assumes an agent
     with no shell access.
   **Priority: highest. This is the core security promise.**
5. ~~**The proposal hash isn't recomputed at execution.**~~ **Fixed.**
   `server/execution/executor.py` and `server/approvals/decide.py` now
   recompute the hash from the stored fields
   (`server.proposals.engine.recompute_proposal_hash`) and refuse on
   mismatch; covered by `tests/unit/test_executor_hash.py`. Remaining
   limit: the hash is unkeyed, so someone with write access to the DB can
   forge a consistent row. Closing that depends on #4 (a signed approval
   or a DB the agent can't write).

## Not started (Phase 6 — hardening)

Roughly in the order the doc itself suggests tackling them:

1. **CI gates for the adversarial/fault-injection/effect-conformance
   suites.** The tests exist and pass (`tests/adversarial/`,
   `tests/integration/`) but nothing runs them automatically on push.
2. **Effect-conformance testing under strace/auditd** (§25.2) — verifying
   an operation touched *nothing* outside its declared `reads`/`writes` by
   observing real syscalls, not just by trusting the sandbox held. The
   sandbox itself was verified manually (undeclared reads/writes/network
   all fail correctly — see README), but there's no automated per-operation
   conformance test yet.
3. **External audit anchor + nightly chain verification.** `AuditSink`
   hash-chains locally and `verify_chain()` detects tampering
   (`tests/unit/test_audit_sink.py`); nothing ships a rolling digest
   off-box or runs verification on a schedule.
4. **Rate limits beyond `max_runs_per_hour`.** No per-session output-byte
   cap, no concurrent-run cap enforcement beyond `devd`'s semaphore.
5. **Monitoring/alerting/runbooks** for the signals in the doc's §26.2
   table (unpaired intent, `RUN_NEEDS_HUMAN`, `SANDBOX_VIOLATION`, etc.) —
   the audit events exist; nothing watches for them.
6. **Real IaC provisioning + quarterly rebuild drill**, HSM/KMS for the CA
   and token-signing keys, break-glass procedure. All infra this sandbox
   doesn't have.
7. **`NETWORK_EXEC` operations + container sandbox mode** (§14.3) — needs
   Docker-in-Docker or an equivalent inside the demo container; skipped by
   explicit scope decision, not forgotten.
8. **`DESTRUCTIVE` operations with four-eyes and pre-run snapshots** — the
   state-machine and approval-store mechanics are there and tested; no
   operation actually uses them yet.

## Suggested next step

First fix Known gaps #5 (hash recompute, small) and #4 (approval-channel
isolation), because both undercut the core "human approves the exact
thing that runs" guarantee. After that, #1 above (wire the existing test
suites into CI) is the highest-leverage next move — everything else in Phase 6 is
easier to get right with that safety net already in place, and it's the
only item on this list that needs no new infrastructure to start.
