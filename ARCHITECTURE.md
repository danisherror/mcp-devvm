# Architecture

Two diagrams. The first is the conceptual request lifecycle (what happens,
in order, regardless of which file does it). The second is the literal file
map: which module calls which, across the three process boundaries this
system actually has (the MCP server process, the human's CLI process, and
`devd` inside the container, reached only over the SSH tunnel).

Both reflect what's actually implemented and tested here, not the doc's
full production design — see [ROADMAP.md](./ROADMAP.md) for what's done vs.
outstanding, and the README's "What's simulated" section for the local-demo
substitutions (software CA, `--privileged` container, etc.).

## 1. Overview: the request lifecycle

```mermaid
flowchart TB
    A["🤖 Agent selects an operation"] --> B["MCP tool surface<br/>server/tools/mcp_app.py"]

    B --> C{"READ_ONLY and<br/>approval not required?"}
    C -->|yes| D["run_operation:<br/>execute directly, no approval"]
    C -->|no| E["request_operation:<br/>PROPOSE ONLY -- executes nothing"]

    E --> F["Policy check + precondition capture<br/>server/policy · server/services"]
    F --> G[("Approval store: PENDING<br/>server/approvals/store.py")]

    G -.->|out-of-band, separate terminal| H["👤 Human reviews<br/>server/approvals/decide.py (CLI)"]
    H -->|approve: passphrase unlocks<br/>approver key, signs proposal| I[("APPROVED + signature")]
    H -->|deny| J[("DENIED -- terminal")]

    I --> K["Dispatcher notices<br/>(polls every ~2s)"]
    K --> L["Executor claims atomically<br/>APPROVED to CLAIMED"]
    L --> M["Re-verify policy + manifest hash<br/>(state may have changed since approval)"]
    M --> N["Mint one-operation, two-minute token<br/>open the SSH connection if not already up"]
    N --> O["POST to devd: one SSH session per connection,<br/>forced into a pipe to devd's socket<br/>Idempotency-Key = approval_id, signatures attached"]
    D --> O

    O --> P["devd re-validates independently<br/>token scope · params · manifest version<br/>· human signature over recomputed hashes"]
    P --> Q["Sandbox built FROM the manifest's<br/>effect declaration -- no other input"]
    Q --> R["bubblewrap: execve directly<br/>no shell anywhere"]

    R --> S{"Outcome"}
    S -->|ran to completion| T[("SUCCEEDED / OP_FAILED")]
    S -->|hit its timeout| U[("TIMED_OUT")]
    S -->|connection dropped| V[("UNKNOWN -- never reported<br/>as failure or success")]

    V --> W["Reconciler polls devd's own<br/>idempotency-keyed run record<br/>(read-only, never re-executes)"]
    W -->|resolved| T
    W -->|exhausted after retries| X[("NEEDS_HUMAN -- pages someone")]

    T --> Y["Hash-chained audit record<br/>server/audit/logger.py"]
    U --> Y
    X --> Y
    J --> Y
```

Two independent enforcement points make this hold even if the control plane
is compromised: **devd never trusts what the server asserts** — it re-loads
its own manifest from local disk, re-validates every param, and checks that
the per-request token actually names the operation being called.

## 2. File map: who calls whom, and when

Real module names, real call order, across the three process boundaries.
"Control plane" and "Data plane" run continuously; "Human / CLI" is a
separate process invoked on demand, writing to the same SQLite file.

```mermaid
sequenceDiagram
    autonumber
    actor Agent as 🤖 Agent (MCP client)

    box rgb(230,240,255) Control plane (server/)
        participant Tools as tools/mcp_app.py
        participant Svc as services/operation_service.py
        participant Reg as registry/client.py
        participant Pol as policy/matrix.py
        participant Prop as proposals/engine.py
        participant Store as approvals/store.py (SQLite)
        participant Disp as execution/dispatcher.py
        participant Exec as execution/executor.py
        participant Tun as tunnel/manager.py
        participant Aud as audit/logger.py
    end

    actor Human as 👤 Human
    participant CLI as approvals/decide.py<br/>(separate process, own terminal)

    box rgb(255,240,230) Data plane (devd/, inside the VM container)
        participant App as devd/app.py
        participant Fw as devd/framework.py
        participant Sbx as sandbox/namespace.py<br/>(bubblewrap)
    end

    Agent->>Tools: request_operation(op_id, params, reason)
    Tools->>Svc: request_operation(principal, ...)
    Svc->>Reg: get(target, op_id)
    Reg->>Tun: ensure_connected(target)
    Tun-->>App: GET /manifest  (SSH tunnel, per-request token)
    App-->>Reg: manifest JSON: id, version, hash, params, effect
    Svc->>Pol: allows(principal, target, op)?
    Svc->>App: POST /preconditions  (read-only capture)
    App-->>Svc: preconditions
    Svc->>Prop: build_proposal(...) -- canonical hash
    Svc->>Store: create(...)  status=PENDING
    Svc->>Aud: emit(OPERATION_PROPOSED)
    Svc-->>Tools: {approval_id, status: PENDING, effect}
    Tools-->>Agent: proposal only -- nothing executed

    Note over Human,CLI: separate process -- the agent cannot reach this path
    Human->>CLI: decide.py show / approve appr_xxx
    Human->>CLI: approver passphrase
    CLI->>Store: record_decision(APPROVE, displayed_hash, signature)
    Store-->>CLI: status=APPROVED

    loop every ~2s
        Disp->>Store: SELECT WHERE status='APPROVED'
    end
    Disp->>Exec: execute(approval_id)
    Exec->>Store: claim(approval_id) -- atomic CAS, APPROVED to CLAIMED
    Exec->>Aud: emit(EXECUTION_INTENT)
    Exec->>Reg: get(..., force_refresh=True) -- catches a redeploy
    Exec->>Pol: allows(...)?  -- catches a policy change
    Exec->>Tun: ensure_connected(target)
    Exec->>App: POST /operations/{id}/run<br/>token + Idempotency-Key=approval_id
    App->>App: verify token scope, manifest version, params<br/>(its OWN copies -- never trusts the server)
    App->>App: recompute proposal + effect hashes, verify<br/>approver signature(s) against its own public keys
    App->>Fw: OperationContext(op, params, preconditions)
    Fw->>Sbx: run_sandboxed(argv, reads, writes, network)
    Sbx-->>Fw: exit_code, stdout, stderr
    Fw-->>App: Result(summary, data)
    App-->>Exec: {run_id, status: SUCCEEDED, ...}
    Exec->>Store: settle(approval_id, SUCCEEDED)
    Exec->>Aud: emit(EXECUTION_OUTCOME)

    Agent->>Tools: check_run_status(approval_id)
    Tools->>Store: get(approval_id)
    Store-->>Agent: {status: SUCCEEDED, run_id}
```

**If the tunnel drops mid-call** (not shown above to keep the happy path
readable): `executor.py` catches the transport error, sets the approval to
`UNKNOWN`, and enqueues it with `execution/reconciler.py`, which polls
`GET /runs/by-idempotency-key/{approval_id}` on `devd/app.py` — read-only,
never re-executing — until it resolves or exhausts its retries into
`NEEDS_HUMAN`. Covered for real in
`tests/integration/test_end_to_end.py::TestFaultInjection`.

**`run_operation`** (the direct, no-approval path for `READ_ONLY`
operations) is the same diagram with the top half skipped: `Tools` →
`Svc.run_operation` → straight to `App` over the tunnel, no `Store` row
created at all.
