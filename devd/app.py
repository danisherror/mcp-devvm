"""devd: the data plane. Runs on the dev VM, binds a unix socket only, and
is the second, independent enforcement point (B5) -- a compromised control
plane still cannot exceed the operation set this process re-validates
against its own on-disk copies of every schema and manifest.

Simplification vs. doc §13.5: `POST /operations/{id}/run` here awaits the
operation to completion (our demo operations all finish in well under a
second) and returns its terminal status directly, rather than immediately
backgrounding every call. A durable run record is still written to disk
BEFORE the effect starts and updated with `status` written LAST, so
`GET /runs/{run_id}` and idempotency-key replay behave identically to the
fully-backgrounded design even if the original HTTP response never reaches
the caller (simulated in tests by dropping the connection). A production
build with genuinely long-running operations (a 40-minute build) would
background via asyncio.create_task and have the agent poll, exactly as
§13.5 describes -- nothing here would need to change to support that.
"""

from __future__ import annotations

import asyncio
import logging
import sys
import uuid
from typing import Any

import structlog
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from common.output import handle_output
from devd import config
from devd.auth import TokenClaims, token_dependency
from devd.framework import (
    ManifestError,
    OperationContext,
    PreconditionDrift,
    SandboxViolation,
    get_implementation,
)
from devd.registry import OperationRegistry, load_registry
from devd.runs import RunStore
from devd.sandbox.namespace import SandboxConstructionError

# Transport-safe logging (doc §18.5): nothing but the ASGI server's own
# framing on stdout; everything we log goes to stderr.
logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(message)s")
structlog.configure(logger_factory=structlog.PrintLoggerFactory(file=sys.stderr))
log = structlog.get_logger("devd")

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)  # no introspection endpoints

registry: OperationRegistry = load_registry()
run_store = RunStore()
_run_semaphore = asyncio.Semaphore(config.MAX_CONCURRENT_RUNS)


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    params: dict[str, Any] = Field(default_factory=dict)
    preconditions: dict[str, Any] = Field(default_factory=dict)
    manifest_version: int
    manifest_hash: str


@app.get("/manifest")
async def manifest(caller: TokenClaims = Depends(token_dependency)) -> dict[str, Any]:
    return {"target_id": config.TARGET_ID, "operations": [op.as_dict() for op in registry.all()]}


class PreconditionsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    operation_id: str
    params: dict[str, Any] = Field(default_factory=dict)


@app.post("/preconditions")
async def preconditions(req: PreconditionsRequest, caller: TokenClaims = Depends(token_dependency)) -> dict[str, Any]:
    if caller.operation_id != req.operation_id:
        log.warning("token_operation_mismatch", endpoint="preconditions", token_op=caller.operation_id, req_op=req.operation_id)
        raise HTTPException(status_code=403, detail="token_operation_mismatch")
    op = registry.get(req.operation_id)
    if op is None:
        raise HTTPException(status_code=404, detail="unknown_operation")
    try:
        params = _validate_params(op, req.params)
        captured = await registry.capture_preconditions(op, params)
    except Exception as exc:  # noqa: BLE001 -- converted to a typed error response below
        log.warning("precondition_capture_failed", operation_id=op.id, error=str(exc))
        raise HTTPException(status_code=422, detail="precondition_capture_failed") from exc
    return {"preconditions": captured}


def _validate_params(op, raw_params: dict[str, Any]) -> dict[str, Any]:
    from common.paramschema import InvalidParameter, validate_params

    try:
        return validate_params(op.params, raw_params)
    except InvalidParameter as exc:
        raise HTTPException(status_code=422, detail=f"invalid_parameter:{exc.name}:{exc.reason}") from exc


@app.post("/operations/{operation_id}/run")
async def run_operation(
    operation_id: str,
    req: RunRequest,
    request: Request,
    caller: TokenClaims = Depends(token_dependency),
    idempotency_key: str = Header(alias="Idempotency-Key"),
) -> dict[str, Any]:
    # ── B5: devd trusts nothing the caller merely asserted ──────────────────
    if caller.operation_id != operation_id:
        log.warning("token_operation_mismatch", token_op=caller.operation_id, req_op=operation_id)
        raise HTTPException(status_code=403, detail="token_operation_mismatch")

    op = registry.get(operation_id)
    if op is None:
        raise HTTPException(status_code=404, detail="unknown_operation")

    if (req.manifest_version, req.manifest_hash) != (op.version, op.content_hash):
        raise HTTPException(status_code=409, detail="manifest_version_mismatch")

    params = _validate_params(op, req.params)  # devd's OWN schema check, independent of the server's

    if existing := run_store.by_idempotency_key(idempotency_key):
        log.info("idempotent_replay", idempotency_key=idempotency_key, run_id=existing.run_id)
        return existing.as_response()

    body_len = int(request.headers.get("content-length", "0") or "0")
    if body_len > 1_000_000:
        raise HTTPException(status_code=413, detail="request_too_large")

    run_id = "run_" + uuid.uuid4().hex[:16]
    run = run_store.create(
        operation_id=op.id, run_id=run_id, idempotency_key=idempotency_key,
        principal=caller.sub, approval_id=caller.approval_id,
    )
    log.info("run_started", run_id=run_id, operation_id=op.id, principal=caller.sub, approval_id=caller.approval_id)

    async with _run_semaphore:
        ctx = OperationContext(op, params, req.preconditions, config.WORKSPACES)
        impl = get_implementation(op.id)
        assert impl is not None

        try:
            result = await asyncio.wait_for(impl(ctx, **params), timeout=op.sandbox.timeout_s + 5)
        except PreconditionDrift as exc:
            run_store.finish(run_id, status="OP_FAILED", exit_code=None,
                              summary=f"precondition_drift:{exc.name}", data={"expected": exc.expected, "actual": exc.actual})
            log.warning("precondition_drift", run_id=run_id, name=exc.name)
            raise HTTPException(status_code=409, detail="precondition_drift") from exc
        except SandboxViolation as exc:
            run_store.finish(run_id, status="OP_FAILED", exit_code=None, summary=str(exc), data={})
            log.error("sandbox_violation", run_id=run_id, operation_id=op.id, error=str(exc))
            raise HTTPException(status_code=500, detail="sandbox_violation") from exc
        except SandboxConstructionError as exc:
            run_store.finish(run_id, status="OP_FAILED", exit_code=None, summary=str(exc), data={})
            log.error("sandbox_construction_failed", run_id=run_id, error=str(exc))
            raise HTTPException(status_code=500, detail="sandbox_construction_failed") from exc
        except asyncio.TimeoutError:
            run_store.finish(run_id, status="TIMED_OUT", exit_code=124, summary="operation exceeded its timeout", data={})
            log.warning("run_timed_out", run_id=run_id, operation_id=op.id)
            return run_store.get(run_id).as_response()
        except ManifestError as exc:
            run_store.finish(run_id, status="OP_FAILED", exit_code=None, summary=str(exc), data={})
            raise HTTPException(status_code=500, detail="manifest_error") from exc
        except Exception as exc:  # noqa: BLE001 -- operation ran and failed; not a security event
            run_store.finish(run_id, status="OP_FAILED", exit_code=1, summary=str(exc), data={})
            log.info("op_failed", run_id=run_id, operation_id=op.id, error=str(exc))
            return run_store.get(run_id).as_response()

        run_store.finish(run_id, status="SUCCEEDED", exit_code=0, summary=result.summary, data=result.data)
        log.info("run_succeeded", run_id=run_id, operation_id=op.id)
        return run_store.get(run_id).as_response()


@app.get("/runs/{run_id}")
async def get_run(run_id: str, caller: TokenClaims = Depends(token_dependency)) -> dict[str, Any]:
    run = run_store.get(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="unknown_run")
    return run.as_response()


@app.get("/runs/by-idempotency-key/{idempotency_key}")
async def get_run_by_idempotency_key(idempotency_key: str, caller: TokenClaims = Depends(token_dependency)) -> dict[str, Any]:
    """Read-only lookup used exclusively by the reconciler (doc §13.4): never
    re-executes, just answers "did this ever run, and how did it end." The
    idempotency key IS the approval_id, so this doubles as "what happened to
    approval X" without the caller needing to know a run_id."""
    run = run_store.by_idempotency_key(idempotency_key)
    if run is None or run.operation_id != caller.operation_id:
        raise HTTPException(status_code=404, detail="unknown_run")
    return run.as_response()


@app.get("/runs/{run_id}/output")
async def get_output(
    run_id: str,
    stream: str = "stdout",
    offset: int = 0,
    limit: int = 65536,
    caller: TokenClaims = Depends(token_dependency),
) -> dict[str, Any]:
    if stream not in ("stdout", "stderr"):
        raise HTTPException(status_code=422, detail="invalid_stream")
    raw = run_store.read_output(run_id, stream, offset, limit)
    output = handle_output(raw, limit=limit)
    return {"text": output.text, "truncated": output.truncated, "redacted": output.redacted}
