"""The outcome triage table, in one place (doc §13.4). Two rows deserve
special attention: 422 is a security finding (devd rejected params the
server would have accepted -- schemas have diverged or something tampered
with the request in transit), and transport failure is UNKNOWN, never
failure.
"""

from __future__ import annotations

import httpx


def triage_response(resp: httpx.Response) -> str:
    if resp.status_code == 200:
        try:
            status = resp.json().get("status")
        except Exception:  # noqa: BLE001
            return "UNKNOWN"
        if status in ("SUCCEEDED", "OP_FAILED", "TIMED_OUT"):
            return status
        return "UNKNOWN"

    if resp.status_code == 409:
        return "STALE"  # manifest_version_mismatch or precondition_drift

    if resp.status_code in (401, 403):
        return "UNAUTHORIZED"

    if resp.status_code == 404:
        return "UNAUTHORIZED"  # server/devd skew -- devd doesn't know this operation at all

    if resp.status_code == 422:
        return "UNAUTHORIZED"  # devd rejected params the server accepted -- a security finding

    if resp.status_code == 429:
        return "OP_FAILED"  # backoff; nothing ran

    if resp.status_code >= 500:
        return "UNKNOWN"  # ambiguous -- devd may have started the effect before erroring

    return "UNKNOWN"


def triage_error_code(resp: httpx.Response) -> str | None:
    try:
        return resp.json().get("detail")
    except Exception:  # noqa: BLE001
        return None
