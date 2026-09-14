"""The emit() interface used throughout the control plane (doc §18.1-§18.3).

Never logs secrets: SSH keys, certificates, per-request tokens, session
tokens, or raw command output. `params` should be pre-redacted by the caller
for anything containing user-supplied free text (our param schemas are all
tightly patterned, so in this template there is little to redact, but the
call sites still route through `redact_secrets` defensively).
"""

from __future__ import annotations

import sys
import time
from typing import Any

import structlog

from common.output import redact_secrets
from server.audit.sink import AuditSink

# Transport-safe logging (doc §18.5): nothing but MCP protocol frames on
# stdout for the stdio transport -- everything goes to stderr.
structlog.configure(logger_factory=structlog.PrintLoggerFactory(file=sys.stderr))
_log = structlog.get_logger("server.audit")

_NEVER_LOG_KEYS = {"token", "authorization", "ssh_key", "certificate", "passphrase", "session_token"}


def _redact(fields: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in fields.items():
        if key.lower() in _NEVER_LOG_KEYS:
            out[key] = "[REDACTED]"
        elif isinstance(value, str):
            redacted, hits = redact_secrets(value)
            out[key] = redacted
            if hits:
                out[f"{key}_redaction_hits"] = hits
        else:
            out[key] = value
    return out


class AuditLogger:
    def __init__(self, sink: AuditSink):
        self._sink = sink

    async def emit(self, event: str, **fields: Any) -> dict[str, Any]:
        record = {"event": event, "occurred_at": time.time(), **_redact(fields)}
        entry = self._sink.append(record)
        _log.info(event, **{k: v for k, v in fields.items() if k.lower() not in _NEVER_LOG_KEYS})
        return entry
