from pathlib import Path

from devd import config
from devd.framework import Precondition, Result, operation, precondition_context


@precondition_context("service.restart")
def _context(params: dict) -> Path:
    return config.SERVICE_STATE_DIR / f"{params['service']}.state"


@operation("service.restart")
async def service_restart(ctx, service: str) -> Result:
    state_file = f"/srv/services/{service}.state"

    read_result = await ctx.run_sandboxed(["cat", state_file])
    current = read_result.stdout.decode().strip() if read_result.exit_code == 0 else "unknown"
    ctx.require(Precondition("service.is_active", current == "active"))

    # `tee` + stdin instead of shell `>` redirection -- no shell anywhere (§5.5).
    write_result = await ctx.run_sandboxed(["tee", state_file], stdin=b"active\n")
    if write_result.exit_code != 0:
        raise RuntimeError(write_result.stderr.decode(errors="replace"))

    return Result(summary=f"Restarted {service}", data={"service": service})
