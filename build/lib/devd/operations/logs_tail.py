from devd import config
from devd.framework import Result, operation


@operation("logs.tail")
async def logs_tail(ctx, lines: int) -> Result:
    log_path = config.LOG_DIR / "app.log"
    result = await ctx.run_sandboxed(["tail", "-n", str(lines), str(log_path)])
    if result.exit_code != 0:
        raise RuntimeError(result.stderr.decode(errors="replace"))
    text = result.stdout.decode(errors="replace")
    return Result(summary=f"last {lines} line(s) of app.log", data={"lines": text})
