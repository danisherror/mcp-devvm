from devd.framework import Result, operation


@operation("git.status")
async def git_status(ctx, repo: str) -> Result:
    wt = ctx.workspace(repo)
    head = await wt.head_sha()
    status = await wt.git("status", "--porcelain")
    branch = (await wt.git("rev-parse", "--abbrev-ref", "HEAD")).strip()
    dirty = status.strip() != ""
    return Result(
        summary=f"{repo}: on {branch} at {head[:12]}, {'dirty' if dirty else 'clean'}",
        data={"repo": repo, "branch": branch, "head_sha": head, "dirty": dirty, "status": status},
    )
