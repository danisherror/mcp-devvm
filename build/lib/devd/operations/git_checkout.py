from pathlib import Path

from devd import config
from devd.framework import Precondition, Result, operation, precondition_context


@precondition_context("git.checkout")
def _context(params: dict) -> Path:
    return config.WORKSPACES[params["repo"]]


@operation("git.checkout")
async def git_checkout(ctx, repo: str, branch: str) -> Result:
    wt = ctx.workspace(repo)

    # Check-and-act, adjacent to the effect (§13.3): the values approved by
    # the human are re-verified here, microseconds before the mutation.
    ctx.require(Precondition("git.head_sha", await wt.head_sha()))
    ctx.require(Precondition("git.worktree_clean", await wt.is_clean()))

    # `branch` before the `--` terminator: `git checkout -- <x>` treats <x> as
    # a pathspec, not a branch, which is a different command entirely. Since
    # the param validator already rejects a leading dash (§5.4), `branch`
    # cannot be mistaken for an option either way; the trailing `--` is
    # belt-and-braces against any pathspec ambiguity.
    await wt.git("checkout", branch, "--")
    new_head = await wt.head_sha()

    return Result(
        summary=f"Checked out {branch} in {repo} (now at {new_head[:12]})",
        data={"repo": repo, "branch": branch, "head_sha": new_head},
    )
