"""The parts of the approval setup that need root: scripts/install_decide.sh
and `approver-keys enroll`. Run as root in a throwaway Linux container with
tests/root/run_in_container.sh; skipped everywhere else.

The container has users alice (owns the checkout at /home/alice/repo), bob
and carol. Tests run in order and build on each other, like the real setup.
"""

from __future__ import annotations

import io
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    not (sys.platform.startswith("linux") and os.geteuid() == 0 and os.environ.get("MCP_ROOT_TESTS") == "1"),
    reason="root-only: run tests/root/run_in_container.sh",
)

REPO = Path(__file__).resolve().parents[2]
PREFIX = Path("/opt/mcp-devvm-approve")
TRUSTED = Path("/etc/mcp-devvm/approvers")
KEYS = PREFIX / "bin" / "approver-keys"
PASS = "correct horse battery staple"
PATH = "/usr/bin:/bin:/usr/sbin:/sbin"


def run(cmd: list[str], *, user: str | None = None, sudo_user: str | None = None,
        answers: tuple[tuple[str, str], ...] = (), timeout: int = 300,
        extra_env: dict[str, str] | None = None) -> tuple[int, str]:
    """Run `cmd` on a terminal, answering prompts in order. `user` runs it as
    that user; `sudo_user` runs it as root the way `sudo` from that user would."""
    import pexpect

    env = {"PATH": PATH, "HOME": "/root", "LANG": "C.UTF-8"}
    # Local wheel cache from run_in_container.sh, if any.
    env.update({k: v for k, v in os.environ.items() if k in ("PIP_FIND_LINKS", "PIP_NO_INDEX")})
    if user:
        cmd = ["sudo", "-u", user, "-H", "--", *cmd]
    if sudo_user:
        env["SUDO_USER"] = sudo_user
    env.update(extra_env or {})
    out = io.StringIO()
    child = pexpect.spawn(cmd[0], cmd[1:], env=env, cwd=str(REPO), encoding="utf-8", timeout=timeout)
    child.logfile_read = out
    for prompt, answer in answers:
        child.expect(prompt)
        child.sendline(answer)
    child.expect(pexpect.EOF)
    child.close()
    return child.exitstatus, out.getvalue()


def mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


def test_installer_refuses_without_root():
    code, out = run(["sh", "scripts/install_decide.sh"], user="alice")
    assert code != 0 and "run with sudo" in out


def test_installer_installs_a_root_owned_copy():
    code, out = run(["sh", "scripts/install_decide.sh", "HEAD"], sudo_user="alice",
                    answers=(("Install it\\?", "y"),))
    assert code == 0, out
    head = subprocess.run(["sudo", "-u", "alice", "git", "-C", str(REPO), "rev-parse", "HEAD"],
                          capture_output=True, text=True, check=True).stdout.strip()
    assert (PREFIX / "COMMIT").read_text().strip() == head
    for dirpath, dirnames, filenames in os.walk(PREFIX):
        for name in [*dirnames, *filenames]:
            p = Path(dirpath) / name
            st = p.lstat()
            assert st.st_uid == 0, f"{p} not owned by root"
            if not stat.S_ISLNK(st.st_mode):
                assert not st.st_mode & 0o022, f"{p} is group/world-writable"
    st = TRUSTED.stat()
    assert st.st_uid == 0 and mode(TRUSTED) == 0o755


def test_installer_used_the_hash_pinned_requirements():
    pip = subprocess.run([str(PREFIX / "venv" / "bin" / "python"), "-I", "-m", "pip", "freeze"],
                         capture_output=True, text=True, check=True).stdout
    assert "cryptography==50.0.1" in pip


def test_installed_decide_runs_as_a_user():
    code, out = run([str(PREFIX / "bin" / "decide"), "--help"], user="alice")
    assert code == 0 and "approve" in out, out


def test_security_key_init_without_a_key_fails_cleanly():
    code, out = run([str(KEYS), "init"], user="alice")
    assert code != 0 and "no security key found" in out, out
    assert not Path("/home/alice/.mcp-devvm/approver/alice.fido").exists()


def test_init_puts_the_key_in_the_users_home():
    code, out = run([str(KEYS), "init", "--passphrase"], user="alice",
                    answers=(("New passphrase", PASS), ("Repeat passphrase", PASS)))
    assert code == 0, out
    key = Path("/home/alice/.mcp-devvm/approver/alice.key")
    assert key.stat().st_uid == int(subprocess.check_output(["id", "-u", "alice"]))
    assert mode(key) == 0o600 and mode(key.parent) == 0o700


def test_enroll_refuses_without_root():
    code, out = run([str(KEYS), "enroll"], user="alice")
    assert code != 0 and "needs root" in out


def test_enroll_refuses_the_repo_copy_as_root():
    # The installed venv has the dependencies; the code comes from the repo.
    code, out = run([str(PREFIX / "venv" / "bin" / "python"), "-I", "-c",
                     "import sys; sys.path.insert(0, '.'); sys.argv[1:] = ['enroll']; "
                     "import runpy; runpy.run_module('scripts.approver_keys', run_name='__main__')"],
                    sudo_user="alice")
    assert code != 0 and "copy your user can edit" in out, out


def test_enroll_wants_a_security_key_unless_told_otherwise():
    code, out = run([str(KEYS), "enroll"], sudo_user="alice")
    assert code != 0 and "--passphrase-key" in out, out
    assert not (TRUSTED / "alice.pub").exists()


def test_enroll_refuses_a_wrong_passphrase():
    code, out = run([str(KEYS), "enroll", "--passphrase-key"], sudo_user="alice",
                    answers=(("Passphrase for approver", "nope"),))
    assert code != 0 and "not enrolled" in out
    assert not (TRUSTED / "alice.pub").exists()


def test_enroll_writes_a_root_owned_public_key():
    code, out = run([str(KEYS), "enroll", "--passphrase-key"], sudo_user="alice",
                    answers=(("Passphrase for approver", PASS),))
    assert code == 0, out
    pub = TRUSTED / "alice.pub"
    assert pub.stat().st_uid == 0 and mode(pub) == 0o644
    assert pub.read_text().startswith("-----BEGIN PUBLIC KEY-----")


def test_enroll_twice_needs_replace():
    code, out = run([str(KEYS), "enroll", "--passphrase-key"], sudo_user="alice",
                    answers=(("Passphrase for approver", PASS),))
    assert code != 0 and "--replace" in out


def test_second_approver_enrolls_from_their_own_home():
    code, out = run([str(KEYS), "init", "--passphrase"], user="bob",
                    answers=(("New passphrase", PASS), ("Repeat passphrase", PASS)))
    assert code == 0, out
    assert Path("/home/bob/.mcp-devvm/approver/bob.key").is_file()
    assert not (REPO / "data" / "approvers" / "private" / "bob.key").exists()
    code, out = run([str(KEYS), "enroll", "--passphrase-key", "--user", "bob"], sudo_user="alice",
                    answers=(("Passphrase for approver", PASS),))
    assert code == 0, out
    assert (TRUSTED / "bob.pub").stat().st_uid == 0


def test_enroll_refuses_a_symlinked_key():
    # carol points her key at alice's; root must not follow the link.
    d = Path("/home/carol/.mcp-devvm/approver")
    subprocess.run(["sudo", "-u", "carol", "mkdir", "-p", str(d)], check=True)
    subprocess.run(["sudo", "-u", "carol", "ln", "-s", "/home/alice/.mcp-devvm/approver/alice.key",
                    str(d / "carol.key")], check=True)
    code, out = run([str(KEYS), "enroll", "--passphrase-key", "--user", "carol"], sudo_user="alice",
                    answers=(("Passphrase for approver", PASS),))
    assert code != 0, out
    assert not (TRUSTED / "carol.pub").exists()


def test_list_shows_enrolled_kinds():
    code, out = run([str(KEYS), "list"], user="alice")
    assert code == 0 and "passphrase key enrolled" in out and "bob (passphrase)" in out, out


def test_installer_can_use_the_pinned_standalone_python():
    """The path macOS takes (its /usr/bin/python3 is too old), as real root."""
    prefix, home = Path("/opt/alt-decide"), Path("/opt/alt-python")
    code, out = run(["sh", "scripts/install_decide.sh", "HEAD"], sudo_user="alice",
                    answers=(("Install it\\?", "y"),),
                    extra_env={"MCP_DECIDE_PYTHON": "standalone", "MCP_DECIDE_PREFIX": str(prefix),
                               "MCP_DECIDE_PYTHON_HOME": str(home)})
    assert code == 0, out
    assert "Downloading Python" in out
    python = next(home.glob("cpython-*/bin/python3"))
    for p in (home, python.resolve()):
        assert p.stat().st_uid == 0 and not p.stat().st_mode & 0o022
    code, out = run([str(prefix / "bin" / "approver-keys"), "--help"], user="alice")
    assert code == 0 and "security key" in out, out
