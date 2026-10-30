"""The ONLY module that opens an SSH connection (doc §24 review rule).

One long-lived SSH connection per target: connect on demand, pin the host
key, and serve a local unix socket. Each connection to that local socket
gets its own SSH session on the VM, where the tunnel account's forced
command (vm/bin/devd-bridge) pipes it to devd's unix socket.

This replaced SSH port forwarding, which needed `PermitOpen any` on the VM
and so let the tunnel account reach any TCP host:port (ROADMAP Known gap
#1). The session's command string is ignored by the VM -- the forced
command always runs -- so nothing sent here can choose what executes there.
Never falls back to a direct connection.
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
from pathlib import Path

import asyncssh

from server.policy.targets import Target
from server.tunnel.hostkeys import known_hosts_path

logger = logging.getLogger("server.tunnel")

# The VM ignores the requested command and always runs its forced command;
# this string only shows up in sshd's logs.
_SESSION_COMMAND = "devd-bridge"
_CHUNK = 65536


class TunnelError(Exception):
    pass


class HostKeyMismatch(TunnelError):
    pass


class TunnelDown(TunnelError):
    pass


def bind_private_unix_socket(path: Path) -> socket.socket:
    """Bind a unix socket that only this OS user can connect to, with no
    moment where it exists with looser permissions: the umask applies at
    bind() time, before anyone else could connect. The chmod afterwards is
    a second guard in case the platform ignores the umask for sockets."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old_umask = os.umask(0o177)
    try:
        sock.bind(str(path))
    except OSError:
        sock.close()
        raise
    finally:
        os.umask(old_umask)
    try:
        path.chmod(0o600)
    except OSError:
        sock.close()
        path.unlink(missing_ok=True)
        raise
    return sock


class TunnelManager:
    def __init__(self, *, pin_dir: Path, cert_provider):
        """`cert_provider(target) -> (private_key_path, cert_path)` mints (or
        reuses a still-valid) short-lived SSH certificate for the tunnel
        account (doc §9.4)."""
        self._pin_dir = pin_dir
        self._cert_provider = cert_provider
        self._connections: dict[str, asyncssh.SSHClientConnection] = {}
        self._listeners: dict[str, asyncio.AbstractServer] = {}

    def is_up(self, target_id: str) -> bool:
        conn = self._connections.get(target_id)
        return conn is not None and not conn.is_closed()

    async def ensure_connected(self, target: Target) -> None:
        if self.is_up(target.id):
            return

        priv_path, cert_path = await self._cert_provider(target)
        client_keys = asyncssh.load_keypairs([str(priv_path)], certlist=[str(cert_path)])
        known_hosts = str(known_hosts_path(target, pin_dir=self._pin_dir))

        try:
            conn = await asyncssh.connect(
                host=target.ssh_host,
                port=target.ssh_port,
                username=target.ssh_user,
                client_keys=client_keys,
                known_hosts=known_hosts,  # pinned -- never None, never AutoAdd
                agent_path=None,  # no agent forwarding
                config=None,  # never inherit ~/.ssh/config -- a ProxyCommand there is host code exec
                connect_timeout=10,
                keepalive_interval=15,
                keepalive_count_max=3,
            )
        except asyncssh.HostKeyNotVerifiable as exc:
            logger.critical("SSH_HOST_KEY_MISMATCH target=%s", target.id)
            raise HostKeyMismatch(str(exc)) from exc
        except (asyncssh.Error, OSError) as exc:
            raise TunnelDown(str(exc)) from exc

        socket_path = Path(target.local_socket_path)
        socket_path.parent.mkdir(parents=True, exist_ok=True)
        if socket_path.exists():
            socket_path.unlink()

        old_listener = self._listeners.pop(target.id, None)
        if old_listener is not None:
            old_listener.close()

        try:
            sock = bind_private_unix_socket(socket_path)
            listener = await asyncio.start_unix_server(lambda r, w: self._bridge(conn, r, w), sock=sock)
        except OSError as exc:
            conn.close()
            raise TunnelDown(str(exc)) from exc

        self._connections[target.id] = conn
        self._listeners[target.id] = listener
        logger.info("TUNNEL_UP target=%s local=%s", target.id, socket_path)

    @staticmethod
    async def _bridge(conn: asyncssh.SSHClientConnection, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Copy bytes both ways between one local connection and one SSH session."""
        try:
            proc = await conn.create_process(_SESSION_COMMAND, encoding=None)
        except (asyncssh.Error, OSError) as exc:
            logger.warning("TUNNEL_SESSION_FAILED error=%s", exc)
            writer.close()
            return

        async def upstream() -> None:
            try:
                while data := await reader.read(_CHUNK):
                    proc.stdin.write(data)
                    # Wait for the SSH channel to accept it, so a large or
                    # fast request can't pile up in memory here.
                    await proc.stdin.drain()
                proc.stdin.write_eof()
            except (asyncssh.Error, OSError, ConnectionError):
                pass

        async def downstream() -> None:
            try:
                while data := await proc.stdout.read(_CHUNK):
                    writer.write(data)
                    await writer.drain()
            except (asyncssh.Error, OSError, ConnectionError):
                pass
            finally:
                writer.close()

        try:
            await asyncio.gather(upstream(), downstream())
        finally:
            proc.close()

    async def close(self, target_id: str) -> None:
        if target_id in self._listeners:
            self._listeners[target_id].close()
            del self._listeners[target_id]
        if target_id in self._connections:
            self._connections[target_id].close()
            await self._connections[target_id].wait_closed()
            del self._connections[target_id]
        logger.info("TUNNEL_DOWN target=%s", target_id)

    async def close_all(self) -> None:
        for target_id in list(self._connections):
            await self.close(target_id)
