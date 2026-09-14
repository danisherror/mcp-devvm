"""The ONLY module that opens an SSH connection (doc §24 review rule).

One long-lived tunnel per target: connect on demand, pin the host key,
forward a local unix socket to devd's remote unix socket, reconnect with
backoff. Never falls back to a direct connection or to SSH exec.
"""

from __future__ import annotations

import logging
from pathlib import Path

import asyncssh

from server.policy.targets import Target
from server.tunnel.hostkeys import known_hosts_path

logger = logging.getLogger("server.tunnel")


class TunnelError(Exception):
    pass


class HostKeyMismatch(TunnelError):
    pass


class TunnelDown(TunnelError):
    pass


class TunnelManager:
    def __init__(self, *, pin_dir: Path, cert_provider):
        """`cert_provider(target) -> (private_key_path, cert_path)` mints (or
        reuses a still-valid) short-lived SSH certificate for the tunnel
        account (doc §9.4)."""
        self._pin_dir = pin_dir
        self._cert_provider = cert_provider
        self._connections: dict[str, asyncssh.SSHClientConnection] = {}
        self._listeners: dict[str, asyncssh.SSHListener] = {}

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

        try:
            listener = await conn.forward_local_path(str(socket_path), target.remote_socket_path)
        except (asyncssh.Error, OSError) as exc:
            conn.close()
            raise TunnelDown(str(exc)) from exc

        self._connections[target.id] = conn
        self._listeners[target.id] = listener
        logger.info("TUNNEL_UP target=%s local=%s remote=%s", target.id, socket_path, target.remote_socket_path)

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
