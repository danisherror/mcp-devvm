"""HTTP client factory for talking to devd over the tunnel's local unix
socket. The socket only exists once TunnelManager.ensure_connected() has
run for that target."""

from __future__ import annotations

import httpx

from server.policy.targets import Target


def client_for(target: Target, *, timeout: float = 30) -> httpx.AsyncClient:
    transport = httpx.AsyncHTTPTransport(uds=target.local_socket_path)
    return httpx.AsyncClient(transport=transport, base_url="http://devd", timeout=timeout)
