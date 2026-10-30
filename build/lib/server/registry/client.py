"""Registry client (doc §5.6): fetches devd's manifest over the tunnel,
caches it with its per-operation content_hash, and refreshes on demand.
This is the control plane's OWN copy -- devd never trusts it back (B5)."""

from __future__ import annotations

from common.manifest import OperationManifest, manifest_from_wire_dict
from server.auth.tokens import TokenMinter
from server.policy.targets import Target
from server.tunnel.devd_client import client_for
from server.tunnel.manager import TunnelManager


class RegistryError(Exception):
    pass


class RegistryClient:
    def __init__(self, token_minter: TokenMinter, tunnel: TunnelManager):
        self._token_minter = token_minter
        self._tunnel = tunnel
        self._cache: dict[str, dict[str, OperationManifest]] = {}

    async def refresh(self, target: Target, principal_id: str) -> dict[str, OperationManifest]:
        token = self._token_minter.mint(
            sub=principal_id,
            approval_id="n/a:manifest-refresh",
            operation_id="__discovery__",
            manifest_version=0,
            audience=f"devd:{target.id}",
            ttl_seconds=60,
        )
        try:
            await self._tunnel.ensure_connected(target)
            async with client_for(target) as client:
                resp = await client.get("/manifest", headers={"Authorization": f"Bearer {token}"})
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:  # noqa: BLE001
            raise RegistryError(str(exc)) from exc

        ops = {o["id"]: manifest_from_wire_dict(o) for o in data["operations"]}
        self._cache[target.id] = ops
        return ops

    def get_cached(self, target_id: str) -> dict[str, OperationManifest]:
        return self._cache.get(target_id, {})

    async def get(
        self, target: Target, operation_id: str, principal_id: str, *, force_refresh: bool = False
    ) -> OperationManifest | None:
        if force_refresh or target.id not in self._cache:
            await self.refresh(target, principal_id)
        return self._cache.get(target.id, {}).get(operation_id)
