"""Operation registry: loads manifests + implementations from local disk,
computes per-operation content hashes, and is the thing devd trusts for
param schemas and effect declarations -- never a request (B5)."""

from __future__ import annotations

import importlib
import logging
from pathlib import Path

import yaml

from common.manifest import ManifestError, OperationManifest, manifest_from_yaml_dict
from devd import config
from devd.framework import get_implementation, get_precondition_context
from devd.preconditions import capture as capture_precondition

logger = logging.getLogger("devd.registry")


class OperationRegistry:
    def __init__(self, operations: dict[str, OperationManifest]):
        self._operations = operations

    def get(self, operation_id: str) -> OperationManifest | None:
        return self._operations.get(operation_id)

    def all(self) -> list[OperationManifest]:
        return list(self._operations.values())

    async def capture_preconditions(self, op: OperationManifest, params: dict) -> dict:
        ctx_fn = get_precondition_context(op.id)
        if ctx_fn is None:
            if op.preconditions:
                raise ManifestError(f"{op.id} declares preconditions but has no context resolver")
            return {}
        root = ctx_fn(params)
        return {name: await capture_precondition(name, root) for name in op.preconditions}


def load_registry(operations_dir: Path = config.OPERATIONS_DIR) -> OperationRegistry:
    operations: dict[str, OperationManifest] = {}

    for yaml_path in sorted(operations_dir.glob("*.yaml")):
        module_name = yaml_path.stem
        py_path = yaml_path.with_suffix(".py")
        if not py_path.exists():
            raise ManifestError(f"{yaml_path} has no matching implementation {py_path}")

        raw = yaml.safe_load(yaml_path.read_text())
        impl_source = py_path.read_bytes()
        manifest = manifest_from_yaml_dict(raw, impl_source=impl_source)

        # Import the implementation module so its @operation / @precondition_context
        # decorators register into the framework's registries.
        spec = importlib.util.spec_from_file_location(f"devd.operations.{module_name}", py_path)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        if get_implementation(manifest.id) is None:
            raise ManifestError(f"{py_path} did not register an implementation for {manifest.id!r}")

        operations[manifest.id] = manifest
        logger.info("loaded operation %s v%s (hash %s)", manifest.id, manifest.version, manifest.content_hash[:12])

    return OperationRegistry(operations)
