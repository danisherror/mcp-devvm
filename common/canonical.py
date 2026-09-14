"""Canonical JSON encoding + hashing for proposals (doc §7.4).

Not a full RFC 8785 (JCS) implementation, but a deterministic subset adequate
for our own canonical objects, which by construction never contain floats:

  - object keys sorted by Unicode code point (Python's default `str` ordering)
  - strings NFC-normalized before encoding
  - no floats permitted anywhere in the tree (integers only)
  - `None` and "key absent" remain distinguishable (a present key encodes as
    `"key":null`; an absent key simply does not appear)
  - lists preserve order and are hashed as lists, never joined into a string

`json.dumps(sort_keys=True)` is explicitly NOT what this does: it does not
NFC-normalize strings and it would silently accept floats.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from typing import Any


class NonCanonicalValue(TypeError):
    pass


def _encode_string(s: str) -> str:
    normalized = unicodedata.normalize("NFC", s)
    return json.dumps(normalized, ensure_ascii=False)


def _encode(obj: Any) -> str:
    if obj is None:
        return "null"
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, float):
        raise NonCanonicalValue("floats are not permitted in a canonical proposal")
    if isinstance(obj, int):
        return str(obj)
    if isinstance(obj, str):
        return _encode_string(obj)
    if isinstance(obj, (list, tuple)):
        return "[" + ",".join(_encode(x) for x in obj) + "]"
    if isinstance(obj, dict):
        items = sorted(obj.items(), key=lambda kv: kv[0])
        return "{" + ",".join(f"{_encode_string(k)}:{_encode(v)}" for k, v in items) + "}"
    raise NonCanonicalValue(f"cannot canonicalize type {type(obj).__name__}")


def canonicalize(obj: Any) -> bytes:
    return _encode(obj).encode("utf-8")


def content_hash(obj: Any) -> str:
    return hashlib.sha256(canonicalize(obj)).hexdigest()


def proposal_hash(
    *,
    v: int,
    principal: str,
    target_id: str,
    operation_id: str,
    manifest_version: int,
    manifest_hash: str,
    params: dict[str, Any],
    preconditions: dict[str, Any],
) -> str:
    """The canonical proposal object from doc §7.4, hashed.

    `reason`, timestamps, and `request_id` are deliberately excluded -- they
    sit outside the hash per the doc.
    """
    canonical = {
        "v": v,
        "principal": principal,
        "target_id": target_id,
        "operation_id": operation_id,
        "manifest_version": manifest_version,
        "manifest_hash": manifest_hash,
        "params": params,
        "preconditions": preconditions,
    }
    return content_hash(canonical)
