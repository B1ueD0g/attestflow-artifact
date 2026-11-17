"""Typed HMAC commitments used by local trace adapters."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
from collections.abc import Mapping, Sequence, Set
from typing import Any


def _typed_value(value: Any) -> Any:
    if value is None:
        return {"type": "null", "value": None}
    if isinstance(value, bool):
        return {"type": "bool", "value": value}
    if isinstance(value, int):
        return {"type": "int", "value": str(value)}
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite floats cannot be committed")
        return {"type": "float", "value": value.hex()}
    if isinstance(value, str):
        return {"type": "str", "value": value}
    if isinstance(value, (bytes, bytearray, memoryview)):
        encoded = base64.b64encode(bytes(value)).decode("ascii")
        return {"type": "bytes", "value": encoded}
    if isinstance(value, Mapping):
        items = [
            [_typed_value(key), _typed_value(item)] for key, item in value.items()
        ]
        items.sort(key=lambda item: json.dumps(item[0], sort_keys=True, separators=(",", ":")))
        return {"type": "mapping", "value": items}
    if isinstance(value, Set):
        items = [_typed_value(item) for item in value]
        items.sort(key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")))
        return {"type": "set", "value": items}
    if isinstance(value, Sequence):
        return {"type": "sequence", "value": [_typed_value(item) for item in value]}
    raise TypeError(f"unsupported commitment value type: {type(value).__name__}")


def commitment(value: Any, key: bytes, *, label: str = "attestflow.trace.v1") -> str:
    """Return a domain-separated HMAC-SHA256 commitment without logging raw values."""

    if not isinstance(key, bytes) or len(key) < 16:
        raise ValueError("commitment key must be at least 16 bytes")
    if not isinstance(label, str) or not label:
        raise ValueError("commitment label must be a non-empty string")
    envelope = {"domain": label, "typed_value": _typed_value(value)}
    payload = json.dumps(
        envelope, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    digest = hmac.new(key, payload, hashlib.sha256).hexdigest()
    return f"hmac-sha256:{digest}"

