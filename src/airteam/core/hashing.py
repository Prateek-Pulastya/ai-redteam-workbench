"""Canonical serialisation and hashing used for config hashes and evidence chains."""

import hashlib
import json
from typing import Any


def canonical_json(value: Any) -> str:
    """Serialise ``value`` deterministically: sorted keys, no whitespace, UTF-8."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
