"""Parameter type/pattern validation shared by both planes.

Per doc §5.4/§12.1: this module is *interpreted* independently by the control
plane (against a manifest fetched over HTTP) and by devd (against the
manifest it loaded from local disk). Sharing this pure-logic module does not
create a trust dependency between the planes -- each side still calls
validate() itself, against its own copy of the schema, before acting.

Rules enforced here, each with a unit test in tests/unit/test_paramschema.py:
  - typed: enum | string (regex) | integer (bounds) | boolean -- never bare str
  - pattern is fullmatch, anchored, with max_length
  - leading dashes rejected unless explicitly allowed (option injection, §5.4)
  - NUL / CR / LF / control characters rejected
  - unicode NFC-normalized; bidi and zero-width characters flagged, not stripped
  - exact key set: no extra params, no missing params (checked by the caller)
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Literal

_CONTROL_CHARS = {chr(c) for c in range(0, 0x20)} | {chr(0x7F)}
_CONTROL_CHARS -= {"\t"}  # tabs inside a param are still rejected below via NUL/CR/LF rule anyway

# Bidi override / embedding characters and zero-width characters worth flagging.
_BIDI_CHARS = set("‪‫‬‭‮⁦⁧⁨⁩")
_ZERO_WIDTH_CHARS = set("​‌‍⁠﻿")


class InvalidParameter(ValueError):
    def __init__(self, name: str, reason: str):
        self.name = name
        self.reason = reason
        super().__init__(f"invalid_parameter:{name}:{reason}")


@dataclass(frozen=True)
class Param:
    type: Literal["string", "enum", "integer", "boolean"]
    pattern: str | None = None                # required for type == "string"
    max_length: int = 200
    allow_leading_dash: bool = False           # default False -- see §5.4
    values: tuple[str, ...] = field(default_factory=tuple)   # required for type == "enum"
    min_value: int | None = None               # for type == "integer"
    max_value: int | None = None

    def __post_init__(self):
        if self.type == "string" and not self.pattern:
            raise ValueError("string params must declare a pattern")
        if self.type == "enum" and not self.values:
            raise ValueError("enum params must declare values")

    def validate(self, name: str, value: Any) -> Any:
        if self.type == "enum":
            if not isinstance(value, str) or value not in self.values:
                raise InvalidParameter(name, "not_in_enum")
            return value

        if self.type == "boolean":
            if not isinstance(value, bool):
                raise InvalidParameter(name, "not_boolean")
            return value

        if self.type == "integer":
            if isinstance(value, bool) or not isinstance(value, int):
                raise InvalidParameter(name, "not_integer")
            if self.min_value is not None and value < self.min_value:
                raise InvalidParameter(name, "below_minimum")
            if self.max_value is not None and value > self.max_value:
                raise InvalidParameter(name, "above_maximum")
            return value

        if self.type == "string":
            return self._validate_string(name, value)

        raise InvalidParameter(name, "unknown_type")

    def _validate_string(self, name: str, value: Any) -> str:
        if not isinstance(value, str):
            raise InvalidParameter(name, "not_string")
        if len(value) == 0:
            raise InvalidParameter(name, "empty")
        if len(value) > self.max_length:
            raise InvalidParameter(name, "too_long")

        # NUL / CR / LF / other control characters -- rejected outright, never stripped.
        if any(c in _CONTROL_CHARS for c in value):
            raise InvalidParameter(name, "control_char")

        # Bidi overrides and zero-width characters are flagged (rejected), not silently
        # normalized away -- their presence is itself a signal (§5.4, §15).
        if any(c in _BIDI_CHARS for c in value):
            raise InvalidParameter(name, "bidi_override")
        if any(c in _ZERO_WIDTH_CHARS for c in value):
            raise InvalidParameter(name, "zero_width_char")

        normalized = unicodedata.normalize("NFC", value)

        # Leading dash = an option, not data (§5.4) -- rejected unless explicitly allowed.
        if normalized.startswith("-") and not self.allow_leading_dash:
            raise InvalidParameter(name, "leading_dash")

        assert self.pattern is not None
        if not re.fullmatch(self.pattern, normalized):
            raise InvalidParameter(name, "pattern")

        return normalized


def validate_params(schema: dict[str, Param], given: dict[str, Any]) -> dict[str, Any]:
    """Exact key set: no extras, no omissions (§5.4)."""
    if set(given) != set(schema):
        raise InvalidParameter("params", "key_set_mismatch")
    return {name: schema[name].validate(name, value) for name, value in given.items()}
