from __future__ import annotations

import string

_ASCII_A = ord("A")
_FLAG_BASE = 0x1F1E6
_VALID = set(string.ascii_uppercase)


def country_flag(code: str | None) -> str:
    if not code:
        return ""
    code = code.strip().upper()
    if len(code) != 2 or any(char not in _VALID for char in code):
        return ""
    return "".join(chr(_FLAG_BASE + (ord(ch) - _ASCII_A)) for ch in code)

