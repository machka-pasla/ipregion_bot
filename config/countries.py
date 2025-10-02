from __future__ import annotations

import pycountry

_OVERRIDES = {
    "XK": "Kosovo",
    "EU": "European Union",
}


def country_name(code: str | None) -> str:
    if not code:
        return ""
    code = code.strip().upper()
    if code in _OVERRIDES:
        return _OVERRIDES[code]
    country = pycountry.countries.get(alpha_2=code)
    if country and getattr(country, "name", None):
        return country.name
    return code

