from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(slots=True)
class Settings:
    bot_api_token: str
    ipinfo_token: str | None
    cloudflare_api_token: str | None
    ipregistry_api_token: str | None
    maxmind_db_city_url: str | None
    maxmind_db_asn_url: str | None
    maxmind_db_city: str
    maxmind_db_asn: str
    enable_subscription_check: bool
    outbound_proxy: str | None


def _bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    value = value.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    return default


def load_settings() -> Settings:
    db_root = os.getenv("MAXMIND_DB_ROOT", "/app/databases")
    return Settings(
        bot_api_token=os.getenv("BOT_API_TOKEN", ""),
        ipinfo_token=os.getenv("IPINFO_TOKEN"),
        cloudflare_api_token=os.getenv("CLOUDFLARE_API_TOKEN"),
        ipregistry_api_token=os.getenv("IPREGISTRY_API_TOKEN"),
        maxmind_db_city_url=os.getenv("MAXMIND_DB_CITY_URL"),
        maxmind_db_asn_url=os.getenv("MAXMIND_DB_ASN_URL"),
        maxmind_db_city=os.getenv("MAXMIND_DB_CITY", os.path.join(db_root, "GeoLite2-City.mmdb")),
        maxmind_db_asn=os.getenv("MAXMIND_DB_ASN", os.path.join(db_root, "GeoLite2-ASN.mmdb")),
        enable_subscription_check=_bool(os.getenv("ENABLE_SUBSCRIPTION_CHECK"), default=True),
        outbound_proxy=os.getenv("OUTBOUND_PROXY"),
    )


SETTINGS = load_settings()

BOT_API_TOKEN = SETTINGS.bot_api_token
IPINFO_TOKEN = SETTINGS.ipinfo_token
CLOUDFLARE_API_TOKEN = SETTINGS.cloudflare_api_token
IPREGISTRY_API_TOKEN = SETTINGS.ipregistry_api_token
MAXMIND_DB_CITY_URL = SETTINGS.maxmind_db_city_url
MAXMIND_DB_ASN_URL = SETTINGS.maxmind_db_asn_url
MAXMIND_DB_CITY = SETTINGS.maxmind_db_city
MAXMIND_DB_ASN = SETTINGS.maxmind_db_asn
ENABLE_SUBSCRIPTION_CHECK = SETTINGS.enable_subscription_check
OUTBOUND_PROXY = SETTINGS.outbound_proxy

__all__ = [
    "Settings",
    "load_settings",
    "SETTINGS",
    "BOT_API_TOKEN",
    "IPINFO_TOKEN",
    "CLOUDFLARE_API_TOKEN",
    "IPREGISTRY_API_TOKEN",
    "MAXMIND_DB_CITY_URL",
    "MAXMIND_DB_ASN_URL",
    "MAXMIND_DB_CITY",
    "MAXMIND_DB_ASN",
    "ENABLE_SUBSCRIPTION_CHECK",
    "OUTBOUND_PROXY",
]
