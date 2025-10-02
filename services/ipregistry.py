from __future__ import annotations

from http import HTTPStatus

import aiohttp
from aiohttp import ClientSession

from services.types import IPRegistryInfo, SecurityFlags


async def get_ipregistry_info(session: ClientSession, api_token: str | None, ip: str) -> IPRegistryInfo:
    url = f"https://api.ipregistry.co/{ip}"
    params = {"key": api_token} if api_token else {}

    info: IPRegistryInfo = {
        "ip": ip,
        "security": {},
    }

    if not api_token:
        info["request_error"] = "IPRegistry token is not configured"
        return info

    try:
        async with session.get(url, params=params) as response:
            if response.status != HTTPStatus.OK:
                info["request_error"] = f"HTTP error: {response.status}"
                return info

            data = await response.json()
            if not isinstance(data, dict):
                info["request_error"] = "Invalid JSON response"
                return info

            location = data.get("location", {})
            region = location.get("region", {})
            country = location.get("country", {})
            info.update({
                "type": data.get("type"),
                "hostname": data.get("hostname"),
                "city": location.get("city"),
                "region": region.get("name"),
                "region_code": region.get("code"),
                "country": country.get("name"),
                "country_code": country.get("code"),
                "latitude": location.get("latitude"),
                "longitude": location.get("longitude"),
            })

            connection = data.get("connection", {})
            info.update({
                "asn_number": connection.get("asn"),
                "asn_org": connection.get("organization"),
                "network": connection.get("route"),
                "type": connection.get("type", info.get("type")),
            })

            security_data = data.get("security", {})
            security: SecurityFlags = {}
            for key in ("is_abuser", "is_attacker", "is_bogon", "is_cloud_provider", "is_proxy", "is_relay", "is_tor", "is_tor_exit", "is_vpn", "is_anonymous", "is_threat"):
                security[key] = bool(security_data.get(key, False))
            info["security"] = security

    except aiohttp.ClientResponseError as exc:
        info["request_error"] = f"HTTP error: {exc.status} {exc.message}"
    except aiohttp.ClientError as exc:
        info["request_error"] = f"Client error: {exc}"
    except Exception as exc:  # noqa: BLE001
        info["request_error"] = f"Unexpected error: {exc}"

    return info
