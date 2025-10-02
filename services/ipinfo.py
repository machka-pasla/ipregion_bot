from __future__ import annotations

from http import HTTPStatus

import aiohttp
from aiohttp import ClientSession

from services.types import IPInfoData


async def get_ipinfo_info(session: ClientSession, api_token: str | None, ip: str) -> IPInfoData:
    url = f"https://ipinfo.io/{ip}/json"
    headers = {"Authorization": f"Bearer {api_token}"} if api_token else {}

    try:
        async with session.get(url, headers=headers) as response:
            if response.status == HTTPStatus.OK:
                data = await response.json()
                asn_number: str | None = None
                asn_org: str | None = None
                org = data.get("org")
                if org and org.startswith("AS"):
                    parts = org.split(" ", 1)
                    asn_number = parts[0]
                    asn_org = parts[1] if len(parts) > 1 else None

                return {
                    "country": data.get("country"),
                    "region": data.get("region"),
                    "city": data.get("city"),
                    "asn_number": asn_number,
                    "asn_org": asn_org,
                }

            return {"error": f"HTTP {response.status}"}
    except aiohttp.ClientError as exc:
        return {"error": f"Client error: {exc}"}
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}
