from __future__ import annotations

import asyncio
from http import HTTPStatus
from typing import Final

import aiohttp
from aiohttp import ClientSession

from services.types import CloudflareInfo

_API_URL: Final[str] = "https://api.cloudflare.com/client/v4/radar/entities/ip"
_RETRIES: Final[int] = 3
_RETRY_DELAY_SECONDS: Final[int] = 2


async def get_cloudflare_info(session: ClientSession, api_token: str | None, ip: str) -> CloudflareInfo:
    info: CloudflareInfo = {}
    if not api_token:
        info["request_error"] = "Cloudflare token is not configured"
        return info

    url = f"{_API_URL}?ip={ip}"
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
    }

    for attempt in range(1, _RETRIES + 1):
        try:
            async with session.get(url, headers=headers) as response:
                if response.status == HTTPStatus.TOO_MANY_REQUESTS:
                    if attempt < _RETRIES:
                        await asyncio.sleep(_RETRY_DELAY_SECONDS)
                        continue
                    info["request_error"] = (
                        f"{HTTPStatus.TOO_MANY_REQUESTS.value} Too Many Requests after {_RETRIES} attempts"
                    )
                    break

                response.raise_for_status()
                data = await response.json()

                if data.get("success") and "ip" in data.get("result", {}):
                    ip_info = data["result"]["ip"]
                    info.update({
                        "ip": ip_info.get("ip", ip),
                        "ip_version": ip_info.get("ipVersion"),
                        "country": ip_info.get("location"),
                        "country_name": ip_info.get("locationName"),
                        "asn_number": ip_info.get("asn"),
                        "asn_name": ip_info.get("asnName"),
                        "asn_org": ip_info.get("asnOrgName"),
                        "asn_location": ip_info.get("asnLocation"),
                    })
                else:
                    errors = data.get("errors") or "Unknown error"
                    info["error"] = errors
                break

        except aiohttp.ClientResponseError as exc:
            info["request_error"] = f"HTTP error: {exc.status} {exc.message}"
            break
        except aiohttp.ClientError as exc:
            if attempt < _RETRIES:
                await asyncio.sleep(_RETRY_DELAY_SECONDS)
                continue
            info["request_error"] = f"Client error: {exc}" if exc else "Client error"
            break
        except Exception as exc:  # noqa: BLE001
            if attempt < _RETRIES:
                await asyncio.sleep(_RETRY_DELAY_SECONDS)
                continue
            info["request_error"] = str(exc)
            break

    return info
