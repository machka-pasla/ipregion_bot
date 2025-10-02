from __future__ import annotations

import asyncio
from http import HTTPStatus
from typing import Final

import aiohttp
from aiohttp import ClientSession

from services.types import RdapInfo

_API_URL: Final[str] = "https://api.cloudflare.com/client/v4/radar/entities/asns/"
_RETRIES: Final[int] = 3
_RETRY_DELAY_SECONDS: Final[int] = 3


async def get_rdap_info(session: ClientSession, api_token: str | None, asn: str) -> RdapInfo:
    info: RdapInfo = {}
    if not api_token:
        info["request_error"] = "Cloudflare token is not configured"
        return info

    params = {"asn": asn}
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
    }

    for attempt in range(1, _RETRIES + 1):
        try:
            async with session.get(_API_URL, params=params, headers=headers) as response:
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

                if data.get("success") and "asns" in data.get("result", {}):
                    asns_list = data["result"].get("asns") or []
                    if asns_list:
                        asn_info = asns_list[0]
                        info.update({
                            "number": asn_info.get("asn"),
                            "name": asn_info.get("name"),
                            "website": asn_info.get("website"),
                            "country": asn_info.get("country"),
                            "country_name": asn_info.get("countryName"),
                            "aka": asn_info.get("aka"),
                            "org": asn_info.get("orgName"),
                            "source": asn_info.get("source"),
                        })
                    else:
                        info["error"] = "ASN not found in response"
                else:
                    info["error"] = data.get("errors", "Unknown error")
                break

        except aiohttp.ClientResponseError as exc:
            info["request_error"] = f"HTTP error: {exc.status} {exc.message}"
            break
        except aiohttp.ClientError as exc:
            if attempt < _RETRIES:
                await asyncio.sleep(_RETRY_DELAY_SECONDS)
                continue
            info["request_error"] = f"Client error: {exc}"
            break
        except Exception as exc:  # noqa: BLE001
            if attempt < _RETRIES:
                await asyncio.sleep(_RETRY_DELAY_SECONDS)
                continue
            info["request_error"] = str(exc)
            break

    return info
