from __future__ import annotations

import base64
import json
import re
import string
from typing import Final, TypedDict
from urllib.parse import parse_qs, unquote, unquote_plus, urlparse

from aiohttp import ClientError, ClientSession

from config.variables import Settings

_PROXY_SCHEMES: Final[tuple[str, ...]] = ("vless", "trojan", "vmess", "ss")
_PROXY_PATTERN = re.compile(rf"(?i)\b(?:{'|'.join(_PROXY_SCHEMES)})://[^\s]+")
_HEX_CHARS = set(string.hexdigits)
_URL_PATTERN = re.compile(r"https?://[^\s]+", re.IGNORECASE)

_HEADERS = {
    "User-Agent": "ipregion-bot",
    "X-HWID": "e8444c64-212c-4cbb-b7ca-9347a0f260f1",
}


class ProxyPayload(TypedDict, total=False):
    protocol: str
    server: str | None
    port: int | str | None
    type: str | None
    security: str | None
    sni: str | None
    host: str | None
    comment: str | None
    comment_truncated: bool


def _b64_fix(value: str) -> str:
    return value + "=" * (-len(value) % 4)


def _qdict(query: str) -> dict[str, str]:
    return {key.lower(): values[0] for key, values in parse_qs(query).items()}


def extract_proxy_uris(text: str | None) -> list[str]:
    if not text:
        return []
    raw_text = text.strip()
    if not raw_text:
        return []

    seen: set[str] = set()
    uris: list[str] = []
    for match in _PROXY_PATTERN.finditer(raw_text):
        uri = match.group(0).rstrip(")],.;:\n\r")
        if uri not in seen:
            seen.add(uri)
            uris.append(uri)
    if uris:
        return uris

    fallback = raw_text.rstrip(")],.;:\n\r")
    if "://" in fallback:
        scheme = fallback.split('://', 1)[0].lower()
        if scheme in _PROXY_SCHEMES:
            return [fallback]
    return []


def extract_subscription_urls(text: str) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    for candidate in _URL_PATTERN.findall(text):
        try:
            parsed = urlparse(candidate)
        except Exception:
            continue
        if parsed.scheme not in {"http", "https"}:
            continue
        normalized = parsed.geturl()
        if normalized not in seen:
            seen.add(normalized)
            urls.append(normalized)
    return urls


def _decode_fragment(fragment: str | None) -> tuple[str | None, bool]:
    if not fragment:
        return None, False

    cleaned = fragment
    truncated = False

    while cleaned:
        if cleaned.endswith("%"):
            cleaned = cleaned[:-1]
            truncated = True
            continue
        if len(cleaned) >= 2 and cleaned[-2] == "%" and cleaned[-1] in _HEX_CHARS:
            cleaned = cleaned[:-2]
            truncated = True
            continue
        break

    try:
        decoded = unquote_plus(cleaned)
    except Exception:
        decoded = unquote(cleaned, encoding="utf-8", errors="ignore")

    decoded = decoded or ""
    if truncated:
        decoded = decoded.rstrip()

    if not decoded:
        return None, truncated

    return decoded, truncated


def parse_proxy_uri(uri: str) -> ProxyPayload:
    parsed = urlparse((uri or "").strip())
    scheme = (parsed.scheme or "").lower()
    comment, comment_truncated = _decode_fragment(parsed.fragment)

    if scheme in {"vless", "trojan"}:
        query = _qdict(parsed.query)
        payload: ProxyPayload = {
            "protocol": scheme,
            "port": parsed.port,
            "type": query.get("type"),
            "sni": query.get("sni"),
            "host": query.get("host"),
            "server": parsed.hostname,
            "comment": comment,
            "comment_truncated": comment_truncated,
        }
        if scheme == "vless":
            payload["security"] = query.get("security")
        return payload

    if scheme == "vmess":
        if not parsed.netloc and parsed.path:
            try:
                raw = base64.urlsafe_b64decode(_b64_fix(parsed.path)).decode()
                cfg = json.loads(raw)
            except Exception:
                return {
                    "protocol": "vmess",
                    "type": "vmess",
                    "port": None,
                    "sni": None,
                    "host": None,
                    "server": None,
                    "comment": comment,
                    "comment_truncated": comment_truncated,
                }
            network_type = cfg.get("type") or cfg.get("net") or cfg.get("network")
            sni_value = cfg.get("sni") or cfg.get("peer") or cfg.get("servername")
            ws_opts = cfg.get("ws-opts") or {}
            headers = ws_opts.get("headers") or {}
            host_header = headers.get("Host")
            return {
                "protocol": "vmess",
                "port": cfg.get("port"),
                "type": network_type,
                "sni": sni_value,
                "host": cfg.get("host") or host_header,
                "server": cfg.get("add") or cfg.get("address") or cfg.get("server"),
                "comment": comment,
                "comment_truncated": comment_truncated,
            }
        query = _qdict(parsed.query)
        return {
            "protocol": "vmess",
            "port": parsed.port,
            "type": query.get("type"),
            "sni": query.get("sni") or query.get("peer") or query.get("servername"),
            "host": query.get("host") or query.get("authority"),
            "server": parsed.hostname,
            "comment": comment,
            "comment_truncated": comment_truncated,
        }

    if scheme == "ss":
        netloc = parsed.netloc or ""
        if "@" in netloc:
            userinfo, hostport = netloc.rsplit("@", 1)
            try:
                decoded_userinfo = base64.urlsafe_b64decode(_b64_fix(userinfo)).decode()
                if ":" in decoded_userinfo:
                    netloc = f"{decoded_userinfo}@{hostport}"
            except Exception:
                pass
        elif not netloc and parsed.path:
            try:
                decoded_full = base64.urlsafe_b64decode(_b64_fix(parsed.path)).decode()
                if "@" in decoded_full:
                    netloc = decoded_full
            except Exception:
                pass

        method, host, port = None, None, None
        if "@" in netloc:
            creds, hostport = netloc.rsplit("@", 1)
            if ":" in creds:
                method = creds.split(":", 1)[0]
            host_str, port_str = None, None
            if hostport.startswith("["):
                closing = hostport.find("]")
                if closing != -1:
                    host_str = hostport[1:closing]
                    rest = hostport[closing + 1 :]
                    if rest.startswith(":"):
                        port_str = rest[1:]
            else:
                if ":" in hostport:
                    host_str, port_str = hostport.rsplit(":", 1)
            host = host_str
            try:
                port = int(port_str) if port_str else None
            except Exception:
                port = None

        return {
            "protocol": "ss",
            "port": port,
            "type": method,
            "host": host,
            "server": parsed.hostname or host,
            "comment": comment,
            "comment_truncated": comment_truncated,
        }

    return {
        "protocol": scheme,
        "server": parsed.hostname,
        "port": parsed.port,
        "type": None,
        "sni": None,
        "host": None,
        "comment": comment,
        "comment_truncated": comment_truncated,
    }


def parse_subscription_payload(raw: str) -> list[ProxyPayload]:
    proxies: list[ProxyPayload] = []
    seen: set[str] = set()
    for line in raw.splitlines():
        candidate = line.strip()
        if not candidate:
            continue
        for uri in extract_proxy_uris(candidate):
            if uri in seen:
                continue
            seen.add(uri)
            proxies.append(parse_proxy_uri(uri))
    return proxies


def _is_valid_subscription_url(url: str) -> bool:
    try:
        parsed = urlparse(url.strip())
    except Exception:
        return False
    if parsed.scheme not in {"http", "https"}:
        return False
    if not parsed.netloc:
        return False
    if not parsed.path or parsed.path == "/":
        return False
    return True


async def fetch_subscription_proxies(
    session: ClientSession,
    settings: Settings,
    url: str,
) -> tuple[list[ProxyPayload], str | None]:
    if not _is_valid_subscription_url(url):
        return [], "❌ Invalid subscription URL"

    request_kwargs: dict[str, object] = {"headers": _HEADERS}
    if settings.outbound_proxy:
        request_kwargs["proxy"] = settings.outbound_proxy

    try:
        async with session.get(url, **request_kwargs) as response:
            if response.status >= 400:
                return [], f"❌ Subscription request failed: HTTP {response.status}"
            body = await response.text()
    except ClientError as exc:
        return [], f"❌ Subscription request error: {exc}"
    except Exception as exc:  # noqa: BLE001
        return [], f"❌ Subscription request error: {exc}"

    decoded = None
    compact = "".join(body.strip().split())
    if compact:
        for decoder in (base64.urlsafe_b64decode, base64.b64decode):
            try:
                decoded_bytes = decoder(_b64_fix(compact))
                decoded = decoded_bytes.decode("utf-8", errors="ignore")
                break
            except Exception:
                continue
    if decoded:
        proxies = parse_subscription_payload(decoded)
        if proxies:
            return proxies, None

    proxies = parse_subscription_payload(body)
    if not proxies:
        return [], "❌ No proxies found in subscription"
    return proxies, None
