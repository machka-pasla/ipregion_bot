from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
import tempfile
import time
import uuid
from collections import OrderedDict
from http import HTTPStatus
from typing import Iterable, TypedDict
from urllib.parse import urlparse

import aiohttp
import tldextract
from aiogram import Bot, Dispatcher
from aiogram.filters import Command
from aiogram.types import InlineQuery, InlineQueryResultArticle, InputTextMessageContent, Message

from config.bogon_ranges import BOGON_RANGES
from config.countries import country_name
from config.flags import country_flag
from config.text_file_extensions import TEXT_FILE_EXTENSIONS
from config.variables import (
    BOT_API_TOKEN,
    CLOUDFLARE_API_TOKEN,
    ENABLE_SUBSCRIPTION_CHECK,
    IPINFO_TOKEN,
    IPREGISTRY_API_TOKEN,
    MAXMIND_DB_ASN,
    MAXMIND_DB_ASN_URL,
    MAXMIND_DB_CITY,
    MAXMIND_DB_CITY_URL,
    OUTBOUND_PROXY,
    SETTINGS,
)
from services.cloudflare import get_cloudflare_info
from services.http_client import HttpClientManager
from services.ipinfo import get_ipinfo_info
from services.ipregistry import get_ipregistry_info
from services.maxmind import get_maxmind_info
from services.rdap import get_rdap_info
from services.subscriptions import (
    ProxyPayload,
    extract_subscription_urls,
    fetch_subscription_proxies,
)
from services.types import (
    CloudflareInfo,
    HostInfo,
    IPInfoData,
    IPRegistryInfo,
    MaxMindInfo,
    RdapInfo,
)

CHECK_INTERVAL_SECONDS = 60 * 60
UPDATE_THRESHOLD_SECONDS = 24 * 60 * 60
MAX_TELEGRAM_MESSAGES_PER_SECOND = 25
MIN_DB_FILE_SIZE_BYTES = 1 * 1024 * 1024

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


class ResolutionResult(TypedDict):
    host: str
    ips: list[str]
    is_domain: bool
    ech_supported: bool


class RateLimiter:
    __slots__ = ("_max_calls", "_period", "_events", "_lock")

    def __init__(self, max_calls: int, period: float) -> None:
        self._max_calls = max_calls
        self._period = period
        self._events: list[float] = []
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        loop = asyncio.get_running_loop()
        async with self._lock:
            now = loop.time()
            self._events = [event for event in self._events if event > now - self._period]
            if len(self._events) >= self._max_calls:
                sleep_for = self._events[0] + self._period - now
                await asyncio.sleep(max(sleep_for, 0))
                now = loop.time()
                self._events = [event for event in self._events if event > now - self._period]
            self._events.append(loop.time())


http_client = HttpClientManager()
rate_limiter = RateLimiter(MAX_TELEGRAM_MESSAGES_PER_SECOND, 1.0)


def describe_bogon(ip: str) -> str | None:
    ip_obj = ipaddress.ip_address(ip)
    for net, desc in BOGON_RANGES.items():
        if ip_obj in ipaddress.ip_network(net, strict=False):
            return desc
    return None


def normalize_target(query: str) -> str:
    query = (query or "").strip()
    if not query:
        return ""

    try:
        ipaddress.ip_address(query)
        return query
    except ValueError:
        pass

    if "://" not in query:
        query = "https://" + query

    parsed = urlparse(query)
    host = parsed.hostname or ""
    if host.lower() == "localhost":
        return "127.0.0.1"
    return host


def _to_punycode(value: str) -> str:
    try:
        return value.encode("idna").decode("ascii")
    except Exception:
        return value


def extract_hosts(text: str) -> list[str]:
    ipv4_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
    ipv6_pattern = r"\b(?:[A-Fa-f0-9:]+:+)+[A-Fa-f0-9]+\b"
    domain_pattern = r"\b(?:[a-zA-Z0-9\u00a1-\uffff-]{1,63}\.)+[a-zA-Z\u00a1-\uffff]{2,63}\b"

    ips = re.findall(ipv4_pattern, text)
    ips += re.findall(ipv6_pattern, text)
    domains = re.findall(domain_pattern, text, flags=re.UNICODE)

    seen: set[str] = set()
    ordered: list[str] = []
    for item in ips + domains:
        if item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered


def is_valid_target(value: str) -> bool:
    if not value:
        return False
    if value.lower() == "localhost":
        return True
    parsed = urlparse(value)
    if parsed.scheme in {"http", "https"} and parsed.hostname:
        host = _to_punycode(parsed.hostname)
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            domain_re = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9-]{2,63}$")
            return bool(domain_re.match(host))
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    return bool(re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9-]{2,63}$", _to_punycode(value)))


async def _doh_query(session: aiohttp.ClientSession, domain: str, doh_url: str, record_type: str) -> list[str]:
    headers = {"Accept": "application/dns-json"}
    try:
        async with session.get(
            doh_url,
            params={"name": domain, "type": record_type},
            headers=headers,
        ) as response:
            data = await response.json(content_type=None)
    except Exception:
        return []
    answers = data.get("Answer") or data.get("answer")
    if not answers:
        return []
    return [str(item.get("data")) for item in answers if item.get("data")]


async def resolve_host(session: aiohttp.ClientSession, query: str) -> ResolutionResult:
    normalized = normalize_target(query)
    if not normalized:
        return {"host": "", "ips": [], "is_domain": False, "ech_supported": False}

    try:
        ipaddress.ip_address(normalized)
        return {"host": normalized, "ips": [normalized], "is_domain": False, "ech_supported": False}
    except ValueError:
        pass

    puny = _to_punycode(normalized)
    to_resolve = [puny]
    final_ips: list[str] = []
    ech_supported = False
    seen: set[str] = set()

    doh_endpoints = ("https://1.1.1.1/dns-query", "https://1.0.0.1/dns-query")

    for doh_url in doh_endpoints:
        queue = OrderedDict((item, None) for item in to_resolve if item not in seen)
        while queue:
            domain, _ = queue.popitem(last=False)
            if domain in seen:
                continue
            seen.add(domain)

            tasks = {
                record: asyncio.create_task(_doh_query(session, domain, doh_url, record))
                for record in ("A", "AAAA", "CNAME", "HTTPS")
            }
            results = {record: await task for record, task in tasks.items()}

            for record in ("A", "AAAA"):
                for candidate in results[record]:
                    try:
                        ipaddress.ip_address(candidate)
                    except ValueError:
                        continue
                    if candidate not in final_ips:
                        final_ips.append(candidate)

            for cname in results["CNAME"]:
                cname = cname.rstrip(".")
                if cname and cname not in seen:
                    queue.setdefault(cname, None)

            for https_record in results["HTTPS"]:
                try:
                    parts = https_record.split()
                    if len(parts) < 3:
                        continue
                    data_bytes = bytes.fromhex("".join(parts[2:]))
                    if b"cloudflare-ech.com" in data_bytes:
                        ech_supported = True
                except Exception:
                    continue

            if final_ips:
                break
        if final_ips:
            break

    return {
        "host": normalized,
        "ips": final_ips,
        "is_domain": bool(final_ips),
        "ech_supported": ech_supported,
    }


def _format_asn(number: str | int | None, org: str | None) -> str | None:
    if number in (None, "", 0):
        return None
    prefix = f"AS{number}" if isinstance(number, int) or str(number).isdigit() else str(number)
    if org:
        return f"{prefix} / {org}"
    return prefix


def _country_line(code: str | None, region: str | None = None, city: str | None = None) -> str | None:
    if not code:
        return None
    flag = country_flag(code)
    name = country_name(code)
    parts = [f"{flag} {code}".strip(), name]
    if region:
        parts.append(region)
    if city and city != region:
        parts.append(city)
    return ", ".join(part for part in parts if part)


def _section(title: str, lines: Iterable[str]) -> list[str]:
    filtered = [line for line in lines if line]
    if not filtered:
        return []
    return [f"○  <b>{title}</b>"] + list(filtered)


def sort_ips(addresses: Iterable[str]) -> list[str]:
    def _key(value: str):
        try:
            ip_obj = ipaddress.ip_address(value.strip())
            return (ip_obj.version, ip_obj)
        except ValueError:
            return (9, value)

    return sorted(set(addresses), key=_key)


async def fetch_geo(session: aiohttp.ClientSession, ip: str) -> HostInfo:
    maxmind_task = asyncio.create_task(get_maxmind_info(ip))
    ipinfo_task = asyncio.create_task(get_ipinfo_info(session, IPINFO_TOKEN, ip))
    cloudflare_task = asyncio.create_task(get_cloudflare_info(session, CLOUDFLARE_API_TOKEN, ip))
    ipregistry_task = asyncio.create_task(get_ipregistry_info(session, IPREGISTRY_API_TOKEN, ip))

    maxmind: MaxMindInfo = await maxmind_task
    ipinfo: IPInfoData = await ipinfo_task
    cloudflare: CloudflareInfo = await cloudflare_task
    ipregistry: IPRegistryInfo = await ipregistry_task

    asn_number = cloudflare.get("asn_number") if isinstance(cloudflare, dict) else None
    if asn_number:
        rdap: RdapInfo = await get_rdap_info(session, CLOUDFLARE_API_TOKEN, str(asn_number))
    else:
        rdap = {"error": "ASN unavailable"}

    return {
        "host": ip,
        "ip": ip,
        "maxmind": maxmind,
        "ipinfo": ipinfo,
        "cloudflare": cloudflare,
        "rdap": rdap,
        "ipregistry": ipregistry,
    }


def build_report(resolution: ResolutionResult, info: HostInfo) -> str:
    ip = info["ip"]
    bogon_desc = describe_bogon(ip)
    bgp_link = f"https://bgp.tools/prefix-selector?ip={ip}"
    censys_link = f"https://search.censys.io/hosts/{ip}"
    ipinfo_link = f"https://ipinfo.io/{ip}"
    ip_line = f"<b>IP:</b> <code>{ip}</code>\n<a href='{bgp_link}'>BGP</a> / <a href='{censys_link}'>Censys</a> / <a href='{ipinfo_link}'>Ipinfo.io</a>"

    if bogon_desc:
        return f"{ip_line.split('\n')[0]}\n⚠️ <b>Private Network IP:</b> {bogon_desc}"

    lines: list[str] = []
    maxmind = info.get("maxmind", {})
    maxmind_lines = []
    country_line = _country_line(maxmind.get("country"), maxmind.get("region"), maxmind.get("city"))
    maxmind_lines.append(country_line or "🏳 Region not specified")
    as_line = _format_asn(maxmind.get("asn_number"), maxmind.get("asn_org"))
    if as_line:
        maxmind_lines.append(as_line)
    lines.extend(_section("MaxMind:", maxmind_lines))

    ipinfo = info.get("ipinfo", {})
    if ipinfo.get("error") == f"HTTP {HTTPStatus.TOO_MANY_REQUESTS.value}":
        lines.extend([""] + ["○  <b>IPinfo:</b>", "Too Many Requests, please wait"])
    elif "error" in ipinfo:
        lines.extend([""] + ["⚠️ IPinfo error"])
    else:
        ipinfo_lines = []
        country_line = _country_line(ipinfo.get("country"), ipinfo.get("region"), ipinfo.get("city"))
        if country_line:
            ipinfo_lines.append(country_line)
        as_line = _format_asn(ipinfo.get("asn_number"), ipinfo.get("asn_org"))
        if as_line:
            ipinfo_lines.append(as_line)
        lines.extend([""] + _section("IPinfo:", ipinfo_lines))

    cloudflare = info.get("cloudflare", {})
    if cloudflare.get("request_error"):
        lines.extend([""] + [f"⚠️ Cloudflare error: {cloudflare['request_error']}"])
    else:
        cf_lines = []
        country_line = _country_line(cloudflare.get("country"))
        if country_line:
            cf_lines.append(country_line)
        as_line = _format_asn(cloudflare.get("asn_number"), cloudflare.get("asn_org") or cloudflare.get("asn_name"))
        if as_line:
            cf_lines.append(as_line)
        lines.extend([""] + _section("Cloudflare:", cf_lines))

    rdap = info.get("rdap", {})
    if rdap.get("request_error"):
        lines.extend([""] + [f"⚠️ RDAP error: {rdap['request_error']}"])
    elif rdap.get("error"):
        lines.extend([""] + [f"⚠️ RDAP error: {rdap['error']}"])
    else:
        rdap_lines = []
        country_line = _country_line(rdap.get("country"))
        if country_line:
            rdap_lines.append(country_line)
        name = rdap.get("name") or rdap.get("org")
        if name:
            website = rdap.get("website")
            if website and website.lower() != "none":
                rdap_lines.append(f"<a href='{website}'>{name}</a>")
            else:
                rdap_lines.append(name)
        aka = rdap.get("aka")
        if aka:
            rdap_lines.append(aka)
        source = rdap.get("source")
        title = "Registration:"
        if isinstance(source, str) and source:
            title = f"Registration ({source.upper()}):"
        lines.extend([""] + _section(title, rdap_lines))

    ipregistry = info.get("ipregistry", {})
    if isinstance(ipregistry, dict):
        if ipregistry.get("request_error"):
            lines.extend([""] + [f"⚠️ ipregistry error: {ipregistry['request_error']}"])
        else:
            security = ipregistry.get("security") or {}
            checks = OrderedDict(
                (
                    ("Malicious", security.get("is_abuser") or security.get("is_attacker") or security.get("is_threat")),
                    ("Server", security.get("is_cloud_provider") or security.get("is_relay")),
                    ("Proxy", security.get("is_proxy") or security.get("is_tor") or security.get("is_tor_exit") or security.get("is_anonymous")),
                    ("VPN", security.get("is_vpn")),
                )
            )
            security_lines = [f"{label}: {'✅' if value else '❌'}" for label, value in checks.items()]
            lines.extend([""] + _section("VPN Info (ipregistry.co):", security_lines))

    header: str | None = None
    footer_note: str | None = None
    if resolution["is_domain"]:
        puny = _to_punycode(resolution["host"])
        ext = tldextract.extract(puny)
        suffix = (ext.suffix or "").lower()
        root = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else puny
        if suffix in {"ru", "su", "дети", "tatar", "рф"}:
            whois_link = f"https://whois.tcinet.ru#{root}"
        elif suffix == "ua":
            whois_link = f"https://www.hostmaster.ua/whois/?_domain={root}"
        else:
            whois_link = f"https://info.addr.tools/{root}"
        header = f"🔗 <b>Host:</b> {resolution['host']} (<a href='{whois_link}'>Whois</a>?)"
        if resolution["ech_supported"]:
            footer_note = "✅ ECH is supported"

    separator = "----------------"
    report_lines: list[str] = []
    if header:
        report_lines.append(header)

    report_lines.append(separator)
    report_lines.append(ip_line)

    if lines:
        if lines[0] != "":
            report_lines.append("")
        report_lines.extend(lines)

    if footer_note:
        if report_lines and report_lines[-1] != "":
            report_lines.append("")
        report_lines.append(footer_note)

    report_lines.append(separator)

    return "\n".join(report_lines).strip()


async def gather_host_entries(session: aiohttp.ClientSession, target: str) -> list[dict[str, str | None]]:
    resolution = await resolve_host(session, target)
    if not resolution["ips"]:
        return []
    entries: list[dict[str, str | None]] = []
    for ip in sort_ips(resolution["ips"]):
        bogon_desc = describe_bogon(ip)
        if bogon_desc:
            entries.append({
                "country": None,
                "text": f"<b>IP:</b> <code>{ip}</code>\n⚠️ <b>Private Network IP:</b> {bogon_desc}",
            })
            continue
        info = await fetch_geo(session, ip)
        resolution_payload: ResolutionResult = {
            "host": resolution["host"],
            "ips": [ip],
            "is_domain": resolution["is_domain"],
            "ech_supported": resolution["ech_supported"],
        }
        text = build_report(resolution_payload, info)
        country = info.get("maxmind", {}).get("country") or info.get("cloudflare", {}).get("country")
        entries.append({"country": country, "text": text})
    return entries


async def inspect_target(session: aiohttp.ClientSession, target: str) -> list[str]:
    return [entry["text"] for entry in await gather_host_entries(session, target) if entry["text"]]


def _clean_text(raw: str) -> str:
    text = re.sub(r"[,'\"!?]", " ", raw)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


async def extract_message_text(bot: Bot, message: Message) -> tuple[str, str | None]:
    if message.text:
        return _clean_text(message.text), None

    if message.document:
        doc = message.document
        filename = doc.file_name or ""
        mimetype = doc.mime_type or ""
        if mimetype.startswith("text/") or filename.endswith(TEXT_FILE_EXTENSIONS):
            file_info = await bot.get_file(doc.file_id)
            file = await bot.download_file(file_info.file_path)
            data = file.read().decode("utf-8", errors="ignore")
            return _clean_text(data), None
        return "", "❌ This file is not in text format."

    return "", None


async def ensure_database_fresh(session: aiohttp.ClientSession, path: str, url: str | None) -> None:
    if not url:
        return
    file_path = os.path.abspath(path)
    if not os.path.exists(file_path):
        logger.info("%s not found. Downloading.", file_path)
        await download_database(session, file_path, url)
        return
    size_bytes = os.path.getsize(file_path)
    if size_bytes < MIN_DB_FILE_SIZE_BYTES:
        logger.warning("%s is too small (%s bytes). Re-downloading.", file_path, size_bytes)
        await download_database(session, file_path, url)
        return
    age_seconds = time.time() - os.path.getmtime(file_path)
    if age_seconds <= UPDATE_THRESHOLD_SECONDS:
        return
    logger.info("%s is outdated (%s seconds). Updating.", file_path, int(age_seconds))
    await download_database(session, file_path, url)


async def download_database(session: aiohttp.ClientSession, path: str, url: str) -> None:
    logger.info("Downloading %s to %s", url, path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temp_path: str | None = None
    try:
        timeout = aiohttp.ClientTimeout(total=None)
        async with session.get(url, timeout=timeout) as response:
            response.raise_for_status()
            with tempfile.NamedTemporaryFile(mode="wb", delete=False, dir=os.path.dirname(path)) as handle:
                temp_path = handle.name
                async for chunk in response.content.iter_chunked(1024 * 1024):
                    handle.write(chunk)
        os.replace(temp_path, path)
        logger.info("Geo database %s updated", path)
    except Exception:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass
        raise


async def updater_loop(stop_event: asyncio.Event) -> None:
    session = http_client.session
    while not stop_event.is_set():
        await asyncio.gather(
            ensure_database_fresh(session, MAXMIND_DB_CITY, MAXMIND_DB_CITY_URL),
            ensure_database_fresh(session, MAXMIND_DB_ASN, MAXMIND_DB_ASN_URL),
        )
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=CHECK_INTERVAL_SECONDS)
        except asyncio.TimeoutError:
            continue


def _format_proxy_comment(payload: ProxyPayload, default_country: str | None) -> str:
    comment = payload.get("comment")
    if comment and payload.get("comment_truncated"):
        comment = f"{comment}…"

    def _clean(value: object | None, uppercase: bool = False) -> str | None:
        if value in (None, "", "-"):
            return None
        text = str(value)
        return text.upper() if uppercase else text

    headline_parts: list[str] = []

    if default_country:
        flag = country_flag(default_country)
        name = country_name(default_country)
        country_part = " ".join(part for part in (flag, name) if part).strip()
        if country_part:
            headline_parts.append(country_part)

    protocol = _clean(payload.get("protocol"), uppercase=True)
    if protocol:
        headline_parts.append(protocol)

    server = _clean(payload.get("server")) or _clean(payload.get("host"))
    port = _clean(payload.get("port"))
    if server:
        endpoint = f"{server}:{port}" if port else server
        headline_parts.append(endpoint)

    connection_type = _clean(payload.get("type"))
    if connection_type:
        headline_parts.append(connection_type)

    security = _clean(payload.get("security"))
    if security:
        headline_parts.append(security)

    if comment:
        headline_parts.append(comment)

    if headline_parts:
        seen: set[str] = set()
        unique_parts: list[str] = []
        for part in headline_parts:
            if part not in seen:
                seen.add(part)
                unique_parts.append(part)
        return " • ".join(unique_parts)

    return "Proxy"


def format_proxy_message(
    payload: ProxyPayload,
    extra_header: str | None,
    host_report: str | None,
) -> str:
    def _normalize(value: object) -> str:
        return "-" if value in (None, "") else str(value)

    lines = []
    if extra_header:
        lines.append(f"🔝 {extra_header}")
        lines.append("")

    lines.append("🔗 Proxy:")
    lines.append(f"protocol={_normalize(payload.get('protocol'))}")
    lines.append(f"server={_normalize(payload.get('server'))}")
    lines.append(f"port={_normalize(payload.get('port'))}")
    lines.append(f"type={_normalize(payload.get('type'))}")
    lines.append(f"security={_normalize(payload.get('security'))}")
    lines.append(f"sni={_normalize(payload.get('sni'))}")
    lines.append(f"host={_normalize(payload.get('host'))}")

    if host_report:
        lines.extend([""])
        lines.append(host_report)

    return "\n".join(lines)


async def process_subscription(url: str, message: Message) -> set[str]:
    session = http_client.session
    skip_hosts: set[str] = set()

    parsed = urlparse(url)
    domain = parsed.hostname
    if domain:
        reports = await inspect_target(session, domain)
        for report in reports:
            await rate_limiter.acquire()
            await message.answer(report, parse_mode="HTML", disable_web_page_preview=True)
        skip_hosts.add(domain.lower())
        skip_hosts.add(_to_punycode(domain).lower())

    proxies, error = await fetch_subscription_proxies(session, SETTINGS, url)
    if error:
        await rate_limiter.acquire()
        await message.answer(error)
        return skip_hosts

    for payload in proxies:
        server = payload.get("server")
        host_report = None
        if server:
            host_entries = await gather_host_entries(session, server)
            host_report = host_entries[0]["text"] if host_entries else None
            header = _format_proxy_comment(
                payload,
                host_entries[0]["country"] if host_entries else None,
            )
            skip_hosts.add(server.lower())
            skip_hosts.add(_to_punycode(server).lower())
        else:
            header = _format_proxy_comment(payload, None)
        text = format_proxy_message(payload, header, host_report)
        await rate_limiter.acquire()
        await message.answer(text, parse_mode="HTML", disable_web_page_preview=True)
    return skip_hosts


async def handle_text(message: Message, text: str) -> None:
    session = http_client.session
    skip_hosts: set[str] = set()
    if ENABLE_SUBSCRIPTION_CHECK:
        for url in extract_subscription_urls(text):
            skip_hosts.update(await process_subscription(url, message))

    found = False
    for target in extract_hosts(text):
        if not is_valid_target(target):
            continue
        normalized = target.lower()
        if normalized in skip_hosts or _to_punycode(normalized).lower() in skip_hosts:
            continue
        reports = await inspect_target(session, target)
        for report in reports:
            await rate_limiter.acquire()
            await message.answer(report, parse_mode="HTML", disable_web_page_preview=True)
            found = True
    if not found:
        await rate_limiter.acquire()
        await message.answer("❌ No IPs or domains found.")


async def start_bot() -> None:
    if not BOT_API_TOKEN:
        raise RuntimeError("BOT_API_TOKEN is required")

    bot = Bot(BOT_API_TOKEN)
    dp = Dispatcher()

    @dp.startup()
    async def on_startup(bot: Bot) -> None:  # noqa: ARG001
        await http_client.startup()
        logger.info("Bot started")

    @dp.shutdown()
    async def on_shutdown(bot: Bot) -> None:  # noqa: ARG001
        await http_client.shutdown()
        logger.info("Bot stopped")

    stop_event = asyncio.Event()

    async def updater_worker() -> None:
        if not MAXMIND_DB_CITY_URL and not MAXMIND_DB_ASN_URL:
            return
        await http_client.startup()
        await updater_loop(stop_event)

    @dp.message(Command("start"))
    async def start_handler(message: Message) -> None:
        await rate_limiter.acquire()
        await message.answer("Hi! Send me an IPv4, IPv6, or domain name, and I’ll show you its geo information.")

    @dp.message()
    async def message_handler(message: Message) -> None:
        text, error = await extract_message_text(bot, message)
        if error:
            await rate_limiter.acquire()
            await message.answer(error)
            return
        if not text:
            return
        await handle_text(message, text)

    @dp.inline_query()
    async def inline_handler(query: InlineQuery) -> None:
        raw = query.query.strip()
        if not raw:
            return
        session = http_client.session
        reports = await inspect_target(session, raw)
        if not reports:
            content = InputTextMessageContent(message_text=f"❌ Failed to resolve IP for: {raw}")
        else:
            content = InputTextMessageContent(
                message_text=reports[0],
                parse_mode="HTML",
                disable_web_page_preview=True,
            )
        result = InlineQueryResultArticle(
            id=str(uuid.uuid4()),
            title=f"Send geo info about: {raw}",
            input_message_content=content,
        )
        await query.answer([result], cache_time=10, is_personal=True)

    updater_task = asyncio.create_task(updater_worker())
    try:
        await dp.start_polling(bot)
    finally:
        stop_event.set()
        await updater_task


if __name__ == "__main__":
    asyncio.run(start_bot())
