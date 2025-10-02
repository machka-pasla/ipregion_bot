from __future__ import annotations

from typing import TypedDict


class MaxMindInfo(TypedDict, total=False):
    country: str
    country_name: str | None
    region: str | None
    city: str | None
    asn_number: int
    asn_org: str | None
    city_error: str
    asn_error: str


class IPInfoData(TypedDict, total=False):
    country: str
    region: str | None
    city: str | None
    asn_number: str | None
    asn_org: str | None
    error: str


class CloudflareInfo(TypedDict, total=False):
    ip: str
    ip_version: str | None
    country: str | None
    country_name: str | None
    asn_number: str | None
    asn_name: str | None
    asn_org: str | None
    asn_location: str | None
    request_error: str
    error: str


class RdapInfo(TypedDict, total=False):
    number: int | str | None
    name: str | None
    website: str | None
    country: str | None
    country_name: str | None
    aka: str | None
    org: str | None
    source: str | None
    request_error: str
    error: str


class SecurityFlags(TypedDict, total=False):
    is_abuser: bool
    is_attacker: bool
    is_bogon: bool
    is_cloud_provider: bool
    is_proxy: bool
    is_relay: bool
    is_tor: bool
    is_tor_exit: bool
    is_vpn: bool
    is_anonymous: bool
    is_threat: bool


class IPRegistryInfo(TypedDict, total=False):
    ip: str
    type: str | None
    hostname: str | None
    city: str | None
    region: str | None
    region_code: str | None
    country: str | None
    country_code: str | None
    latitude: float | None
    longitude: float | None
    asn_number: int | str | None
    asn_org: str | None
    network: str | None
    security: SecurityFlags
    request_error: str


class HostInfo(TypedDict):
    host: str
    ip: str
    maxmind: MaxMindInfo
    ipinfo: IPInfoData
    cloudflare: CloudflareInfo
    rdap: RdapInfo
    ipregistry: IPRegistryInfo

