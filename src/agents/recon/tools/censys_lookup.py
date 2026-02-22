"""Censys host enrichment tool."""

import asyncio
import logging
import os

import httpx

from src.models.asset import ServiceInfo

logger = logging.getLogger(__name__)

_CENSYS_LOOKUP_SEMAPHORE = asyncio.Semaphore(1)


def _empty_result() -> dict:
    return {
        "vulns": [],
        "services": [],
        "ports": [],
        "hostnames": [],
        "os": None,
        "org": None,
        "isp": None,
    }


def _service_version(service: dict) -> str | None:
    software = service.get("software")
    if not isinstance(software, list) or not software:
        return None

    # Prefer entries that actually contain product/version metadata.
    chosen: dict | None = None
    for item in software:
        if not isinstance(item, dict):
            continue
        if any(
            isinstance(item.get(k), str) and item.get(k, "").strip()
            for k in ("product", "version")
        ):
            chosen = item
            break
        if chosen is None:
            chosen = item

    if not chosen:
        return None

    version = chosen.get("version")
    if isinstance(version, str) and version.strip():
        return version.strip()

    return None


def _service_name_from_software(service: dict) -> str | None:
    software = service.get("software")
    if not isinstance(software, list):
        return None

    for item in software:
        if not isinstance(item, dict):
            continue
        product = item.get("product")
        if isinstance(product, str) and product.strip():
            return product.strip().lower()

    return None


def _extract_vulns(host: dict) -> list[str]:
    raw_vulns = host.get("vulnerabilities")
    observed_vulns = host.get("observed_vulnerabilities")
    vulns: set[str] = set()

    if isinstance(raw_vulns, dict):
        for key in raw_vulns.keys():
            if isinstance(key, str):
                vulns.add(key)
    elif isinstance(raw_vulns, list):
        for item in raw_vulns:
            if isinstance(item, str):
                vulns.add(item)
            elif isinstance(item, dict):
                cve = item.get("cve") or item.get("id")
                if isinstance(cve, str):
                    vulns.add(cve)

    if isinstance(observed_vulns, dict):
        for key in observed_vulns.keys():
            if isinstance(key, str):
                vulns.add(key)
    elif isinstance(observed_vulns, list):
        for item in observed_vulns:
            if isinstance(item, str):
                vulns.add(item)
            elif isinstance(item, dict):
                cve = item.get("cve") or item.get("id")
                if isinstance(cve, str):
                    vulns.add(cve)

    for service in host.get("services", []):
        if not isinstance(service, dict):
            continue
        service_vulns = service.get("vulns")
        if isinstance(service_vulns, list):
            for item in service_vulns:
                if isinstance(item, str):
                    vulns.add(item)
        observed = service.get("observed_vulnerabilities")
        if isinstance(observed, list):
            for item in observed:
                if isinstance(item, str):
                    vulns.add(item)
                elif isinstance(item, dict):
                    cve = item.get("cve") or item.get("id")
                    if isinstance(cve, str):
                        vulns.add(cve)
        elif isinstance(observed, dict):
            for key in observed.keys():
                if isinstance(key, str):
                    vulns.add(key)

    return sorted(vulns)


def _extract_services(host: dict) -> tuple[list[int], list[ServiceInfo]]:
    ports: set[int] = set()
    services: dict[tuple[int, str, str | None], ServiceInfo] = {}

    for item in host.get("services", []):
        if not isinstance(item, dict):
            continue

        port = item.get("port")
        if not isinstance(port, int):
            continue

        service_name = (
            _service_name_from_software(item)
            or item.get("extended_service_name")
            or item.get("service_name")
            or item.get("service")
            or item.get("protocol")
            or item.get("transport_protocol")
            or "unknown"
        )
        service = str(service_name).strip().lower()
        version = _service_version(item)

        ports.add(port)
        key = (port, service, version)
        services[key] = ServiceInfo(port=port, service=service, version=version)

    return sorted(ports), sorted(
        services.values(),
        key=lambda s: (s.port, s.service, s.version or ""),
    )


def _extract_hostnames(host: dict) -> list[str]:
    hostnames: set[str] = set()

    direct = host.get("hostnames")
    if isinstance(direct, list):
        for item in direct:
            if isinstance(item, str):
                hostnames.add(item)

    dns = host.get("dns")
    if isinstance(dns, dict):
        names = dns.get("names")
        if isinstance(names, list):
            for item in names:
                if isinstance(item, str):
                    hostnames.add(item)
        forward_dns = dns.get("forward_dns")
        if isinstance(forward_dns, dict):
            for item in forward_dns.keys():
                if isinstance(item, str):
                    hostnames.add(item)

    return sorted(hostnames)


def _extract_enrichment(payload: dict) -> dict:
    host = payload.get("result")
    if isinstance(host, dict) and isinstance(host.get("resource"), dict):
        host = host["resource"]
    if not isinstance(host, dict):
        host = payload

    ports, services = _extract_services(host)
    vulns = _extract_vulns(host)
    hostnames = _extract_hostnames(host)

    operating_system = host.get("operating_system")
    os_name = None
    if isinstance(operating_system, dict):
        os_name = operating_system.get("product") or operating_system.get("name")
    elif isinstance(operating_system, str):
        os_name = operating_system

    autonomous_system = host.get("autonomous_system")
    org = None
    isp = None
    if isinstance(autonomous_system, dict):
        org = autonomous_system.get("description")
        isp = autonomous_system.get("name")

    if org is None:
        org = host.get("organization")

    return {
        "vulns": vulns,
        "services": services,
        "ports": ports,
        "hostnames": hostnames,
        "os": os_name,
        "org": org,
        "isp": isp,
    }


async def _lookup_platform_host(ip: str, api_key: str) -> tuple[int, dict]:
    headers = {"Authorization": f"Bearer {api_key}"}
    url = f"https://api.platform.censys.io/v3/global/asset/host/{ip}"
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(url, headers=headers)
    return response.status_code, response.json()


async def _lookup_legacy_host(
    ip: str,
    api_id: str,
    api_secret: str,
) -> tuple[int, dict]:
    url = f"https://search.censys.io/api/v2/hosts/{ip}"
    async with httpx.AsyncClient(timeout=30.0, auth=(api_id, api_secret)) as client:
        response = await client.get(url)
    return response.status_code, response.json()


async def censys_lookup(ip: str, api_key: str | None = None) -> dict:
    """
    Look up a host in Censys Search.

    Censys API limits are strict for some plans; this tool enforces one
    concurrent request globally.
    """
    api_key = api_key or os.getenv("CENSYS_API_KEY")
    api_id = os.getenv("CENSYS_API_ID")
    api_secret = os.getenv("CENSYS_API_SECRET")

    logger.info("Looking up %s in Censys", ip)

    if not api_key and not (api_id and api_secret):
        logger.warning("No Censys credentials provided, skipping lookup")
        return _empty_result()

    async with _CENSYS_LOOKUP_SEMAPHORE:
        try:
            if api_key:
                status_code, payload = await _lookup_platform_host(ip, api_key)
                if status_code == 200:
                    result = _extract_enrichment(payload)
                    logger.info(
                        "Censys lookup complete for %s: %d ports, %d vulns",
                        ip,
                        len(result["ports"]),
                        len(result["vulns"]),
                    )
                    return result
                if status_code not in (401, 403):
                    logger.warning(
                        "Censys Platform API returned %s for %s",
                        status_code,
                        ip,
                    )
                    return _empty_result()

            # Legacy Search v2 supports API ID/secret basic auth
            if api_id and api_secret:
                status_code, payload = await _lookup_legacy_host(ip, api_id, api_secret)
                if status_code == 200:
                    result = _extract_enrichment(payload)
                    logger.info(
                        "Censys legacy lookup complete for %s: %d ports, %d vulns",
                        ip,
                        len(result["ports"]),
                        len(result["vulns"]),
                    )
                    return result

            if api_key and ":" in api_key:
                split_id, split_secret = api_key.split(":", 1)
                if split_id and split_secret:
                    status_code, payload = await _lookup_legacy_host(
                        ip,
                        split_id,
                        split_secret,
                    )
                    if status_code == 200:
                        result = _extract_enrichment(payload)
                        logger.info(
                            "Censys legacy lookup complete for %s: %d ports, %d vulns",
                            ip,
                            len(result["ports"]),
                            len(result["vulns"]),
                        )
                        return result

            logger.warning("Censys API authentication failed for %s", ip)
            return _empty_result()
        except Exception as exc:
            logger.error("Unexpected error in Censys lookup for %s: %s", ip, exc)
            return _empty_result()
