"""Nmap port scanning tool."""

import asyncio
import logging
import socket

import nmap

from src.models.asset import AssetDocument, ServiceInfo

logger = logging.getLogger(__name__)


async def run_nmap(
    target: str,
    engagement_id: str,
    ports: str = "1-1000",
    arguments: str = "-sV",
) -> AssetDocument | None:
    """
    Run nmap scan against a target.

    Args:
        target: IP address or hostname to scan
        engagement_id: Parent engagement ID
        ports: Port range to scan (default: 1-1000)
        arguments: Nmap arguments (default: -sV for version detection)

    Returns:
        AssetDocument with populated ip, open_ports, and services fields
    """
    logger.info(f"Starting nmap scan on {target} ports {ports}")

    # Run nmap in a thread pool to not block async loop
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        None, _run_nmap_sync, target, ports, arguments
    )

    if result is None:
        return None

    ip, open_ports, services = result

    # Determine asset type based on common web ports
    web_ports = {80, 443, 8080, 8443, 3000, 5000, 8000}
    asset_type = "web_app" if any(p in web_ports for p in open_ports) else "host"

    asset = AssetDocument(
        engagement_id=engagement_id,
        asset_type=asset_type,
        ip=ip,
        open_ports=open_ports,
        services=services,
    )

    logger.info(f"Nmap scan complete: {len(open_ports)} open ports on {ip}")
    return asset


def _run_nmap_sync(
    target: str,
    ports: str,
    arguments: str,
) -> tuple[str, list[int], list[ServiceInfo]] | None:
    """Synchronous nmap scan (runs in thread pool)."""
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=target, ports=ports, arguments=arguments)

        # Get the scanned host (might be IP even if hostname was provided)
        hosts = nm.all_hosts()
        if not hosts:
            logger.warning(f"No hosts found for target {target}")
            return None

        host = hosts[0]
        ip = host

        # Resolve hostname to IP if needed
        if not _is_ip(target):
            try:
                ip = socket.gethostbyname(target)
            except socket.gaierror:
                ip = host

        open_ports: list[int] = []
        services: list[ServiceInfo] = []

        # Extract port and service info
        if "tcp" in nm[host]:
            for port, port_info in nm[host]["tcp"].items():
                if port_info["state"] == "open":
                    open_ports.append(port)

                    service_name = port_info.get("name", "unknown")
                    version = port_info.get("version", "").strip()

                    # Only emit the bare version number, not product name
                    version_str = version or None

                    services.append(ServiceInfo(
                        port=port,
                        service=service_name,
                        version=version_str,
                    ))

        return ip, sorted(open_ports), services

    except nmap.PortScannerError as e:
        logger.error(f"Nmap scan failed: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error during nmap scan: {e}")
        return None


def _is_ip(target: str) -> bool:
    """Check if target is an IP address."""
    try:
        socket.inet_aton(target)
        return True
    except socket.error:
        return False
