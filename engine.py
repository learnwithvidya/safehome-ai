from __future__ import annotations

from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime
import getpass
import platform
import psutil
import socket
from ipaddress import ip_network, ip_address

from scanner.discover import discover_devices
from scanner.ports import scan_device_ports
from scanner.risk import assess_device_risk
from reports.template import render_report


def _get_host_ip_for_network(network_cidr: str) -> str | None:
    """
    Try to find the IP address of this machine that belongs to the scanned network.
    This makes the report clearly auditable: which IP initiated the scan.
    """
    try:
        net = ip_network(network_cidr, strict=False)
    except ValueError:
        return None

    addrs = psutil.net_if_addrs()
    for iface_addrs in addrs.values():
        for addr in iface_addrs:
            if addr.family != socket.AF_INET:
                continue
            ip_str = addr.address
            if ip_str.startswith("127."):
                continue
            try:
                ip_obj = ip_address(ip_str)
            except ValueError:
                continue
            if ip_obj in net:
                return ip_str

    return None


def run_safehome_scan(network: str) -> Dict[str, Any]:
    # ------------------------------------------------------------------
    # Scan timing: start
    # ------------------------------------------------------------------
    scan_started = datetime.now()

    devices = discover_devices(network_cidr=network)

    results: List[Dict[str, Any]] = []

    for dev in devices:
        ports = scan_device_ports(dev.ip)
        risk = assess_device_risk(ports=ports, vendor=dev.vendor)

        results.append({
            "ip": dev.ip,
            "mac": dev.mac,
            "vendor": dev.vendor,
            "hostname": dev.hostname,
            "open_ports": ports,
            "risk": risk
        })

    # ------------------------------------------------------------------
    # Scan timing: end + metadata
    # ------------------------------------------------------------------
    scan_finished = datetime.now()
    duration_seconds = (scan_finished - scan_started).total_seconds()

    timestamp = scan_finished.strftime("%Y%m%d_%H%M%S")
    report_id = f"SAFEHOME-{timestamp}"

    creator_username = getpass.getuser()
    creator_hostname = platform.node()
    creator_ip = _get_host_ip_for_network(network)

    metadata: Dict[str, Any] = {
        "app_name": "SafeHome-AI",
        "app_version": "2.0.0",
        "report_id": report_id,

        "scan_started_at": scan_started.strftime("%Y-%m-%d %H:%M:%S"),
        "scan_finished_at": scan_finished.strftime("%Y-%m-%d %H:%M:%S"),
        "duration_seconds": duration_seconds,

        "network_scanned": network,
        "device_count": len(results),

        "creator_username": creator_username,
        "creator_hostname": creator_hostname,
        "creator_ip": creator_ip,
    }

    # ------------------------------------------------------------------
    # Save HTML report in reports/html/report_YYYYMMDD_HHMMSS.html
    # ------------------------------------------------------------------
    reports_root = Path("reports") / "html"
    reports_root.mkdir(parents=True, exist_ok=True)

    report_filename = f"report_{timestamp}.html"
    report_path = reports_root / report_filename

    render_report(
        results=results,
        network=network,
        output_path=report_path,
        metadata=metadata,
    )

    return {
        "network": network,
        "devices": results,
        "report_path": str(report_path.resolve()),
        "report_file": report_filename,
        "metadata": metadata,
    }
