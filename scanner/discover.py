# filename: scanner/discover.py

from typing import List
from rich.console import Console

from .utils import Device

console = Console()

try:
    import nmap  # type: ignore
    from nmap.nmap import PortScannerError
except ImportError:
    nmap = None
    PortScannerError = Exception  # fallback


def discover_devices(network_cidr: str) -> List[Device]:
    """
    Discover active hosts in the given network range using Nmap ping scan (-sn).

    This is more reliable on Windows than raw-ARP via scapy, especially with
    multiple adapters (Wi-Fi, host-only, etc.).
    """
    devices: List[Device] = []

    if nmap is None:
        console.print(
            "[!] python-nmap / Nmap binary not available. "
            "Discovery is disabled.",
            style="bold red",
        )
        return devices

    console.print(
        f"[+] Performing Nmap host discovery on {network_cidr}",
        style="bold green",
    )

    scanner = nmap.PortScanner()

    try:
        # -sn = ping scan (no port scan), good for host discovery
        scanner.scan(hosts=network_cidr, arguments="-sn")
    except PortScannerError as e:
        console.print(f"[!] Nmap discovery error: {e}", style="bold red")
        return devices
    except Exception as e:
        console.print(f"[!] Unexpected error during discovery: {e}", style="bold red")
        return devices

    for host in scanner.all_hosts():
        if scanner[host].state() != "up":
            continue

        addresses = scanner[host].get("addresses", {})
        mac = addresses.get("mac")
        vendor = None
        if mac:
            vendor = scanner[host].get("vendor", {}).get(mac.upper())

        devices.append(
            Device(
                ip=host,
                mac=mac,
                vendor=vendor,
                hostname=None,  # can add reverse DNS later
            )
        )

    console.print(f"[+] {len(devices)} device(s) discovered.")
    return devices
