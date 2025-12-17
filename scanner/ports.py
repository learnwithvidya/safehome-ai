# filename: scanner/ports.py

from typing import List
from rich.console import Console

console = Console()

try:
    import nmap  # type: ignore
except ImportError:
    nmap = None


COMMON_PORTS = "21,22,23,80,443,445,554,8000,8080,8883,1883"


def scan_device_ports(ip: str) -> List[int]:
    """
    Scan common ports on a device using python-nmap.
    Returns a list of open port numbers.
    """
    if nmap is None:
        console.print("[!] python-nmap not available. Port scanning not implemented yet.", style="bold red")
        return []

    nm = nmap.PortScanner()

    try:
        nm.scan(ip, COMMON_PORTS, arguments="-sS -T4")
    except Exception as e:
        console.print(f"[!] Error scanning {ip}: {e}", style="bold red")
        return []

    open_ports: List[int] = []

    # nm[ip]['tcp'] gives a dict {portnum: {...}}
    if ip in nm.all_hosts():
        tcp_info = nm[ip].get("tcp", {})
        for port, state_data in tcp_info.items():
            if state_data.get("state") == "open":
                open_ports.append(int(port))

    open_ports.sort()
    return open_ports
