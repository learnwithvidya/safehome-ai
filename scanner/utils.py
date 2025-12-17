# filename: scanner/utils.py

from dataclasses import dataclass
from typing import Optional, List
from pathlib import Path

from rich.console import Console
from rich.table import Table

console = Console()


@dataclass
class Device:
    ip: str
    mac: Optional[str] = None
    vendor: Optional[str] = None
    hostname: Optional[str] = None


def print_banner():
    banner = r"""
   ____        __        __             
  / __/__  ___/ /__ ___ / /  ___  ____ _
 _\ \/ _ \/ _  / -_|_-</ _ \/ _ \/ __ `/
/___/\___/\_,_/\__/___/_//_/\___/\__, / 
                                /___/  
    SafeHome-AI v0.1 – Home & Lab IoT Scanner
"""
    console.print(banner, style="bold blue")


def print_summary_table(results: List[dict]):
    table = Table(title="SafeHome-AI Scan Summary")

    table.add_column("IP", style="cyan", no_wrap=True)
    table.add_column("MAC")
    table.add_column("Vendor")
    table.add_column("Open Ports")
    table.add_column("Risk", style="bold")

    for r in results:
        ports_str = ", ".join(str(p) for p in r["open_ports"]) if r["open_ports"] else "-"
        risk_label = r["risk"]["label"]
        if risk_label == "High":
            risk_style = "[bold red]High[/]"
        elif risk_label == "Medium":
            risk_style = "[bold yellow]Medium[/]"
        else:
            risk_style = "[bold green]Low[/]"

        table.add_row(
            r["ip"],
            r.get("mac") or "-",
            r.get("vendor") or "-",
            ports_str,
            risk_style,
        )

    console.print(table)


def ensure_output_dir():
    Path("output").mkdir(exist_ok=True)
