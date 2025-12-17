from __future__ import annotations

from pathlib import Path
from typing import List, Dict, Any

import socket
from ipaddress import ip_network, ip_address, IPv4Network
from datetime import datetime

import psutil
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from engine import run_safehome_scan


# ---------------------------------------------------------
# FastAPI app + templates
# ---------------------------------------------------------

app = FastAPI(title="SafeHome-AI 2.0")

templates = Jinja2Templates(directory="templates")

# Optional: serve /static for future CSS/JS/images
app.mount("/static", StaticFiles(directory="static"), name="static")


# ---------------------------------------------------------
# Models
# ---------------------------------------------------------

class ScanRequest(BaseModel):
    network: str


# ---------------------------------------------------------
# Utility: detect local IPv4 networks
# ---------------------------------------------------------

def _list_local_networks() -> Dict[str, Any]:
    """
    Inspect local interfaces and build a list of candidate IPv4 networks.

    Returns a dict:
    {
        "networks": [ { ... }, ... ],
        "suggested_network": "192.168.56.0/24" | None
    }
    """
    networks: List[Dict[str, Any]] = []

    addrs = psutil.net_if_addrs()

    for iface_name, iface_addrs in addrs.items():
        for addr in iface_addrs:
            if addr.family != socket.AF_INET:
                continue

            ip_str = addr.address
            netmask = addr.netmask

            # Ignore loopback
            if ip_str.startswith("127."):
                continue

            try:
                net = IPv4Network(f"{ip_str}/{netmask}", strict=False)
            except Exception:
                continue

            ip_obj = ip_address(ip_str)
            is_priv = ip_obj.is_private

            name_lower = iface_name.lower()
            is_wifi_guess = "wi-fi" in name_lower or "wifi" in name_lower or "wlan" in name_lower
            is_vm_guess = "vmnet" in name_lower or "virtualbox" in name_lower or "vmware" in name_lower
            is_eth_guess = "ethernet" in name_lower or "eth" in name_lower

            # Build a human-friendly label
            if is_wifi_guess:
                label = "Home / Wi-Fi Network"
            elif is_vm_guess:
                label = "Lab / VM Network"
            elif is_eth_guess:
                label = "LAN / Ethernet Network"
            else:
                label = f"Interface {iface_name}"

            # Rank for sorting: Wi-Fi first, then Ethernet, then VM, then others
            if is_wifi_guess:
                rank = 0
            elif is_eth_guess:
                rank = 1
            elif is_vm_guess:
                rank = 2
            else:
                rank = 3

            networks.append({
                "interface": iface_name,
                "ip": ip_str,
                "network": str(net),
                "is_private": is_priv,
                "is_wifi_guess": is_wifi_guess,
                "is_lab_guess": is_vm_guess,
                "label": label,
                "rank": rank,
            })

    # Sort by rank to make suggestion more sensible
    networks.sort(key=lambda n: n["rank"])

    suggested = networks[0]["network"] if networks else None

    return {
        "networks": networks,
        "suggested_network": suggested,
    }


# ---------------------------------------------------------
# Routes: UI
# ---------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/ui", response_class=HTMLResponse)
def ui(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


# ---------------------------------------------------------
# Routes: API
# ---------------------------------------------------------

@app.get("/api/networks")
def api_networks():
    """
    Detect local IPv4 networks and return them for the dropdown.
    """
    data = _list_local_networks()
    return JSONResponse(content=data)


@app.post("/api/scan")
def api_scan(req: ScanRequest):
    """
    Run the SafeHome-AI scan on the selected network.
    """
    network = req.network.strip()
    if not network:
        raise HTTPException(status_code=400, detail="Network CIDR is required.")

    try:
        result = run_safehome_scan(network)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Scan failed: {exc}") from exc

    return {
        "status": "completed",
        "network": result["network"],
        "device_count": len(result["devices"]),
        "devices": result["devices"],
        "report_path": result.get("report_path"),
        "report_file": result.get("report_file"),
    }


@app.get("/api/reports")
def api_reports():
    """
    List existing HTML reports (for 'Recent scans' UI).
    """
    reports_root = Path("reports") / "html"
    items = []

    if reports_root.exists():
        for p in sorted(
            reports_root.glob("report_*.html"),
            key=lambda x: x.stat().st_mtime,
            reverse=True,
        ):
            ts = datetime.fromtimestamp(p.stat().st_mtime)
            items.append({
                "file": p.name,
                "created_at": ts.isoformat(timespec="seconds"),
                "display_time": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "url": f"/report/html/{p.name}",
            })

    return {"reports": items}


# ---------------------------------------------------------
# Routes: Reports
# ---------------------------------------------------------

@app.get("/report/html", response_class=HTMLResponse)
def report_html():
    """
    Serve the latest HTML report (inline in browser), from reports/html/.
    """
    reports_root = Path("reports") / "html"
    if not reports_root.exists():
        return HTMLResponse("<h3>No report generated yet.</h3>", status_code=200)

    reports = sorted(
        reports_root.glob("report_*.html"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )

    if not reports:
        return HTMLResponse("<h3>No report generated yet.</h3>", status_code=200)

    latest_report = reports[0]
    html = latest_report.read_text(encoding="utf-8")
    return HTMLResponse(content=html, media_type="text/html")


@app.get("/report/html/{filename}", response_class=HTMLResponse)
def report_html_named(filename: str):
    """
    Serve a specific report by filename (used by 'Recent scans' list).
    """
    if "/" in filename or "\\" in filename:
        raise HTTPException(status_code=400, detail="Invalid filename.")

    reports_root = Path("reports") / "html"
    file_path = reports_root / filename

    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Report not found.")

    html = file_path.read_text(encoding="utf-8")
    return HTMLResponse(content=html, media_type="text/html")
