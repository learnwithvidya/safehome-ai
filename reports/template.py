from __future__ import annotations

from pathlib import Path
from typing import List, Dict, Any
from html import escape


def render_report(
    results: List[Dict[str, Any]],
    network: str,
    output_path: Path,
    metadata: Dict[str, Any] | None = None,
) -> None:
    """
    Render a readable, audit-friendly HTML report for SafeHome-AI.
    """
    metadata = metadata or {}

    def m(key: str, default: str = "-") -> str:
        val = metadata.get(key, default)
        return escape(str(val)) if val is not None else "-"

    # Basic fields
    app_name = m("app_name", "SafeHome-AI")
    app_version = m("app_version", "2.0.0")
    report_id = m("report_id")

    scan_started_at = m("scan_started_at")
    scan_finished_at = m("scan_finished_at")
    duration_seconds = escape(str(metadata.get("duration_seconds", "-")))

    network_scanned = m("network_scanned", network)
    device_count = escape(str(metadata.get("device_count", len(results))))

    creator_username = m("creator_username")
    creator_hostname = m("creator_hostname")
    creator_ip = m("creator_ip")

    # Compute risk distribution
    high_count = 0
    med_count = 0
    low_count = 0

    for dev in results:
        risk = dev.get("risk") or {}
        label = str(risk.get("label", "")).lower()
        if label == "high":
            high_count += 1
        elif label == "medium":
            med_count += 1
        elif label == "low":
            low_count += 1

    high_count_str = escape(str(high_count))
    med_count_str = escape(str(med_count))
    low_count_str = escape(str(low_count))

    parts: List[str] = []

    parts.append("""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>SafeHome-AI Network Security Report</title>
  <style>
    body {
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #f3f4f6;
      color: #111827;
      margin: 0;
      padding: 24px;
    }
    h1, h2, h3 {
      margin-top: 0;
    }
    .wrapper {
      max-width: 1000px;
      margin: 0 auto;
    }
    .card {
      background: #ffffff;
      border-radius: 12px;
      padding: 18px 22px;
      margin-bottom: 18px;
      box-shadow: 0 4px 12px rgba(15, 23, 42, 0.06);
      border: 1px solid #e5e7eb;
    }
    .muted {
      color: #6b7280;
      font-size: 0.92rem;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.9rem;
    }
    th, td {
      border-bottom: 1px solid #e5e7eb;
      padding: 8px 10px;
      text-align: left;
    }
    th {
      background: #f9fafb;
      font-weight: 600;
    }
    tr:nth-child(even) td {
      background: #f9fafb;
    }
    .label {
      font-weight: 600;
      color: #4b5563;
      width: 220px;
      padding-right: 16px;
    }
    .value {
      color: #111827;
    }
    .pill {
      display: inline-block;
      padding: 3px 10px;
      border-radius: 999px;
      font-size: 0.8rem;
      font-weight: 600;
    }
    .pill-high {
      background: #fee2e2;
      color: #b91c1c;
    }
    .pill-medium {
      background: #fef3c7;
      color: #92400e;
    }
    .pill-low {
      background: #dcfce7;
      color: #166534;
    }
    .pill-neutral {
      background: #e5e7eb;
      color: #374151;
    }
    ul {
      margin-top: 4px;
      margin-bottom: 8px;
      padding-left: 18px;
    }
    .section-title {
      font-size: 1.05rem;
      font-weight: 600;
      margin-bottom: 6px;
    }
    .section-subtitle {
      font-size: 0.92rem;
      color: #6b7280;
      margin-bottom: 4px;
    }
    .small {
      font-size: 0.8rem;
      color: #6b7280;
    }

    /* Device tiles */
    .device-card {
      border-radius: 10px;
      border: 1px solid #e5e7eb;
      padding: 10px 14px;
      margin-bottom: 10px;
      background: #f9fafb;
    }
    .device-card-high {
      border-left: 4px solid #b91c1c;
    }
    .device-card-medium {
      border-left: 4px solid #d97706;
    }
    .device-card-low {
      border-left: 4px solid #16a34a;
    }
    .device-header {
      font-weight: 600;
      margin-bottom: 4px;
    }
  </style>
</head>
<body>
  <div class="wrapper">
""")

    # Title + executive summary
    overall_level = "Low"
    if high_count > 0:
        overall_level = "High"
    elif med_count > 0:
        overall_level = "Medium"

    overall_pill_class = {
        "High": "pill-high",
        "Medium": "pill-medium",
        "Low": "pill-low"
    }.get(overall_level, "pill-neutral")

    parts.append(f"""
    <div class="card">
      <h1>SafeHome-AI – Network Security Report</h1>
      <p class="muted">
        Application: {app_name} v{app_version} · Report ID: {report_id}
      </p>

      <div class="section-title">Executive summary</div>
      <p>
        This report summarises the results of a security scan on the network
        <strong>{network_scanned}</strong>. A total of <strong>{device_count}</strong>
        devices were detected. Based on exposed services and simple risk rules,
        the overall risk level for this network is
        <span class="pill {overall_pill_class}">{escape(overall_level)} risk</span>.
      </p>
      <p>
        Devices classified as <strong>high risk</strong> should be reviewed first,
        followed by <strong>medium risk</strong> devices. Low-risk devices are
        typically well-behaved or expose only minimal services.
      </p>
    </div>
""")

    # Risk overview
    parts.append(f"""
    <div class="card">
      <h2>1. Risk overview</h2>

      <table style="margin-bottom: 10px;">
        <tr>
          <td class="label">High-risk devices</td>
          <td class="value"><span class="pill pill-high">{high_count_str}</span></td>
        </tr>
        <tr>
          <td class="label">Medium-risk devices</td>
          <td class="value"><span class="pill pill-medium">{med_count_str}</span></td>
        </tr>
        <tr>
          <td class="label">Low-risk devices</td>
          <td class="value"><span class="pill pill-low">{low_count_str}</span></td>
        </tr>
      </table>

      <div class="section-subtitle">How to interpret these levels</div>
      <ul>
        <li><strong>High risk</strong> – Devices exposing sensitive services (for example, remote administration, SMB,
            or web interfaces) that may require immediate review or hardening.</li>
        <li><strong>Medium risk</strong> – Devices exposing common services that should be monitored and restricted to
            trusted users wherever possible.</li>
        <li><strong>Low risk</strong> – Devices with limited exposure or only well-known, low-risk services.</li>
      </ul>
    </div>
""")

    # Device summary table
    parts.append("""
    <div class="card">
      <h2>2. Device summary</h2>
      <p class="muted">
        Summary table of all detected devices with key details.
      </p>
      <table>
        <thead>
          <tr>
            <th>IP address</th>
            <th>Vendor</th>
            <th>Hostname</th>
            <th>Open ports</th>
            <th>Risk</th>
            <th>Score</th>
          </tr>
        </thead>
        <tbody>
""")

    for dev in results:
        ip = escape(str(dev.get("ip", "")))
        vendor = escape(str(dev.get("vendor", "") or ""))
        hostname = escape(str(dev.get("hostname", "") or ""))

        ports = dev.get("open_ports") or []
        ports_str = ", ".join(str(p) for p in ports) if ports else "-"

        risk = dev.get("risk") or {}
        risk_label = str(risk.get("label", "Unknown"))
        risk_score = escape(str(risk.get("score", "-")))

        label_lower = risk_label.lower()
        if label_lower == "high":
            pill_class = "pill pill-high"
        elif label_lower == "medium":
            pill_class = "pill pill-medium"
        elif label_lower == "low":
            pill_class = "pill pill-low"
        else:
            pill_class = "pill pill-neutral"

        parts.append(f"""
          <tr>
            <td>{ip}</td>
            <td>{vendor}</td>
            <td>{hostname}</td>
            <td>{ports_str}</td>
            <td><span class="{pill_class}">{escape(risk_label)}</span></td>
            <td>{risk_score}</td>
          </tr>
""")

    parts.append("""
        </tbody>
      </table>
    </div>
""")

    # Detailed risk notes – now with tiles
    parts.append("""
    <div class="card">
      <h2>3. Detailed risk notes</h2>
      <p class="muted">
        This section explains why each device received its classification and
        which services contributed to the assigned risk level.
      </p>
""")

    if not results:
        parts.append("<p>No devices were detected on this network during the scan.</p>")
    else:
        for dev in results:
            ip = escape(str(dev.get("ip", "")))
            vendor = escape(str(dev.get("vendor", "") or "Unknown vendor"))
            hostname = escape(str(dev.get("hostname", "") or "-"))

            risk = dev.get("risk") or {}
            risk_label = escape(str(risk.get("label", "Unknown")))
            risk_score = escape(str(risk.get("score", "-")))
            reasons = risk.get("reasons") or []

            label_lower = (risk.get("label") or "").lower()
            if label_lower == "high":
                card_class = "device-card device-card-high"
            elif label_lower == "medium":
                card_class = "device-card device-card-medium"
            elif label_lower == "low":
                card_class = "device-card device-card-low"
            else:
                card_class = "device-card"

            parts.append(f"""
      <div class="{card_class}">
        <div class="device-header">Device: {ip}</div>
        <p>
          <strong>Vendor:</strong> {vendor}
          &nbsp; | &nbsp;
          <strong>Hostname:</strong> {hostname}<br>
          <strong>Risk level:</strong> {risk_label}
          &nbsp; | &nbsp;
          <strong>Score:</strong> {risk_score}
        </p>
""")

            if reasons:
                parts.append("<p>Key contributing factors:</p><ul>")
                for r in reasons:
                    parts.append(f"<li>{escape(str(r))}</li>")
                parts.append("</ul>")
            else:
                parts.append("<p><em>No detailed reasons recorded for this device.</em></p>")

            parts.append("</div>")  # close device-card

    parts.append("""
    </div>
""")

    # Appendix – audit information
    parts.append(f"""
    <div class="card">
      <h2>Appendix A – Scan audit information</h2>
      <table>
        <tr><td class="label">Network scanned</td><td class="value">{network_scanned}</td></tr>
        <tr><td class="label">Scan started at</td><td class="value">{scan_started_at}</td></tr>
        <tr><td class="label">Scan finished at</td><td class="value">{scan_finished_at}</td></tr>
        <tr><td class="label">Scan duration (seconds)</td><td class="value">{duration_seconds}</td></tr>
        <tr><td class="label">Devices detected</td><td class="value">{device_count}</td></tr>
        <tr><td class="label">Creator username</td><td class="value">{creator_username}</td></tr>
        <tr><td class="label">Creator hostname</td><td class="value">{creator_hostname}</td></tr>
        <tr><td class="label">Creator IP (within scanned network)</td><td class="value">{creator_ip}</td></tr>
      </table>
      <p class="small">
        This section is intended to support local audit trails, lab documentation
        and internal reviews. Store this report according to your organisation's
        security policy.
      </p>
    </div>

    <div class="card">
      <p class="small">
        Disclaimer: SafeHome-AI is intended for scanning networks that you own or
        administer. Use on third-party networks without permission may violate
        applicable laws or internal policies.
      </p>
    </div>

  </div> <!-- wrapper -->
</body>
</html>
""")

    output_path.write_text("".join(parts), encoding="utf-8")
