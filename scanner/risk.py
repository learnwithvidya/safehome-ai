# filename: scanner/risk.py

from typing import List, Dict


HIGH_RISK_PORTS = {21, 23, 445, 554, 8000, 8080, 1883}
MEDIUM_RISK_PORTS = {22, 80, 5355, 8883}


def assess_device_risk(ports: List[int], vendor: str | None = None) -> Dict[str, object]:
    """
    Very simple rule-based risk scoring for MVP.

    Returns:
        {
          "label": "Low" | "Medium" | "High",
          "reasons": [ ... ]
        }
    """
    reasons: List[str] = []

    if not ports:
        return {"label": "Low", "reasons": ["No common ports detected as open."]}

    high_hits = HIGH_RISK_PORTS.intersection(ports)
    medium_hits = MEDIUM_RISK_PORTS.intersection(ports)

    if high_hits:
        reasons.append(f"High-risk ports open: {sorted(list(high_hits))}")
    if medium_hits:
        reasons.append(f"Medium-risk ports open: {sorted(list(medium_hits))}")

    if len(ports) > 8:
        reasons.append(f"Many open ports detected ({len(ports)}).")

    if vendor is None:
        reasons.append("Vendor unknown; could be unmanaged or unlabelled device.")

    # Decide label
    if high_hits or len(ports) > 8:
        label = "High"
    elif medium_hits or len(ports) > 3:
        label = "Medium"
    else:
        label = "Low"

    return {"label": label, "reasons": reasons}
