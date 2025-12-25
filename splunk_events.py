import json
from datetime import datetime
import pandas as pd

def write_splunk_events(findings: pd.DataFrame, kpis: pd.Series, out_path):
    # Splunk HEC expects {"event": {...}} format; one JSON object per line
    now = datetime.utcnow().isoformat() + "Z"
    with open(out_path, "w", encoding="utf-8") as f:
        # KPI event
        f.write(json.dumps({"time": now, "event": {"type": "vuln_kpi", **kpis.to_dict()}}) + "\n")

        # Finding events
        for _, r in findings.iterrows():
            event = {
                "type": "vuln_finding",
                "source": r.get("source", ""),
                "asset": r.get("asset", ""),
                "ip": r.get("ip", ""),
                "cve": r.get("cve", ""),
                "severity": int(r.get("severity", 0)) if pd.notna(r.get("severity", None)) else 0,
                "status": r.get("status", ""),
                "cis_control": r.get("cis_control", ""),
                "cis_title": r.get("cis_title", ""),
                "first_seen": str(r.get("first_seen", "")),
                "last_seen": str(r.get("last_seen", "")),
                "finding_title": r.get("finding_title", ""),
            }
            f.write(json.dumps({"time": now, "event": event}) + "\n")
