import pandas as pd
from src.transform.kpi import compute_kpis

def test_compute_kpis_runs():
    df = pd.DataFrame([
        {"source":"qualys","asset":"a1","ip":"1.1.1.1","finding_title":"x","severity":4,"cve":"CVE-1",
         "first_seen":"2025-10-01","last_seen":"2025-10-10","status":"Open","cis_control":"CIS 7.1","cis_title":"VM"},
        {"source":"nessus","asset":"a2","ip":"2.2.2.2","finding_title":"y","severity":3,"cve":"CVE-2",
         "first_seen":"2025-09-01","last_seen":"2025-09-20","status":"Fixed","cis_control":"CIS 4.8","cis_title":"Config"},
    ])
    df["first_seen"] = pd.to_datetime(df["first_seen"])
    df["last_seen"] = pd.to_datetime(df["last_seen"])
    kpis, summary = compute_kpis(df)
    assert "total_findings" in kpis.index
    assert len(summary) > 0
