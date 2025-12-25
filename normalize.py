import pandas as pd

def _split_cves(cves: str) -> list[str]:
    if pd.isna(cves) or not str(cves).strip():
        return []
    s = str(cves)
    # support separators ; , space
    for sep in [";", ",", " "]:
        s = s.replace(sep, ";")
    items = [x.strip() for x in s.split(";") if x.strip()]
    # basic de-dupe while preserving order
    seen, out = set(), []
    for x in items:
        if x not in seen:
            out.append(x); seen.add(x)
    return out

def normalize_findings(qualys_df: pd.DataFrame, nessus_df: pd.DataFrame) -> pd.DataFrame:
    q = qualys_df.copy()
    q = q.rename(columns={
        "asset": "asset",
        "title": "finding_title",
        "first_detected": "first_seen",
        "last_detected": "last_seen",
        "status": "status",
    })
    q["source"] = "qualys"
    q["cve_list"] = q["cves"].apply(_split_cves)

    n = nessus_df.copy()
    n = n.rename(columns={
        "host": "asset",
        "plugin_name": "finding_title",
        "first_found": "first_seen",
        "last_found": "last_seen",
        "state": "status",
    })
    n["source"] = "nessus"
    n["cve_list"] = n["cves"].apply(_split_cves)

    # unify columns
    cols = ["source", "asset", "ip", "finding_title", "severity", "cve_list", "first_seen", "last_seen", "status"]
    out = pd.concat([q[cols], n[cols]], ignore_index=True)
    out["first_seen"] = pd.to_datetime(out["first_seen"], errors="coerce")
    out["last_seen"] = pd.to_datetime(out["last_seen"], errors="coerce")
    out["status"] = out["status"].fillna("Open")
    return out
