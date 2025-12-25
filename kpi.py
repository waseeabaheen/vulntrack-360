import pandas as pd

def compute_kpis(findings: pd.DataFrame):
    df = findings.copy()

    # MTTD: proxy = (last_seen - first_seen) for open findings; for fixed, time between first_seen and last_seen
    df["age_days"] = (df["last_seen"] - df["first_seen"]).dt.total_seconds() / 86400.0
    df["age_days"] = df["age_days"].fillna(0).clip(lower=0)

    # MTTR (only fixed)
    fixed_mask = df["status"].str.lower().isin(["fixed", "closed", "remediated", "resolved"])
    mttr = df.loc[fixed_mask, "age_days"].mean() if fixed_mask.any() else 0.0

    # MTTD (for open findings, treat as detection-to-latest-observed)
    open_mask = ~fixed_mask
    mttd = df.loc[open_mask, "age_days"].mean() if open_mask.any() else 0.0

    # SLA/TTR thresholds by severity (example)
    sla_days = {5: 7, 4: 14, 3: 30, 2: 60, 1: 90}
    df["sla_days"] = df["severity"].map(sla_days).fillna(30)
    df["sla_breached"] = df["age_days"] > df["sla_days"]

    kpis = pd.Series({
        "total_findings": int(len(df)),
        "unique_assets": int(df["asset"].nunique()),
        "unique_cves": int(df["cve"].replace("", pd.NA).dropna().nunique()),
        "mttd_days": round(float(mttd), 2),
        "mttr_days": round(float(mttr), 2),
        "sla_breach_rate": round(float(df["sla_breached"].mean() if len(df) else 0.0), 3),
    })

    # summary report
    top_cves = (df[df["cve"] != ""]
                .groupby("cve")
                .size()
                .sort_values(ascending=False)
                .head(10)
                .reset_index(name="count"))
    top_assets = (df.groupby("asset")
                  .size()
                  .sort_values(ascending=False)
                  .head(10)
                  .reset_index(name="count"))

    summary = {
        "kpis": kpis,
        "top_cves": top_cves,
        "top_assets": top_assets,
        "by_severity": df.groupby("severity").size().reset_index(name="count").sort_values("severity", ascending=False),
        "sla_breaches": df[df["sla_breached"]].groupby("severity").size().reset_index(name="breaches"),
    }

    # Flatten summary into a single CSV-friendly table
    rows = []
    for k, v in kpis.items():
        rows.append({"section": "kpi", "name": k, "value": v})
    for _, r in top_cves.iterrows():
        rows.append({"section": "top_cve", "name": r["cve"], "value": int(r["count"])})
    for _, r in top_assets.iterrows():
        rows.append({"section": "top_asset", "name": r["asset"], "value": int(r["count"])})
    summary_df = pd.DataFrame(rows)

    return kpis, summary_df
