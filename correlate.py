import pandas as pd

def correlate_cve_to_cis(findings: pd.DataFrame, mapping_csv_path: str) -> pd.DataFrame:
    m = pd.read_csv(mapping_csv_path)
    m["cve"] = m["cve"].astype(str).str.strip()

    # explode CVEs
    f = findings.copy()
    f = f.explode("cve_list")
    f["cve"] = f["cve_list"].fillna("").astype(str).str.strip()

    merged = f.merge(m, how="left", left_on="cve", right_on="cve")
    merged["cis_control"] = merged["cis_control"].fillna("Unmapped")
    merged["cis_title"] = merged["cis_title"].fillna("Unmapped")
    return merged.drop(columns=["cve_list"])
