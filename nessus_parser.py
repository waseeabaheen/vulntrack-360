import pandas as pd

_RISK_TO_SEV = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}

def load_nessus_csv(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    # expected columns: host, ip, plugin_name, cves, risk, first_found, last_found, state
    df["severity"] = df["risk"].map(_RISK_TO_SEV).fillna(0).astype(int)
    return df
