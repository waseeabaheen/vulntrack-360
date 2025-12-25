import pandas as pd

def load_qualys_csv(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    # expected columns: asset, ip, title, cves, severity, first_detected, last_detected, status
    return df
