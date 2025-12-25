import pandas as pd

def write_summary_csv(summary_df: pd.DataFrame, out_path):
    summary_df.to_csv(out_path, index=False)
