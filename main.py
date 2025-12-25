import argparse
from pathlib import Path

from ingest.qualys_parser import load_qualys_csv
from ingest.nessus_parser import load_nessus_csv
from transform.normalize import normalize_findings
from transform.correlate import correlate_cve_to_cis
from transform.kpi import compute_kpis
from output.report_csv import write_summary_csv
from output.splunk_events import write_splunk_events


def parse_args():
    p = argparse.ArgumentParser(description="VulnTrack 360 – Vulnerability Dashboard Pipeline")
    p.add_argument("--qualys", type=str, required=True, help="Path to Qualys CSV export")
    p.add_argument("--nessus", type=str, required=True, help="Path to Nessus CSV export")
    p.add_argument("--cve-cis-map", type=str, required=True, help="Path to CVE->CIS mapping CSV")
    p.add_argument("--out-dir", type=str, required=True, help="Output directory")
    return p.parse_args()


def main():
    args = parse_args()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    qualys_df = load_qualys_csv(args.qualys)
    nessus_df = load_nessus_csv(args.nessus)

    findings = normalize_findings(qualys_df, nessus_df)  # unified schema
    findings = correlate_cve_to_cis(findings, args.cve_cis_map)

    kpis, summary_df = compute_kpis(findings)

    write_summary_csv(summary_df, out_dir / "summary_report.csv")
    write_splunk_events(findings, kpis, out_dir / "splunk_events.jsonl")
    (out_dir / "kpi.json").write_text(kpis.to_json(indent=2), encoding="utf-8")

    print(f"Done. Outputs written to: {out_dir.resolve()}")


if __name__ == "__main__":
    main()
