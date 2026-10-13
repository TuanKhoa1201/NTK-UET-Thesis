import pandas as pd
import json
import os
import glob

def check_csv(path, name):
    if not os.path.exists(path):
        print(f"[-] {name} does not exist at {path}")
        return
    try:
        df = pd.read_csv(path)
        print(f"[+] {name}: Shape = {df.shape}")
        print(f"    Columns: {list(df.columns)}")
        if "cwe_id" in df.columns or "cwe" in df.columns:
            col = "cwe_id" if "cwe_id" in df.columns else "cwe"
            print(f"    CWEs: {df[col].value_counts().to_dict()}")
    except Exception as e:
        print(f"[-] Error reading {name}: {e}")

print("=== 1. Checking Curated Datasets in data/ ===")
check_csv("/home/tuankhoa/iris/data/fix_info_source_sink.csv", "fix_info_source_sink")
check_csv("/home/tuankhoa/iris/data/source_sink_detect.csv", "source_sink_detect")
check_csv("/home/tuankhoa/iris/data/project_info.csv", "project_info")
check_csv("/home/tuankhoa/iris/data/fix_info.csv", "fix_info")
check_csv("/home/tuankhoa/iris/data/project-sources/owasp_benchmark_CVE-2026-0005_1.0/expectedresults-1.2.csv", "owasp_expected_results")

print("\n=== 2. Checking specs.model.yml in output/ ===")
specs_files = glob.glob("/home/tuankhoa/iris/output/**/specs.model.yml", recursive=True)
print(f"[+] Found {len(specs_files)} specs.model.yml files")
for sf in specs_files[:10]:
    print("   ", sf)

print("\n=== 3. Checking existing manual review batches in migration/ ===")
batches = glob.glob("/home/tuankhoa/migration/fine_tuning_dataset_audit_v2_20261001/21_stage3_group_reviews/batch*.tsv")
print(f"[+] Found {len(batches)} batch TSV files")
