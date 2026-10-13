import glob
import re
import os

ext_dir = "/home/tuankhoa/migration/codeql-queries-v2.25.6/java/ql/lib/ext"
files = glob.glob(f"{ext_dir}/**/*.model.yml", recursive=True)
print(f"Total model YAMLs: {len(files)}")

counts = {"source": 0, "sink": 0, "summary": 0, "neutral": 0}
cwe_kind_counts = {}

# Regex to match data rows:
# - ["package", "class", bool, "method", "param_sig", "?", "ext", "kind", "provenance"]
# or for neutral:
# - ["package", "class", "method", "param_sig", "kind", "provenance"]
data_row_re = re.compile(r'^\s*-\s*\[\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,(.*)\]')

for fpath in files:
    current_model = None
    with open(fpath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if "extensible: sourceModel" in line:
                current_model = "source"
            elif "extensible: sinkModel" in line:
                current_model = "sink"
            elif "extensible: summaryModel" in line:
                current_model = "summary"
            elif "extensible: neutralModel" in line:
                current_model = "neutral"
            elif "extensible:" in line:
                current_model = None
            
            if current_model and line.strip().startswith("- ["):
                counts[current_model] += 1
                # extract kind (like sql-injection, path-injection, command-injection)
                parts = line.strip().split(",")
                if len(parts) >= 8 and current_model == "sink":
                    kind = parts[7].strip().strip('"').strip("'")
                    cwe_kind_counts[kind] = cwe_kind_counts.get(kind, 0) + 1

print(f"Total entries by model type: {counts}")
print("Top 20 Sink Kinds:")
for k, v in sorted(cwe_kind_counts.items(), key=lambda x: x[1], reverse=True)[:20]:
    print(f"  {k}: {v}")
