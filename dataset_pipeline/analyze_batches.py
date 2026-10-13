import glob
import pandas as pd

batches = glob.glob("/home/tuankhoa/migration/fine_tuning_dataset_audit_v2_20261001/21_stage3_group_reviews/batch*.review.*tsv")
print(f"Total review TSVs: {len(batches)}")

total_rows = 0
all_labels = {}

for b in sorted(batches):
    if "POSTREVIEW" not in b and "AFTER" not in b:
        # Check standard review TSV
        try:
            df = pd.read_csv(b, sep="\t")
            label_col = [c for c in df.columns if "label" in c.lower() or "type" in c.lower() or "verdict" in c.lower()]
            print(f"{b.split('/')[-1]}: {df.shape}, cols with label={label_col}")
            if label_col:
                col = label_col[0]
                counts = df[col].value_counts().to_dict()
                print(f"   counts: {counts}")
                for k, v in counts.items():
                    all_labels[k] = all_labels.get(k, 0) + v
            total_rows += len(df)
        except Exception as e:
            print(f"Error reading {b}: {e}")

print(f"\nTotal rows in primary batches: {total_rows}")
print(f"All label counts: {all_labels}")
