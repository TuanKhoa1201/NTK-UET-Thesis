import json
import os
import sys

DATASET_DIR = "/home/tuankhoa/migration/dataset_v3_augmented_20261012"

splits = ["train.jsonl", "validation.jsonl", "test.jsonl"]
split_classes = {}

total_checked = 0
errors = []

for split_file in splits:
    fpath = os.path.join(DATASET_DIR, split_file)
    split_classes[split_file] = set()
    with open(fpath, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            total_checked += 1
            try:
                row = json.loads(line)
            except Exception as e:
                errors.append(f"[{split_file}:{line_num}] JSON parse error: {e}")
                continue
            
            messages = row.get("messages", [])
            if len(messages) != 3:
                errors.append(f"[{split_file}:{line_num}] Invalid message count: {len(messages)}")
                continue
            
            if messages[0].get("role") != "system" or not messages[0].get("content"):
                errors.append(f"[{split_file}:{line_num}] Invalid system message")
            if messages[1].get("role") != "user" or not messages[1].get("content"):
                errors.append(f"[{split_file}:{line_num}] Invalid user message")
            if "{methods}" in messages[1].get("content", "") or "{cwe_id}" in messages[1].get("content", ""):
                errors.append(f"[{split_file}:{line_num}] Unformatted placeholders in user prompt")
            
            asst = messages[2]
            if asst.get("role") != "assistant" or not asst.get("content"):
                errors.append(f"[{split_file}:{line_num}] Invalid assistant message")
                continue
            
            try:
                asst_obj = json.loads(asst["content"])
            except Exception as e:
                errors.append(f"[{split_file}:{line_num}] Assistant content is not valid JSON: {e}")
                continue
            
            pkg = asst_obj.get("package")
            cls = asst_obj.get("class")
            meth = asst_obj.get("method")
            sig = asst_obj.get("signature")
            t = asst_obj.get("type")
            s_args = asst_obj.get("sink_args", [])
            
            if not pkg or not cls or not meth or not sig:
                errors.append(f"[{split_file}:{line_num}] Empty fields in assistant obj")
            
            if t not in {"source", "sink", "taint-propagator", "none"}:
                errors.append(f"[{split_file}:{line_num}] Invalid type: {t}")
            
            if t == "sink" and not s_args:
                errors.append(f"[{split_file}:{line_num}] Sink without sink_args")
            if t != "sink" and s_args:
                errors.append(f"[{split_file}:{line_num}] Non-sink has non-empty sink_args: {s_args}")
                
            split_classes[split_file].add((pkg, cls))

print(f"[+] Total checked samples: {total_checked}")
print(f"[+] Total validation errors: {len(errors)}")
if errors:
    for e in errors[:10]:
        print("  [-]", e)
else:
    print("[✓] ALL SAMPLES STRICTLY PASS JSON & SCHEMA VALIDATION!")

# Check leakage
train_cls = split_classes["train.jsonl"]
val_cls = split_classes["validation.jsonl"]
test_cls = split_classes["test.jsonl"]

leakage_train_val = train_cls.intersection(val_cls)
leakage_train_test = train_cls.intersection(test_cls)
leakage_val_test = val_cls.intersection(test_cls)

print(f"[+] Leakage Check:")
print(f"    Train & Val overlap:  {len(leakage_train_val)} (Expected: 0)")
print(f"    Train & Test overlap: {len(leakage_train_test)} (Expected: 0)")
print(f"    Val & Test overlap:   {len(leakage_val_test)} (Expected: 0)")

if len(leakage_train_val) == 0 and len(leakage_train_test) == 0 and len(leakage_val_test) == 0:
    print("[✓] 100% ZERO-LEAKAGE VERIFIED! NO SHARED CLASSES ACROSS SPLITS!")
else:
    print("[-] WARNING: Cross-split leakage detected!")
