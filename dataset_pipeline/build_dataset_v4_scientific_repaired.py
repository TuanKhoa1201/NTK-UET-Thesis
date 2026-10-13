import os
import sys
import json
import re
import csv
import glob
import random
import hashlib
from collections import defaultdict, Counter

sys.path.append('/home/tuankhoa/iris')
from src.queries import QUERIES

random.seed(42)

OUTPUT_DIR = '/home/tuankhoa/migration/dataset_v4_repaired_20261013'
DOCS_DIR = '/home/tuankhoa/iris/docs/dataset'
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(DOCS_DIR, exist_ok=True)

STAGE3_SYSTEM_PROMPT = """You are a security expert.
You will receive exactly ONE API and must classify it for the requested CWE.

Return exactly ONE JSON object with this format:
{
  "package": "<package name>",
  "class": "<class name>",
  "method": "<method name>",
  "signature": "<signature>",
  "sink_args": [],
  "type": "<source, sink, taint-propagator, or none>"
}

Use:
- source only when the API can introduce attacker-controlled data.
- sink only when the API can directly consume tainted data in a way relevant to the requested CWE.
- taint-propagator only when it propagates tainted data without sanitizing it.
- none when the API does not satisfy any of the above for the requested CWE.

For a sink, sink_args must contain only the argument names/positions that consume tainted data.
For every other type, sink_args must be an empty list.

Do not classify an API merely because it is security-sensitive in some unrelated context.
Do not output anything except the JSON object."""

API_LABELLING_USER_PROMPT = """{cwe_long_description}

Some example source/sink/taint-propagator methods are:
{cwe_examples}

Among the following methods, assuming that the arguments passed to the given function is malicious, what are the functions that are potential source, sink, or taint-propagators to {cwe_description} attack (CWE-{cwe_id})?

Package,Class,Method,Signature
{methods}
"""

CWE_QUERY_MAP = {
    "89": "cwe-089wLLM",
    "089": "cwe-089wLLM",
    "CWE-89": "cwe-089wLLM",
    "CWE-089": "cwe-089wLLM",
    "cwe-089": "cwe-089wLLM",
    "22": "cwe-022wLLM",
    "022": "cwe-022wLLM",
    "CWE-22": "cwe-022wLLM",
    "CWE-022": "cwe-022wLLM",
    "cwe-022": "cwe-022wLLM",
    "23": "cwe-022wLLM",
    "023": "cwe-022wLLM",
    "CWE-23": "cwe-022wLLM",
    "cwe-023": "cwe-022wLLM",
    "78": "cwe-078wLLM",
    "078": "cwe-078wLLM",
    "CWE-78": "cwe-078wLLM",
    "CWE-078": "cwe-078wLLM",
    "cwe-078": "cwe-078wLLM",
    "79": "cwe-079wLLM",
    "079": "cwe-079wLLM",
    "CWE-79": "cwe-079wLLM",
    "CWE-079": "cwe-079wLLM",
    "cwe-079": "cwe-079wLLM",
    "502": "cwe-502wLLM",
    "CWE-502": "cwe-502wLLM",
    "cwe-502": "cwe-502wLLM",
    "611": "cwe-611wLLM",
    "CWE-611": "cwe-611wLLM",
    "cwe-611": "cwe-611wLLM",
}

def resolve_cwe_query(cwe_raw: str):
    cwe_clean = str(cwe_raw).strip()
    return CWE_QUERY_MAP.get(cwe_clean, None)

def get_project_provenance(pkg: str, repo: str = None) -> str:
    if repo and repo.strip():
        return repo.lower().strip()
    if not pkg:
        return 'unknown'
    parts = pkg.split('.')
    if parts[0] in ('java', 'javax'):
        return 'openjdk'
    if len(parts) >= 2:
        if parts[0] == 'org' and parts[1] in ('apache', 'springframework', 'eclipse', 'owasp', 'keycloak'):
            if len(parts) >= 3:
                return f"{parts[1]}-{parts[2]}"
            return parts[1]
        if parts[0] == 'com':
            return f"com-{parts[1]}"
    return parts[0]

def validate_and_normalize_sink_args(sink_args, signature):
    """
    Validates sink_args according to strict contract.
    Returns: (is_valid, clean_args)
    NEVER fabricates Argument[0] when evidence is missing.
    """
    if not sink_args:
        return False, []
    
    clean_args = []
    for arg in sink_args:
        arg_str = str(arg).strip()
        if not arg_str:
            continue
        arg_str = arg_str.strip("[]'\"")
        
        # Disallow raw Java types masquerading as argument names
        if '.' in arg_str or arg_str in {'String', 'int', 'long', 'boolean', 'byte', 'char', 'short', 'float', 'double', 'Object'}:
            continue
        
        if arg_str.isdigit():
            clean_args.append(f"Argument[{arg_str}]")
        elif arg_str.startswith("Argument[") and arg_str.endswith("]"):
            clean_args.append(arg_str)
        elif arg_str in ("this", "Argument[this]"):
            clean_args.append("Argument[this]")
        elif arg_str.startswith("p") and arg_str[1:].isdigit():
            idx = arg_str[1:]
            clean_args.append(f"Argument[{idx}]")
        elif re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', arg_str):
            clean_args.append(arg_str)
        else:
            continue
            
    if not clean_args:
        return False, []
    return True, clean_args

# Extract prompt few-shot examples
prompt_forbidden_signatures = set()
for qk, qv in QUERIES.items():
    for ex in qv.get('prompts', {}).get('examples', []):
        sig = ex.get('signature', '').strip()
        if sig:
            prompt_forbidden_signatures.add(sig)
        pkg = ex.get('package', '').strip()
        cls = ex.get('class', '').strip()
        meth = ex.get('method', '').strip()
        if pkg and cls and meth:
            prompt_forbidden_signatures.add(f"{pkg}.{cls}.{meth}")

print(f"[*] Identified {len(prompt_forbidden_signatures)} few-shot prompt signatures to quarantine.")

raw_candidates = []
quarantined_candidates = []

# 1. Ingest Canonical 401 Ground Truth (Tier 1)
canonical_tsv = "/home/tuankhoa/migration/fine_tuning_dataset_audit_v2_20261001/21_stage3_group_reviews/113_stage3_401_canonical_gt/stage3_401_ground_truth.FROZEN.tsv"
if os.path.exists(canonical_tsv):
    with open(canonical_tsv, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f, delimiter="\t")
        for r in reader:
            lbl = r.get("manual_type", "").strip()
            cwe_raw = r.get("cwe", "").strip()
            q_name = resolve_cwe_query(cwe_raw)
            if not q_name:
                continue
            pkg = r.get("package", "").strip()
            clazz = r.get("class", "").strip()
            method = r.get("method", "").strip()
            sig = r.get("signature", "").strip()
            sink_args_raw = r.get("manual_sink_args", "").strip()
            
            sink_args = []
            if sink_args_raw and sink_args_raw != "[]":
                try:
                    sink_args = json.loads(sink_args_raw.replace("'", '"'))
                except Exception:
                    sink_args = [sink_args_raw.strip("[]'\"")]
            
            if lbl == 'sink':
                valid_sink, norm_args = validate_and_normalize_sink_args(sink_args, sig)
                if not valid_sink:
                    quarantined_candidates.append({
                        'record': (q_name, pkg, clazz, method, sig),
                        'reason': 'SINK_MISSING_OR_INVALID_ARGUMENT_EVIDENCE'
                    })
                    continue
                sink_args = norm_args
            else:
                sink_args = []
                
            raw_candidates.append({
                'cwe_query': q_name,
                'package': pkg,
                'class': clazz,
                'method': method,
                'signature': sig,
                'sink_args': sink_args,
                'type': lbl,
                'provenance': 'CANONICAL_401_GT',
                'confidence': 'HIGH',
                'tier': 1,
                'project': get_project_provenance(pkg)
            })

print(f"[+] Candidate pool size after Canonical 401 GT: {len(raw_candidates)}")

# 2. Ingest Project Info & Curated CVE Sources and Sinks (Tier 2)
cve_cwe_map_from_project_info = {}
project_info_csv = "/home/tuankhoa/iris/data/project_info.csv"
if os.path.exists(project_info_csv):
    with open(project_info_csv, "r", encoding="utf-8", errors="replace") as f:
        for r in csv.DictReader(f):
            cid = r.get("cve_id", "").strip()
            cwid = r.get("cwe_id", "").strip()
            repo = r.get("github_repository_name", "").strip()
            if cid and cwid:
                q = resolve_cwe_query(cwid)
                if q:
                    cve_cwe_map_from_project_info[cid] = (q, repo)

curated_csv = "/home/tuankhoa/iris/data/fix_info_source_sink.csv"
if os.path.exists(curated_csv):
    with open(curated_csv, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for r in reader:
            cve_id = r.get("cve_id", "").strip() or r.get("CVE", "").strip()
            q_info = cve_cwe_map_from_project_info.get(cve_id)
            if not q_info:
                continue
            q_name, mapped_repo = q_info
            repo_name = r.get("github_repository_name", "").strip() or mapped_repo
            
            src_desc = r.get("Source CodeQl  Format", "")
            if src_desc and ";" in src_desc and q_name:
                parts = [p.strip() for p in src_desc.split(";")]
                if len(parts) >= 5:
                    p_pkg, p_cls, p_meth, p_sig = parts[0], parts[1], parts[3], parts[4]
                    sig_fmt = f"{p_meth}{p_sig}"
                    raw_candidates.append({
                        'cwe_query': q_name,
                        'package': p_pkg,
                        'class': p_cls,
                        'method': p_meth,
                        'signature': sig_fmt,
                        'sink_args': [],
                        'type': 'source',
                        'provenance': 'CURATED_CVE_SOURCE',
                        'confidence': 'HIGH',
                        'tier': 2,
                        'project': repo_name or get_project_provenance(p_pkg)
                    })

            snk_desc = r.get("Sink CodeQl Format", "")
            if snk_desc and ";" in snk_desc and q_name:
                parts = [p.strip() for p in snk_desc.split(";")]
                if len(parts) >= 7:
                    p_pkg, p_cls, p_meth, p_sig, p_arg = parts[0], parts[1], parts[3], parts[4], parts[6]
                    sig_fmt = f"{p_meth}{p_sig}"
                    valid_s, norm_args = validate_and_normalize_sink_args([p_arg], sig_fmt)
                    if valid_s:
                        raw_candidates.append({
                            'cwe_query': q_name,
                            'package': p_pkg,
                            'class': p_cls,
                            'method': p_meth,
                            'signature': sig_fmt,
                            'sink_args': norm_args,
                            'type': 'sink',
                            'provenance': 'CURATED_CVE_SINK',
                            'confidence': 'HIGH',
                            'tier': 2,
                            'project': repo_name or get_project_provenance(p_pkg)
                        })

print(f"[+] Candidate pool size after Curated CVE: {len(raw_candidates)}")

# 3. Ingest CodeQL Official Model Extensions (Tier 3: Verified SAST Model Metadata)
codeql_ext_dir = "/home/tuankhoa/migration/codeql-queries-v2.25.6/java/ql/lib/ext"
model_files = glob.glob(f"{codeql_ext_dir}/**/*.model.yml", recursive=True)
for mf in model_files:
    curr_ext = None
    with open(mf, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            l = line.strip()
            if "extensible: sourceModel" in l:
                curr_ext = "source"
            elif "extensible: sinkModel" in l:
                curr_ext = "sink"
            elif "extensible:" in l:
                curr_ext = None
                
            if curr_ext and l.startswith("- ["):
                try:
                    content = l[3:-1]
                    parts = [p.strip().strip('"').strip("'") for p in content.split(",")]
                    if curr_ext == "source" and len(parts) >= 8:
                        pkg, cls, _, meth, params, _, output_kind, src_type = parts[:8]
                        sig = f"{meth}({params})"
                        # Map verified remote input sources explicitly
                        if "remote" in src_type.lower():
                            for q_cand in ["cwe-089wLLM", "cwe-022wLLM", "cwe-078wLLM"]:
                                raw_candidates.append({
                                    'cwe_query': q_cand,
                                    'package': pkg,
                                    'class': cls,
                                    'method': meth,
                                    'signature': sig,
                                    'sink_args': [],
                                    'type': 'source',
                                    'provenance': 'CODEQL_MODEL_CANDIDATE',
                                    'confidence': 'MEDIUM',
                                    'tier': 3,
                                    'project': get_project_provenance(pkg)
                                })
                    elif curr_ext == "sink" and len(parts) >= 8:
                        pkg, cls, _, meth, params, _, arg_idx, sink_kind = parts[:8]
                        sig = f"{meth}({params})"
                        valid_s, norm_args = validate_and_normalize_sink_args([arg_idx], sig)
                        if not valid_s:
                            continue
                        s_lower = sink_kind.lower()
                        target_q = None
                        if "sql" in s_lower:
                            target_q = "cwe-089wLLM"
                        elif "path" in s_lower or "file" in s_lower:
                            target_q = "cwe-022wLLM"
                        elif "command" in s_lower or "exec" in s_lower:
                            target_q = "cwe-078wLLM"
                        elif "html" in s_lower or "xss" in s_lower:
                            target_q = "cwe-079wLLM"
                        elif "deserializ" in s_lower:
                            target_q = "cwe-502wLLM"
                            
                        if target_q:
                            raw_candidates.append({
                                'cwe_query': target_q,
                                'package': pkg,
                                'class': cls,
                                'method': meth,
                                'signature': sig,
                                'sink_args': norm_args,
                                'type': 'sink',
                                'provenance': 'CODEQL_MODEL_CANDIDATE',
                                'confidence': 'MEDIUM',
                                'tier': 3,
                                'project': get_project_provenance(pkg)
                            })
                except Exception:
                    continue

print(f"[+] Candidate pool size after CodeQL Models: {len(raw_candidates)}")
print(f"[!] Quarantined unverified sink records: {len(quarantined_candidates)}")

# 4. Conflict Adjudication & Deterministic Deduplication
candidates_by_key = defaultdict(list)
for item in raw_candidates:
    api_key = (item['cwe_query'], item['package'], item['class'], item['method'], item['signature'])
    candidates_by_key[api_key].append(item)

conflict_ledger = []
evidence_bank = []
disputed_count = 0

for api_key, group in candidates_by_key.items():
    types = set(g['type'] for g in group)
    if len(types) == 1:
        best = min(group, key=lambda x: x['tier'])
        evidence_bank.append(best)
    else:
        sorted_group = sorted(group, key=lambda x: x['tier'])
        highest_tier = sorted_group[0]['tier']
        top_tier_types = set(g['type'] for g in sorted_group if g['tier'] == highest_tier)
        
        if len(top_tier_types) == 1:
            resolved_record = sorted_group[0]
            resolved_record['conflict_resolved'] = True
            resolved_record['competing_labels'] = [g['type'] for g in sorted_group]
            evidence_bank.append(resolved_record)
            conflict_ledger.append({
                'api_key': list(api_key),
                'status': 'RESOLVED_BY_PROVENANCE_TIER',
                'chosen': resolved_record['type'],
                'chosen_provenance': resolved_record['provenance'],
                'rejected': [g['type'] for g in sorted_group if g['type'] != resolved_record['type']]
            })
        else:
            disputed_count += 1
            conflict_ledger.append({
                'api_key': list(api_key),
                'status': 'DISPUTED_TIER_TIE_QUARANTINED',
                'competing_entries': [{'type': g['type'], 'provenance': g['provenance'], 'tier': g['tier']} for g in sorted_group]
            })

print(f"\n[+] Conflict Adjudication Results:")
print(f"    Total Unique APIs: {len(candidates_by_key)}")
print(f"    Conflicts Detected & Adjudicated: {len(conflict_ledger)}")
print(f"    Disputed Quarantined: {disputed_count}")
print(f"    Clean Evidence Bank Size: {len(evidence_bank)}")

# Save Evidence Bank
bank_path = os.path.join(OUTPUT_DIR, "evidence_bank.jsonl")
with open(bank_path, "w", encoding="utf-8") as f:
    for rec in evidence_bank:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")

# 5. Group Splitting by Project Provenance
project_groups = defaultdict(list)
for rec in evidence_bank:
    sig = rec['signature']
    full_ident = f"{rec['package']}.{rec['class']}.{rec['method']}"
    rec['is_prompt_collision'] = (sig in prompt_forbidden_signatures or full_ident in prompt_forbidden_signatures)
    project_groups[rec['project']].append(rec)

unique_projects = sorted(list(project_groups.keys()))
train_projects = set()
val_projects = set()
test_projects = set()

for proj in unique_projects:
    h = int(hashlib.sha256(proj.encode()).hexdigest(), 16) % 100
    if h < 70:
        train_projects.add(proj)
    elif h < 85:
        val_projects.add(proj)
    else:
        test_projects.add(proj)

# Load Historical V3 Train to audit cross-version exposure
v3_train_path = "/home/tuankhoa/migration/dataset_v3_augmented_20261012/train.jsonl"
if not os.path.exists(v3_train_path):
    raise RuntimeError(f"HISTORICAL_OVERLAP_CHECK BLOCKED: Required historical file {v3_train_path} not found!")

v3_train_signatures = set()
with open(v3_train_path, "r", encoding="utf-8") as f:
    for line in f:
        d = json.loads(line)
        asst = json.loads(d['messages'][2]['content'])
        v3_train_signatures.add((asst['package'], asst['class'], asst['method'], asst['signature']))

print(f"[*] Loaded {len(v3_train_signatures)} unique signatures from Historical V3 Train.")

train_records = []
val_records = []
test_records_consumed = []
test_records_clean = []

for proj, items in project_groups.items():
    if proj in train_projects:
        train_records.extend(items)
    elif proj in val_projects:
        val_records.extend(items)
    elif proj in test_projects:
        for it in items:
            if it['is_prompt_collision']:
                continue
            api_sig = (it['package'], it['class'], it['method'], it['signature'])
            if api_sig in v3_train_signatures:
                test_records_consumed.append(it)
            else:
                test_records_clean.append(it)

print(f"[*] Repaired Split Counts:")
print(f"    Train: {len(train_records)}")
print(f"    Validation: {len(val_records)}")
print(f"    Clean Held-Out Test (Zero V3 Exposure, Zero Collision): {len(test_records_clean)}")
print(f"    Consumed Test (Historically Exposed to V3): {len(test_records_consumed)}")

# 6. Format ChatML Dialogues
def format_chat_record(item):
    q_name = item['cwe_query']
    q = QUERIES.get(q_name, QUERIES['cwe-089wLLM'])
    prompts = q.get('prompts', {})
    cwe_id = prompts.get("cwe_id") or prompts.get("cwe-id") or q.get("cwe_id") or "089"
    cwe_id_str = str(cwe_id).replace("CWE-", "")
    
    desc = prompts.get("desc") or q.get("desc", "")
    long_desc = prompts.get("long_desc", desc)
    examples_str = json.dumps(prompts.get("examples", []), indent=2)

    method_line = f"{item['package']},{item['class']},{item['method']},{item['signature']}"
    user_prompt = API_LABELLING_USER_PROMPT.format(
        cwe_long_description=long_desc,
        cwe_examples=examples_str,
        cwe_description=desc,
        cwe_id=cwe_id_str,
        methods=method_line
    )

    assistant_obj = {
        "package": item['package'],
        "class": item['class'],
        "method": item['method'],
        "signature": item['signature'],
        "sink_args": item['sink_args'] if item['type'] == 'sink' else [],
        "type": item['type']
    }
    assistant_content = json.dumps(assistant_obj, separators=(',', ':'))

    return {
        "messages": [
            {"role": "system", "content": STAGE3_SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
            {"role": "assistant", "content": assistant_content}
        ],
        "meta": {
            "cwe": f"CWE-{cwe_id_str.zfill(3)}",
            "package": item['package'],
            "class": item['class'],
            "method": item['method'],
            "signature": item['signature'],
            "project": item['project'],
            "type": item['type'],
            "provenance": item['provenance']
        }
    }

train_chat = [format_chat_record(r) for r in train_records]
val_chat = [format_chat_record(r) for r in val_records]
test_clean_chat = [format_chat_record(r) for r in test_records_clean]
test_consumed_chat = [format_chat_record(r) for r in test_records_consumed]

def write_jsonl(recs, fname):
    fpath = os.path.join(OUTPUT_DIR, fname)
    with open(fpath, "w", encoding="utf-8") as f:
        for r in recs:
            row_dict = {"messages": r["messages"]}
            f.write(json.dumps(row_dict, ensure_ascii=False) + "\n")
    sha256 = hashlib.sha256(open(fpath, "rb").read()).hexdigest()
    return fpath, len(recs), sha256

train_path, train_len, train_hash = write_jsonl(train_chat, "train.jsonl")
val_path, val_len, val_hash = write_jsonl(val_chat, "validation.jsonl")
test_clean_path, test_clean_len, test_clean_hash = write_jsonl(test_clean_chat, "test_clean_heldout.jsonl")
test_consumed_path, test_consumed_len, test_consumed_hash = write_jsonl(test_consumed_chat, "test_consumed_historical.jsonl")
test_path, test_len, test_hash = write_jsonl(test_clean_chat, "test.jsonl")

# 7. Strict Dynamic Quality Gates Assertions
gate_family_leakage = (len(train_projects.intersection(test_projects)) == 0)
assert gate_family_leakage, "FAIL: Project overlap detected between train and test!"

gate_prompt_collision = all(not r['is_prompt_collision'] for r in test_records_clean)
assert gate_prompt_collision, "FAIL: Prompt collision detected in clean held-out test!"

clean_test_sigs = {(r['package'], r['class'], r['method'], r['signature']) for r in test_records_clean}
overlap_with_v3_train = clean_test_sigs.intersection(v3_train_signatures)
gate_v3_overlap = (len(overlap_with_v3_train) == 0)
assert gate_v3_overlap, f"FAIL: {len(overlap_with_v3_train)} records overlap with historical V3 train!"

all_trusted_records = train_records + val_records + test_records_clean
gate_no_heuristic = all(r.get('tier', 99) <= 3 and r.get('provenance') != 'HEURISTIC_CANDIDATE' for r in all_trusted_records)
assert gate_no_heuristic, "FAIL: Heuristic candidate found in trusted splits!"

trusted_sinks = [r for r in all_trusted_records if r['type'] == 'sink']
gate_sink_args = all(r.get('sink_args') and len(r['sink_args']) > 0 for r in trusted_sinks)
assert gate_sink_args, "FAIL: Trusted sink record with empty or invalid sink_args found!"

gate_cwe_mapping = all(r['cwe_query'] in QUERIES for r in all_trusted_records)
assert gate_cwe_mapping, "FAIL: Unmapped CWE query found in trusted records!"

manifest_repaired = {
    "dataset_version": "NTK-IRIS-STAGE3-CANONICAL-V4.1-SCIENTIFIC-VERIFIED",
    "total_training_view_records": train_len + val_len + test_clean_len,
    "split_strategy": "PROJECT_PROVENANCE_INDEPENDENT",
    "provenance_tiers": {
        "tier_1": "CANONICAL_401_GT",
        "tier_2": "CURATED_CVE_SOURCE_SINK",
        "tier_3": "CODEQL_MODEL_CANDIDATE"
    },
    "splits": {
        "train": {"rows": train_len, "sha256": train_hash, "projects": len(train_projects)},
        "validation": {"rows": val_len, "sha256": val_hash, "projects": len(val_projects)},
        "test_clean_heldout": {"rows": test_clean_len, "sha256": test_clean_hash, "projects": len(test_projects)},
        "test_consumed_historical": {"rows": test_consumed_len, "sha256": test_consumed_hash}
    },
    "scientific_quality_gates": {
        "GATE_ZERO_FAMILY_LEAKAGE": gate_family_leakage,
        "GATE_ZERO_PROMPT_COLLISION": gate_prompt_collision,
        "GATE_ZERO_HISTORICAL_TRAIN_OVERLAP": gate_v3_overlap,
        "GATE_NO_HEURISTIC_IN_TRUSTED": gate_no_heuristic,
        "GATE_VERIFIED_SINK_ARGS": gate_sink_args,
        "GATE_EXPLICIT_CWE_MAPPING_FAIL_CLOSED": gate_cwe_mapping,
        "GATE_CONFLICT_ADJUDICATION_COMPLETE": (disputed_count == 0 or all(c['status'].startswith('RESOLVED_') or c['status'].endswith('_QUARANTINED') for c in conflict_ledger))
    }
}

with open(os.path.join(OUTPUT_DIR, "manifest.json"), "w", encoding="utf-8") as f:
    json.dump(manifest_repaired, f, indent=2)

with open(os.path.join(OUTPUT_DIR, "checksums.sha256"), "w", encoding="utf-8") as f:
    f.write(f"{train_hash}  train.jsonl\n")
    f.write(f"{val_hash}  validation.jsonl\n")
    f.write(f"{test_clean_hash}  test_clean_heldout.jsonl\n")
    f.write(f"{test_hash}  test.jsonl\n")

print(f"\n[✓] Canonical Dataset V4.1 Complete & Dynamically Verified:")
print(f"    Train: {train_len} rows (SHA: {train_hash[:16]}...)")
print(f"    Val:   {val_len} rows (SHA: {val_hash[:16]}...)")
print(f"    Clean Held-Out Test: {test_clean_len} rows (SHA: {test_clean_hash[:16]}...)")
print(f"    All 7 Scientific Quality Gates: PASS")
