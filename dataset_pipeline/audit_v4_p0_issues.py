import json
import csv
from collections import defaultdict, Counter

print('=== 1. AUDITING EVIDENCE BANK CONFLICTS (P0.6) ===')
bank_path = '/home/tuankhoa/migration/dataset_v4_scientific_20261013/evidence_bank.jsonl'
records_by_api = defaultdict(list)
total_records = 0

with open(bank_path, 'r', encoding='utf-8') as f:
    for line in f:
        total_records += 1
        r = json.loads(line)
        api_key = (r['cwe_query'], r['package'], r['class'], r['method'], r['signature'])
        records_by_api[api_key].append(r)

conflicts = []
for api_key, items in records_by_api.items():
    types = set(it['type'] for it in items)
    if len(types) > 1:
        conflicts.append((api_key, items))

print(f'Total records in Evidence Bank: {total_records}')
print(f'Unique API keys: {len(records_by_api)}')
print(f'API keys with conflicting labels: {len(conflicts)}')
if conflicts:
    print('Sample conflict:')
    c_key, c_items = conflicts[0]
    print('Key:', c_key)
    for it in c_items:
        print('  type:', it['type'], 'provenance:', it['provenance'], 'confidence:', it['confidence'])

print('\n=== 2. AUDITING V3 TRAIN vs V4 TEST OVERLAP (P0.4) ===')
v3_train_path = '/home/tuankhoa/migration/dataset_v3_augmented_20261012/train.jsonl'
v4_test_path = '/home/tuankhoa/migration/dataset_v4_scientific_20261013/test.jsonl'

v3_train_apis = set()
with open(v3_train_path, 'r', encoding='utf-8') as f:
    for line in f:
        d = json.loads(line)
        asst = json.loads(d['messages'][2]['content'])
        v3_train_apis.add((asst['package'], asst['class'], asst['method'], asst['signature']))

v4_test_apis = set()
v4_test_rows = 0
v4_test_overlap_rows = 0
with open(v4_test_path, 'r', encoding='utf-8') as f:
    for line in f:
        v4_test_rows += 1
        d = json.loads(line)
        asst = json.loads(d['messages'][2]['content'])
        api = (asst['package'], asst['class'], asst['method'], asst['signature'])
        v4_test_apis.add(api)
        if api in v3_train_apis:
            v4_test_overlap_rows += 1

print(f'V3 Train unique APIs: {len(v3_train_apis)}')
print(f'V4 Test unique APIs: {len(v4_test_apis)}')
print(f'V4 Test rows: {v4_test_rows}')
print(f'V4 Test rows that appeared in V3 Train: {v4_test_overlap_rows}')
overlap_apis = v3_train_apis.intersection(v4_test_apis)
print(f'Unique Overlap APIs between V3 Train and V4 Test: {len(overlap_apis)}')

print('\n=== 3. AUDITING SINK_ARGS FORMAT (P0.2) ===')
bad_sink_args = 0
with open(bank_path, 'r', encoding='utf-8') as f:
    for line in f:
        r = json.loads(line)
        if r['type'] == 'sink':
            for arg in r.get('sink_args', []):
                # If arg contains '.' or looks like a Java type e.g. java.lang.String
                if '.' in str(arg) or str(arg).startswith('java.'):
                    bad_sink_args += 1
                    break
print(f'Sink records with Java Type used as argument name: {bad_sink_args}')
