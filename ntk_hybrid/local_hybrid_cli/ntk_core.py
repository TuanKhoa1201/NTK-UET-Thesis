"""Reusable data contract and evaluator. Stdlib only. Never imports ML packages."""
from __future__ import annotations
from collections import Counter
from pathlib import Path, PurePosixPath
import hashlib
import io
import json
import os
import re
import stat
import zipfile
from vendor.common import (Blocker, FIELDS, IDENTITY, PARSER, ROLES, canonical,
                           digest, normalize_cwe, strict_label)

CWES = ('22', '78', '79', '89')


def require(ok, code):
    if not ok:
        raise Blocker(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def loads(data):
    def pairs(items):
        out = {}
        for k, v in items:
            require(k not in out, 'DUPLICATE_JSON_KEY')
            out[k] = v
        return out
    def nonfinite(x):
        raise Blocker('NON_FINITE_JSON')
    try:
        return json.loads(data, object_pairs_hook=pairs, parse_constant=nonfinite)
    except (ValueError, UnicodeError, TypeError) as e:
        raise Blocker('INVALID_JSON:' + type(e).__name__) from None


def jsonl(data):
    rows = []
    try:
        text = data.decode('utf-8-sig') if isinstance(data, bytes) else data
        for i, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            obj = loads(line)
            require(isinstance(obj, dict), 'JSONL_NON_OBJECT_LINE_' + str(i))
            rows.append(obj)
    except UnicodeError:
        raise Blocker('INVALID_UTF8_JSONL') from None
    return rows


def file_state(path):
    s = Path(path).stat()
    return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def read_checked(path, expected=None, limit=64 * 1024**2, states=None):
    path = Path(path)
    require(path.is_file(), 'REQUIRED_FILE_MISSING:' + path.name)
    before = file_state(path)
    require(before[2] <= limit, 'INPUT_SIZE_LIMIT:' + path.name)
    data = path.read_bytes()
    require(file_state(path) == before, 'INPUT_CHANGED_WHILE_READING:' + path.name)
    if expected:
        require(sha(data) == expected, 'INPUT_SHA_MISMATCH:' + path.name)
    if states is not None:
        states[str(path)] = before
    return data


def hash_checked(path, expected, states):
    path = Path(path)
    require(path.is_file(), 'ASSET_FILE_MISSING:' + path.name)
    before = file_state(path)
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(8 * 1024**2), b''):
            h.update(block)
    require(file_state(path) == before, 'ASSET_CHANGED_WHILE_HASHING:' + path.name)
    require(h.hexdigest() == expected, 'ASSET_SHA_MISMATCH:' + path.name)
    states[str(path)] = before
    return h.hexdigest()


def safe_member(name):
    p = PurePosixPath(name)
    require(isinstance(name, str) and name and not p.is_absolute() and
            '..' not in p.parts and '.' not in p.parts and '\\' not in name and
            ':' not in name and not any(ord(c) < 32 for c in name), 'UNSAFE_MEMBER_NAME')
    return p


def zip_members(data, selected=None, max_total=128 * 1024**2):
    """No extraction. CRC on selected bytes. Pinning the archive protects other bytes."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            names = z.namelist()
            require(len(names) == len(set(names)), 'DUPLICATE_ZIP_MEMBERS')
            require(sum(x.file_size for x in z.infolist()) <= max_total, 'ZIP_SIZE_LIMIT')
            for x in z.infolist():
                safe_member(x.filename)
                require(stat.S_IFMT(x.external_attr >> 16) != stat.S_IFLNK, 'ZIP_SYMLINK')
                require(not x.flag_bits & 1, 'ENCRYPTED_ZIP')
            use = selected if selected is not None else [x.filename for x in z.infolist() if not x.is_dir()]
            require(set(use).issubset(names), 'ZIP_REQUIRED_MEMBER_MISSING')
            return {name: z.read(name) for name in use}
    except (zipfile.BadZipFile, KeyError, RuntimeError) as e:
        if isinstance(e, Blocker):
            raise
        raise Blocker('ZIP_READ_ERROR:' + type(e).__name__) from None


def verify_sums(members):
    require('SHA256SUMS' in members, 'SHA256SUMS_MISSING')
    records = {}
    for line in members['SHA256SUMS'].decode('ascii').splitlines():
        require(bool(re.fullmatch(r'[0-9a-f]{64}  .+', line)), 'INVALID_SHA256SUMS_LINE')
        h, name = line.split('  ', 1)
        safe_member(name)
        require(name not in records, 'DUPLICATE_MANIFEST_NAME')
        records[name] = h
    require(set(members) == set(records) | {'SHA256SUMS'}, 'UNMANIFESTED_MEMBERS')
    for name, h in records.items():
        require(sha(members[name]) == h, 'MEMBER_SHA_MISMATCH:' + name)
    return len(records)


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as f:
        f.write(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + '\n')


def write_jsonl(path, values):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as f:
        for obj in values:
            f.write(canonical(obj) + '\n')


def explicit_cwe(row):
    values = []
    for obj in [row, row.get('metadata', {}), row.get('candidate', {})]:
        if not isinstance(obj, dict):
            continue
        for key in ('cwe', 'cwe_id', 'requested_cwe'):
            if key in obj:
                values.append(normalize_cwe(obj[key]))
    require(len(set(values)) == 1, 'MISSING_OR_AMBIGUOUS_CWE')
    return values[0]


def convert_rows(rows):
    """Preserve B28 prompts and targets. Split assistant target away from inference requests."""
    requests, targets, ids = [], [], set()
    for ordinal, row in enumerate(rows):
        require('id' in row and type(row['id']) in (str, int), 'MISSING_SAMPLE_ID')
        key = canonical(row['id'])
        require(key not in ids, 'DUPLICATE_SAMPLE_ID')
        ids.add(key)
        m = row.get('messages')
        require(isinstance(m, list) and len(m) == 3 and all(isinstance(x, dict) for x in m),
                'EXPECTED_EXACTLY_SYSTEM_USER_ASSISTANT')
        require([x.get('role') for x in m] == ['system', 'user', 'assistant'], 'MESSAGE_ROLE_SEQUENCE')
        require(all(set(x) == {'role', 'content'} and isinstance(x['content'], str) for x in m),
                'MESSAGE_SCHEMA')
        label = loads(m[2]['content'])
        require(isinstance(label, dict) and set(label) == FIELDS, 'REFERENCE_NOT_SIX_FIELDS')
        require(all(isinstance(label[k], str) for k in IDENTITY), 'REFERENCE_IDENTITY_SCHEMA')
        require(isinstance(label['type'], str) and label['type'] in ROLES, 'REFERENCE_ROLE')
        sa = label['sink_args']
        require(isinstance(sa, list) and all(isinstance(x, str) for x in sa) and
                len(sa) == len(set(sa)), 'REFERENCE_SINK_ARGS_SCHEMA')
        require((bool(sa) if label['type'] == 'sink' else sa == []), 'REFERENCE_ROLE_ARGS_CONTRADICTION')
        cwe = explicit_cwe(row)
        candidate = {k: label[k] for k in IDENTITY}
        candidate.update(cwe=cwe, is_static=None, receiver_policy='HOLD_THIS_UNTIL_SEMANTIC_REVIEW')
        # Explicit stored identity used for evaluation; NOT a newly compiler-resolved identity.
        for obj in (row, row.get('metadata', {})):
            if not isinstance(obj, dict):
                continue
            for k in IDENTITY:
                if k in obj:
                    require(obj[k] == candidate[k], 'EXPLICIT_IDENTITY_DISAGREES')
        request = {'id': row['id'], 'ordinal': ordinal, 'cwe': cwe, 'candidate': candidate,
                   'messages': m[:2], 'prompt_sha256': digest(m[:2]),
                   'source_record_sha256': digest(row)}
        target = {'id': row['id'], 'cwe': cwe, 'label': label,
                  'quality': 'WEAK_SILVER_NOT_INDEPENDENT_GOLD',
                  'native_reference_contract': strict_label(m[2]['content'], candidate, cwe)}
        requests.append(request)
        targets.append(target)
    return requests, targets


def stats(requests, targets):
    keys = [digest({k: r['candidate'][k] for k in (*IDENTITY, 'cwe')}) for r in requests]
    return {'rows': len(requests), 'distinct_identity_cwe': len(set(keys)),
            'cwes': dict(Counter(r['cwe'] for r in requests)),
            'roles': dict(Counter(t['label']['type'] for t in targets)),
            'cwe_role': dict(Counter(t['cwe'] + '|' + t['label']['type'] for t in targets)),
            'reference_contract_reasons': dict(Counter(t['native_reference_contract']['reason'] for t in targets)),
            'reference_contract_failures_kept': sum(t['native_reference_contract']['status'] != 'ACCEPTED' for t in targets),
            'no_gold_created': True}


def overlap(train, dev):
    key = lambda r: digest({k: r['candidate'][k] for k in (*IDENTITY, 'cwe')})
    return {'id_overlap': len({canonical(x['id']) for x in train} & {canonical(x['id']) for x in dev}),
            'identity_cwe_overlap': len({key(x) for x in train} & {key(x) for x in dev}),
            'prompt_overlap': len({x['prompt_sha256'] for x in train} & {x['prompt_sha256'] for x in dev}),
            'scope': 'EXACT_ONLY_NOT_PROJECT_OR_NEAR_DUPLICATE_LEAKAGE_PROOF'}


def select_smoke(requests):
    # One request per CWE; order depends on input only, never on reference or predictions.
    out = []
    for cwe in CWES:
        subset = [r for r in requests if r['cwe'] == cwe]
        require(bool(subset), 'NO_INPUT_FOR_CWE_' + cwe)
        out.append(min(subset, key=lambda r: (r['prompt_sha256'], canonical(r['id']))))
    return out


def evaluate(requests, targets, predictions):
    """ID-joined evaluator. ABSTAIN remains its own prediction, counted in support/FN."""
    req = {canonical(r['id']): r for r in requests}
    refs = {canonical(t['id']): t for t in targets}
    pred = {canonical(p['id']): p for p in predictions}
    require(len(req) == len(requests) and len(refs) == len(targets) and len(pred) == len(predictions),
            'DUPLICATE_EVALUATION_ID')
    require(set(req) == set(refs) == set(pred), 'EVALUATION_ID_SET_MISMATCH')
    confusion = {role: {p: 0 for p in sorted(ROLES) + ['ABSTAIN']} for role in sorted(ROLES)}
    accepted, exact, joint, reasons = 0, 0, 0, Counter()
    details = []
    for key, r in req.items():
        p, t = pred[key], refs[key]
        require(isinstance(p.get('raw'), str), 'MISSING_RAW_PREDICTION_NOT_ABSTENTION')
        if p.get('infrastructure_failure'):
            raise Blocker('INFRASTRUCTURE_FAILURE_NOT_MODEL_ABSTENTION')
        if 'cwe' in p:
            require(normalize_cwe(p['cwe']) == r['cwe'], 'PREDICTION_CWE_MISMATCH')
        require(t['cwe'] == r['cwe'], 'REFERENCE_CWE_MISMATCH')
        v = strict_label(p['raw'], r['candidate'], r['cwe'], receiver_approved=False)
        role = v['label']['type'] if v['status'] == 'ACCEPTED' else 'ABSTAIN'
        truth = t['label']['type']
        confusion[truth][role] += 1
        accepted += int(role != 'ABSTAIN')
        reasons[v['reason']] += 1
        correct = role == truth
        exact += int(correct)
        sink_correct = truth == 'sink' and role == 'sink' and v['label']['sink_args'] == t['label']['sink_args']
        joint += int(sink_correct)
        details.append({'sample_id_sha256': digest(r['id']), 'cwe': r['cwe'], 'status': v['status'],
                        'reason': v['reason'], 'raw_sha256': sha(p['raw'].encode()),
                        'predicted_role': role, 'reference_role': truth,
                        'role_matches_weak_reference': correct,
                        'sink_args_joint_matches_weak_reference': sink_correct,
                        'prompt_sha256': r['prompt_sha256']})
    per = {}
    for role in sorted(ROLES):
        support = sum(confusion[role].values())
        predicted = sum(v[role] for v in confusion.values())
        tp = confusion[role][role]
        precision = tp / predicted if predicted else 0.0
        recall = tp / support if support else None
        f1 = (2 * tp / (support + predicted)) if support else None
        per[role] = {'support': support, 'predicted': predicted, 'true_positive': tp,
                     'precision_zero_division_0': precision, 'recall': recall, 'f1': f1}
    support_f1s = [m['f1'] for m in per.values() if m['support']]
    n = len(req)
    result = {'n': n, 'parser': PARSER, 'accepted': accepted, 'abstain': n - accepted,
              'coverage': accepted / n if n else None,
              'role_accuracy_over_all': exact / n if n else None,
              'per_role': per, 'confusion_matrix': confusion, 'reason_counts': dict(reasons),
              'macro_f1_supported_roles': sum(support_f1s) / len(support_f1s) if support_f1s else None,
              'macro_f1_four_roles': (sum(support_f1s) / 4 if len(support_f1s) == 4 else None),
              'sink_args_joint_correct': joint, 'sink_denominator': per['sink']['support'],
              'sink_args_joint_accuracy': joint / per['sink']['support'] if per['sink']['support'] else None,
              'label_authority': 'WEAK_SILVER_NOT_GOLD',
              'sink_args_order_policy': 'EXACT_LIST_MATCH_NOT_SET_MATCH',
              'zero_support_recall_and_f1': 'NULL_NOT_ZERO',
              'independent_gold': False}
    return result, details
