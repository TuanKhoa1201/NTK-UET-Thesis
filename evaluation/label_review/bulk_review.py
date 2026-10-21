#!/usr/bin/env python3
"""Single-confirmation B39B6 draft import. Never locks labels or runs metrics/scans.

Use after quitting the original interactive review. Existing reviewed records are
preserved, source identities are checked, and only UNREVIEWED records can change.
The added provenance makes AI assistance explicit in the existing label exports.
"""
from __future__ import annotations
import argparse
from collections import Counter
from datetime import datetime, timezone
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parent
EXPECTED_CODE_SHA = '54ac479baaf77c3b4be15e5aa20aaa600001093b1d98611275dc5065f71a3ab3'
INPUT_SHA = '4a2997470997e3d9b007837ffda8d7c370e493258100194e2ebd01c6d798d148'
PROPOSAL_SCHEMA = 'NTK_B39B6_BULK_REVIEW_PROPOSAL_V1'
CONFIRM = 'DONG_Y_NHAN_HO_TRO_AI'
MARKER = '[AI-assisted source review; operator-approved; not independent gold] '


class Stop(RuntimeError):
    pass


def need(value, reason):
    if not value:
        raise Stop(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def strict_json(raw):
    def unique(pairs):
        out = {}
        for k, v in pairs:
            need(k not in out, 'DUPLICATE_JSON_KEY:' + str(k))
            out[k] = v
        return out
    def invalid(value):
        raise Stop('NONFINITE_JSON:' + value)
    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)


def read_regular(path, maximum=32*1024*1024):
    path = Path(path)
    need(not path.is_symlink() and path.is_file(), 'REGULAR_FILE_REQUIRED:' + str(path))
    need(path.stat().st_size <= maximum, 'FILE_LIMIT:' + path.name)
    raw = path.read_bytes()
    need(len(raw) <= maximum, 'FILE_GREW:' + path.name)
    return raw


def load_original(tool):
    tool = Path(tool).expanduser().resolve(strict=True)
    raw = read_regular(ROOT/'EXPECTED_CODE.json')
    need(sha(raw) == EXPECTED_CODE_SHA, 'EXPECTED_CODE_TABLE_DRIFT')
    expected = strict_json(raw)
    for rel, digest in expected.items():
        need(sha(read_regular(tool/rel)) == digest, 'ORIGINAL_EVALUATOR_CODE_DRIFT:' + rel)
    sys.path.insert(0, str(tool))
    spec = importlib.util.spec_from_file_location('ntk_bulk_original_b39b6', tool/'cli.py')
    need(spec is not None and spec.loader is not None, 'ORIGINAL_IMPORT_SPEC')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def require_unlocked(workspace):
    for rel in ('LABEL_LOCK.json', 'private/labels.locked.jsonl'):
        path = workspace/rel
        need(not path.exists() and not path.is_symlink(), 'LABELS_ALREADY_LOCKED_NO_BULK_REWRITE')


def prepare_updates(cli, units, labels, proposal, sources, reviewer, proposal_sha, timestamp):
    cli.validate_labels(units, labels)
    need(isinstance(proposal, dict) and proposal.get('schema') == PROPOSAL_SCHEMA, 'PROPOSAL_SCHEMA')
    need(proposal.get('origin') == 'AI_SOURCE_REVIEW_DRAFT_REQUIRES_OPERATOR_APPROVAL', 'PROPOSAL_ORIGIN')
    need(proposal.get('scope') == 'POSTHOC_DEVELOPMENT_REVIEW_NOT_INDEPENDENT_GOLD', 'PROPOSAL_SCOPE')
    need(proposal.get('already_exposed_to_predictions') is True, 'PROPOSAL_EXPOSURE')
    need(proposal.get('proposed_by') == 'ChatGPT', 'PROPOSER_IDENTITY')
    need(proposal.get('input_sha256') == INPUT_SHA, 'PROPOSAL_INPUT_SHA')
    need(isinstance(reviewer, str) and reviewer.strip() and len(reviewer) <= 180, 'REVIEWER_REQUIRED')
    need(all(ord(c) >= 32 and ord(c) != 127 for c in reviewer), 'REVIEWER_CONTROL_CHARACTER')
    rows = proposal.get('records')
    need(isinstance(rows, list) and len(rows) == len(units), 'PROPOSAL_RECORD_COUNT')
    by_uri = {}
    for row in rows:
        need(isinstance(row, dict) and set(row) == {'uri','cwe','source_sha256','truth','rationale','assumptions','evidence_lines'}, 'PROPOSAL_FIELDS')
        uri = row['uri']
        need(isinstance(uri, str) and uri not in by_uri, 'DUPLICATE_PROPOSAL_URI')
        by_uri[uri] = row
    need(set(by_uri) == {u['uri'] for u in units}, 'PROPOSAL_SOURCE_SET')
    indexed = {u['unit_id']: u for u in units}
    for u in units:
        row = by_uri[u['uri']]
        need(row['source_sha256'] == u['source_sha256'] and row['cwe'] == u['cwe'] and u['input_sha256'] == INPUT_SHA, 'PROPOSAL_BINDING_DRIFT')
        need(u['uri'] in sources and sha(sources[u['uri']]) == u['source_sha256'], 'ACTUAL_REVIEW_SOURCE_DRIFT')
        lines = row['evidence_lines']
        need(isinstance(lines, list) and bool(lines) and all(type(n) is int and n > 0 for n in lines), 'PROPOSAL_LINE_LIST')
        need(len(lines) == len(set(lines)) and max(lines) <= len(sources[u['uri']].decode('utf-8').splitlines()), 'PROPOSAL_LINE_RANGE')
        need(row['truth'] in ('POSITIVE','NEGATIVE','UNKNOWN'), 'PROPOSAL_TRUTH')
        for key in ('rationale','assumptions'):
            need(isinstance(row[key], str) and 1 <= len(row[key].strip()) <= 7000, 'PROPOSAL_TEXT:' + key)
            need(all(c in '\n\t' or ord(c) >= 32 and ord(c) != 127 for c in row[key]), 'PROPOSAL_TEXT_CONTROL')
    updated, changed = [], []
    for old in labels:
        if old['review_status'] == 'REVIEWED':
            updated.append(old)
            continue
        u = indexed[old['unit_id']]
        p = by_uri[u['uri']]
        new = {**old, 'truth':p['truth'], 'review_status':'REVIEWED',
               'reviewer':reviewer.strip() + ' [AI-assisted]', 'reviewed_at':timestamp,
               'rationale':MARKER + p['rationale'].strip(), 'assumptions':p['assumptions'].strip(),
               'evidence_lines':p['evidence_lines'], 'proposal_author':'ChatGPT',
               'assistance_mode':'AI_SOURCE_DRAFT_OPERATOR_APPROVED',
               'proposal_sha256':proposal_sha, 'human_review_independent':False}
        updated.append(new)
        changed.append((u, new))
    cli.validate_labels(units, updated, for_lock=True)
    return updated, changed


def serialize(cli, labels):
    return (''.join(cli.canonical(x)+'\n' for x in labels)).encode('utf-8')


def save_new(path, raw):
    with path.open('xb') as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())


def atomic_bytes(path, raw):
    temp = path.with_name(path.name + '.bulk_tmp_' + uuid.uuid4().hex)
    try:
        save_new(temp, raw)
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()


def commit(cli, workspace, before, labels, proposal_raw, reviewer, changed):
    require_unlocked(workspace)
    draft = workspace/'private/labels.draft.jsonl'
    need(read_regular(draft) == before, 'DRAFT_CHANGED_CONCURRENTLY_NOT_OVERWRITTEN')
    after = serialize(cli, labels)
    folder = workspace/'private'/('bulk_review_' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '_' + uuid.uuid4().hex[:8])
    folder.mkdir(mode=0o700, exist_ok=False)
    save_new(folder/'labels.before.jsonl', before)
    save_new(folder/'approved_proposals.json', proposal_raw)
    receipt = {'schema':'NTK_B39B6_BULK_IMPORT_RECEIPT_V1', 'workspace':str(workspace),
        'status':'PREPARED_BEFORE_DRAFT_REPLACE', 'before_sha256':sha(before), 'after_sha256':sha(after),
        'proposal_sha256':sha(proposal_raw), 'importer_sha256':sha(read_regular(Path(__file__))),
        'reviewer':reviewer, 'assistance_mode':'AI_SOURCE_DRAFT_OPERATOR_APPROVED',
        'modified_units':[u['unit_id'] for u, _ in changed],
        'preserved_existing_reviewed':len(labels)-len(changed),
        'truth_counts':dict(Counter(x['truth'] for x in labels)),
        'created_at':datetime.now(timezone.utc).isoformat(),
        'independent_gold':False, 'new_scan':False, 'label_lock_created_by_importer':False}
    save_new(folder/'receipt.json', (cli.canonical(receipt)+'\n').encode())
    require_unlocked(workspace)
    need(read_regular(draft) == before, 'DRAFT_CHANGED_DURING_BACKUP_NOT_OVERWRITTEN')
    atomic_bytes(draft, after)
    need(read_regular(draft) == after, 'DRAFT_WRITE_VERIFICATION_FAILED')
    receipt['status'] = 'BULK_REVIEW_IMPORTED_NOT_YET_LOCKED'
    atomic_bytes(folder/'receipt.json', (cli.canonical(receipt)+'\n').encode())
    return folder, receipt


def restore(cli, workspace, receipt_path, ask=input):
    require_unlocked(workspace)
    receipt_path = Path(receipt_path).resolve(strict=True)
    need(receipt_path.name == 'receipt.json' and receipt_path.parent.parent == workspace/'private'
         and receipt_path.parent.name.startswith('bulk_review_'), 'BACKUP_LOCATION_INVALID')
    receipt = strict_json(read_regular(receipt_path))
    need(receipt.get('schema') == 'NTK_B39B6_BULK_IMPORT_RECEIPT_V1'
         and receipt.get('workspace') == str(workspace)
         and receipt.get('status') == 'BULK_REVIEW_IMPORTED_NOT_YET_LOCKED', 'BACKUP_RECEIPT_INVALID')
    old = read_regular(receipt_path.parent/'labels.before.jsonl')
    need(sha(old) == receipt['before_sha256'], 'BACKUP_CHECKSUM_MISMATCH')
    draft = workspace/'private/labels.draft.jsonl'
    current = read_regular(draft)
    need(sha(current) == receipt['after_sha256'], 'CURRENT_DRAFT_CHANGED_REFUSE_RESTORE')
    print('Restore pre-import draft only. No locked labels will be removed.')
    if ask('Type KHOI_PHUC_DRAFT to restore, otherwise cancel: ').strip() != 'KHOI_PHUC_DRAFT':
        return 3
    require_unlocked(workspace)
    need(read_regular(draft) == current, 'CONCURRENT_DRAFT_CHANGE')
    save_new(receipt_path.parent/'labels.before_restore.jsonl', current)
    atomic_bytes(draft, old)
    receipt['status'] = 'DRAFT_RESTORED_BEFORE_LABEL_LOCK'
    atomic_bytes(receipt_path, (cli.canonical(receipt)+'\n').encode())
    print('STATUS=DRAFT_RESTORED_BEFORE_LABEL_LOCK')
    return 0


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--tool-dir', type=Path, required=True)
    p.add_argument('--workspace', type=Path, required=True)
    p.add_argument('--reviewer', default=os.environ.get('NTK_REVIEWER',''))
    p.add_argument('--downloads', type=Path, default=Path('/mnt/c/Users/HP/Downloads'))
    p.add_argument('--proposals', type=Path, default=ROOT/'review_proposals.json')
    action = p.add_mutually_exclusive_group()
    action.add_argument('--apply', action='store_true')
    action.add_argument('--restore', type=Path, metavar='RECEIPT_JSON')
    a = p.parse_args()
    cli = load_original(a.tool_dir)
    isolation = cli.deny_inet()
    workspace, lock, units, _vectors = cli.workspace_load(a.workspace)
    need(not workspace.is_relative_to(Path.home()/'iris') and not workspace.is_relative_to(Path.home()/'migration/ntk_github_publish_20261020'), 'WORKSPACE_INSIDE_FROZEN_REPO')
    require_unlocked(workspace)
    need(lock['input_sha256'] == INPUT_SHA, 'WRONG_INPUT_FIXTURE')
    if a.apply:
        need(a.downloads.is_dir(), 'DOWNLOADS_DIRECTORY_MISSING')
    if a.apply or a.restore:
        need(sys.stdin.isatty(), 'RUN_FROM_TERMINAL_AFTER_QUITTING_ORIGINAL_REVIEW')
    # This advisory lock serializes this importer, not the legacy interactive reviewer.
    # Operators must first quit the legacy review with q.
    need(not (workspace/'private/bulk_import.lock').is_symlink(), 'BULK_LOCK_SYMLINK_REFUSED')
    with (workspace/'private/bulk_import.lock').open('a+b') as fd:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Stop('ANOTHER_BULK_IMPORT_IS_RUNNING')
        if a.restore:
            return restore(cli, workspace, a.restore)
        draft = workspace/'private/labels.draft.jsonl'
        before = read_regular(draft)
        labels = cli.jsonl(before)
        proposal_raw = read_regular(a.proposals, 256*1024)
        proposal = strict_json(proposal_raw)
        sources = cli.zip_members(read_regular(workspace/'private/review_sources.zip'))
        updates, changed = prepare_updates(cli, units, labels, proposal, sources,
             a.reviewer, sha(proposal_raw), datetime.now(timezone.utc).isoformat())
        print('===== BULK REVIEW PREVIEW: AI-ASSISTED / POSTHOC / NOT GOLD =====')
        print('Previously reviewed records are retained verbatim.')
        for n, (u, label) in enumerate(changed, 1):
            print('\n[%d/%d] %s CWE-%s -> %s' % (n, len(changed), u['uri'], u['cwe'], label['truth']))
            source = sources[u['uri']].decode('utf-8').splitlines()
            for line in label['evidence_lines']:
                print('  %3d | %s' % (line, source[line-1]))
            print('  RATIONALE: ' + label['rationale'])
            print('  ASSUMPTIONS: ' + label['assumptions'])
        print('\nCOUNTS=' + cli.canonical(dict(Counter(x['truth'] for x in updates))))
        print('EXISTING_REVIEWED_PRESERVED=' + str(len(labels)-len(changed)))
        print('PROPOSAL_SHA256=' + sha(proposal_raw))
        print('INDEPENDENT_GOLD=False')
        if not a.apply:
            print('STATUS=PREVIEW_ONLY_NO_LABELS_WRITTEN')
            return 0
        if not changed:
            print('STATUS=NO_PENDING_LABELS_EXISTING_REVIEWS_PRESERVED')
            return 0
        print('\nApprove only after checking ALL listed labels, reasons, lines, and assumptions.')
        print('This records your approval of an AI-assisted draft, NOT independent human gold.')
        print('To correct any entry: cancel, edit review_proposals.json, and rerun.')
        if input('Type ' + CONFIRM + ' to apply all, otherwise cancel: ').strip() != CONFIRM:
            print('STATUS=CANCELLED_NO_LABELS_WRITTEN')
            return 3
        cli.workspace_load(workspace)  # Recheck pinned inputs after the human pause.
        need(read_regular(a.proposals, 256*1024) == proposal_raw, 'PROPOSAL_CHANGED_AFTER_PREVIEW')
        folder, receipt = commit(cli, workspace, before, updates, proposal_raw, a.reviewer, changed)
        print('\n===== B39B6 BULK INPUT RESULT =====')
        print('STATUS=' + receipt['status'])
        print('IMPORTED=' + str(len(changed)))
        print('TRUTH_COUNTS=' + cli.canonical(receipt['truth_counts']))
        print('REVIEW_MODE=AI_ASSISTED_OPERATOR_APPROVED_POSTHOC')
        print('INDEPENDENT_GOLD=False')
        print('BACKUP=' + str(folder/'labels.before.jsonl'))
        print('RECEIPT=' + str(folder/'receipt.json'))
        public = {k:v for k,v in receipt.items() if k not in ('workspace',)}
        public['draft_sha256'] = receipt['after_sha256']
        public['scope'] = 'AI_ASSISTED_POSTHOC_DEVELOPMENT_NOT_INDEPENDENT_HUMAN_GOLD'
        public['attach_with_evaluator_zip'] = True
        public_path = a.downloads/('b39b6_' + folder.name + '_provenance.json')
        public_raw = (cli.canonical(public)+'\n').encode()
        save_new(public_path, public_raw)
        save_new(public_path.with_name(public_path.name+'.sha256'), (sha(public_raw)+'  '+public_path.name+'\n').encode())
        print('PROVENANCE_FILE=' + str(public_path))
        print('PROVENANCE_SHA256=' + sha(public_raw))
        print('NEXT_LOCK_COMMAND=bash ' + str(workspace/'lock.sh'))
        print('NEXT_EVALUATE_COMMAND=bash ' + str(workspace/'evaluate.sh'))
        return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (Exception, KeyboardInterrupt) as exc:
        print('BULK_REVIEW_BLOCKED=' + type(exc).__name__ + ': ' + str(exc), flush=True)
        sys.exit(2)
