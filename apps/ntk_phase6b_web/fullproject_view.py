"""Offline, read-only Phase 5.1 Full-Project results on the local NTK one-port UI.

This is NOT a scanner: it only replays SHA-verified evidence created earlier by
OpenGrep, CodeQL, native IRIS Stage3, local LoRA Epoch1 and SAST V2.2.
"""
from __future__ import annotations
import hashlib
import json
import re
import stat
from pathlib import Path, PurePosixPath

PROJECTS = ('spark_CVE-2016-9177_vuln', 'webgoat_sql_CVE-2026-0006_1.0')
EXPECTED = {'spark_CVE-2016-9177_vuln': (18, 0),
            'webgoat_sql_CVE-2026-0006_1.0': (75, 11)}
EXPECTED_STATUS = 'PHASE51_EXACT_MODEL_LINKS_VERIFIED'
MAX_RAW = 32 * 1024 * 1024

class FullProjectError(ValueError):
    pass


def require(ok, why):
    if not ok:
        raise FullProjectError(why)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _read_file(path, maximum=MAX_RAW):
    p = Path(path)
    require(p.is_file() and not p.is_symlink(), 'REQUIRED_FILE_MISSING_OR_SYMLINK:' + p.name)
    before = p.stat()
    require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum, 'FILE_SIZE_LIMIT:' + p.name)
    with p.open('rb') as handle:
        data = handle.read(maximum + 1)
    after = p.stat()
    require(len(data) == before.st_size and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
            'FILE_CHANGED_DURING_READ:' + p.name)
    return data


def _jload(raw, name):
    def strict_pairs(seq):
        d = {}
        for k, v in seq:
            require(k not in d, 'DUPLICATE_JSON_KEY:' + name)
            d[k] = v
        return d
    def reject_const(v):
        raise FullProjectError('NONFINITE_JSON_VALUE:' + name)
    try:
        return json.loads(raw, object_pairs_hook=strict_pairs, parse_constant=reject_const)
    except (ValueError, UnicodeError, TypeError) as exc:
        raise FullProjectError('MALFORMED_JSON:' + name) from exc


def safe_manifest(root):
    require(root.is_dir() and not root.is_symlink(), 'PHASE51_ROOT_MISSING_OR_SYMLINK')
    manifest = _read_file(root / 'SHA256SUMS', 40960).decode('ascii')
    entries = {}
    for line in manifest.splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        require(match is not None, 'INVALID_SHA256SUMS_LINE')
        checksum, name = match.groups()
        rel = PurePosixPath(name)
        require(bool(rel.parts) and not rel.is_absolute() and '..' not in rel.parts and
                '.' not in rel.parts and '\\' not in name and ':' not in name and
                name not in entries, 'UNSAFE_MANIFEST_MEMBER')
        entries[name] = checksum
    must = {'FULLPROJECT_PHASE51_RESULT.json'} | {
        f'{project}/{name}' for project in PROJECTS for name in ('result.json', 'report.sarif')}
    require(must.issubset(entries), 'PHASE51_MISSING_PINNED_REPORTS')
    # Manifest pins all reports; no user-chosen paths are served.
    return entries


class FullProjectView:
    def __init__(self, run_path):
        root = Path(run_path).expanduser()
        require(root.is_dir() and not root.is_symlink(), 'PHASE51_RUN_NOT_FOUND')
        self.root = root.resolve(strict=True)
        sums = safe_manifest(self.root)
        verified = {}
        for name in sorted(sums):
            path = self.root.joinpath(*PurePosixPath(name).parts)
            require(path.resolve(strict=True).is_relative_to(self.root), 'PHASE51_PATH_ESCAPE')
            raw = _read_file(path)
            require(_sha(raw) == sums[name], 'SHA256_MISMATCH:' + name)
            verified[name] = raw
        summary = _jload(verified['FULLPROJECT_PHASE51_RESULT.json'], 'summary')
        require(summary.get('status') == EXPECTED_STATUS, 'PHASE51_NOT_VERIFIED')
        require(summary.get('exact_model_linked_paths') == 11, 'PHASE51_LINK_COUNT_DRIFT')
        require(summary.get('website_8770_integration') == 'NOT_YET', 'PHASE51_SOURCE_STATUS_DRIFT')
        project_rows = summary.get('project_rows')
        require(isinstance(project_rows, list) and len(project_rows) == 2 and
                {r.get('project') for r in project_rows} == set(PROJECTS), 'PROJECT_ROWS_MISMATCH')
        for r in project_rows:
            p = r['project']
            expected_findings, expected_links = EXPECTED[p]
            require(r['reported_findings'] == expected_findings and
                    r['exact_compiler_sink_argument_links'] == expected_links, 'PROJECT_COUNTS_DRIFT:' + p)
        self.projects = {}
        self.blobs = {}
        for p in PROJECTS:
            data = _jload(verified[f'{p}/result.json'], p + '/result')
            sarif = _jload(verified[f'{p}/report.sarif'], p + '/sarif')
            require(data.get('project') == p and data.get('status') == 'PHASE51_EXACT_BINDING_AUDITED',
                    'PHASE51_PROJECT_STATUS_DRIFT:' + p)
            rows = data.get('findings')
            require(isinstance(rows, list) and len(rows) == EXPECTED[p][0], 'FINDINGS_COUNT_DRIFT:' + p)
            ids = [r['id'] for r in rows]
            require(len(set(ids)) == len(ids), 'DUPLICATE_FINDING_IDS:' + p)
            for finding in rows:
                require(finding.get('vulnerability_confirmed') is False, 'FALSE_CONFIRMED_CLAIM:' + p)
                score = (finding.get('score') or {}).get('final_score')
                require(type(score) in (int, float) and 0 <= score <= 100,
                        'INVALID_SAST_PRIORITY:' + p)
            bindings = data.get('exact_argument_bindings')
            require(isinstance(bindings, list) and len(bindings) == EXPECTED[p][1], 'EXACT_BINDINGS_COUNT_DRIFT:' + p)
            linked_ids = {b.get('finding_id') for b in bindings}
            require(len(linked_ids) == len(bindings) and linked_ids.issubset(set(ids)), 'INVALID_MODEL_BINDINGS:' + p)
            for finding in rows:
                if finding['id'] in linked_ids:
                    require(finding.get('model_qualified_dataflow_path') is True and
                            (finding.get('model_annotation') or {}).get('status') == 'ACCEPTED',
                            'MISSING_QUALIFIED_MODEL_PROOF:' + p)
            require(sarif.get('version') == '2.1.0' and isinstance(sarif.get('runs'), list),
                    'INVALID_SARIF:' + p)
            results = [x for run in sarif['runs'] for x in run.get('results', [])]
            require(len(results) == len(rows), 'JSON_SARIF_PARITY_FAILED:' + p)
            run_info = next(x for x in project_rows if x['project'] == p)
            self.projects[p] = {'project': p, 'status': data['status'],
                                'findings': len(rows),
                                'opengrep_findings': len([r for r in rows if r['origin'] == 'OPENGREP']),
                                'codeql_findings': len([r for r in rows if r['origin'] == 'CODEQL_SECURITY_EXTENDED']),
                                'codeql_paths': run_info['codeql_paths_proven_by_security_query'],
                                'native_sink_identities': run_info['model_sink_identities'],
                                'exact_links': len(bindings),
                                'scan_executed_now': False,
                                'model_inference_now': False,
                                'vulnerabilities_confirmed': 0,
                                'mode': 'HISTORICAL_VERIFIED_PHASE51_IMPORTED'}
            self.blobs[(p, 'result.json')] = verified[f'{p}/result.json']
            self.blobs[(p, 'report.sarif')] = verified[f'{p}/report.sarif']
        require(sum(x['findings'] for x in self.projects.values()) == 93 and
                sum(x['exact_links'] for x in self.projects.values()) == 11 and
                sum(x['codeql_findings'] for x in self.projects.values()) == 74 and
                sum(x['opengrep_findings'] for x in self.projects.values()) == 19,
                'REPORTED_TOTAL_PARITY_FAILED')

    def listing(self):
        return {'mode': 'READ_ONLY_PRIOR_PHASE51_EVIDENCE',
                'new_scan_executed': False, 'fullproject_new_zip_scan_ready': False,
                'vulnerability_confirmation': 'NOT_PROVEN_INDEPENDENTLY',
                'projects': [dict(self.projects[p]) for p in PROJECTS]}

    def detail(self, project):
        require(project in self.projects, 'UNKNOWN_FULLPROJECT')
        body = _jload(self.blobs[(project, 'result.json')], project)
        return body

    def file(self, project, name):
        require(project in self.projects and name in ('result.json', 'report.sarif'), 'INVALID_FULLPROJECT_DOWNLOAD')
        # Immutable in-memory snapshot; nothing is re-read from disk during requests.
        return self.blobs[(project, name)]
