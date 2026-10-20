from __future__ import annotations
import csv
import dataclasses
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import sys
from urllib.parse import unquote, urlparse
from ntk_b33.common import Blocker, IDENTITY, canonical, digest, parameter_names, write_json

SOURCE_POLICY = 'CODEQL_DISCOVERED_LOCAL_GETENV_CALL_UNTRUSTED_BY_EXPLICIT_DEMO_POLICY_NOT_LLM'
SCORER_SHA = 'c1b9cbf071739ca6d96062032867835dbf4db185f4e0ac1e2d609bd319e0de7e'


def normalized_uri(value: str, target: Path) -> str:
    """Do not join by basename; reject remote URIs and paths outside the target."""
    parsed = urlparse(value)
    if parsed.scheme and parsed.scheme != 'file':
        raise Blocker('REMOTE_OR_UNSUPPORTED_ARTIFACT_URI: ' + value)
    if parsed.netloc and parsed.netloc not in ('', 'localhost'):
        raise Blocker('REMOTE_FILE_URI')
    raw = unquote(parsed.path if parsed.scheme else value).replace('\\', '/')
    p = Path(raw)
    if p.is_absolute():
        try:
            raw = p.resolve().relative_to(target.resolve()).as_posix()
        except ValueError as exc:
            raise Blocker('ARTIFACT_OUTSIDE_FIXTURE: ' + value) from exc
    pure = PurePosixPath(raw)
    if '..' in pure.parts or not pure.parts or pure.is_absolute():
        raise Blocker('UNSAFE_ARTIFACT_URI: ' + value)
    return pure.as_posix()


def split_types(body: str) -> list[str]:
    if not body.strip():
        return []
    result, buf, depth = [], [], 0
    for ch in body:
        if ch == '<':
            depth += 1
        elif ch == '>':
            depth -= 1
        if depth < 0:
            raise Blocker('UNBALANCED_TYPE_SIGNATURE')
        if ch == ',' and depth == 0:
            result.append(''.join(buf).strip()); buf = []
        else:
            buf.append(ch)
    if depth:
        raise Blocker('UNBALANCED_TYPE_SIGNATURE')
    result.append(''.join(buf).strip())
    if any(not item for item in result):
        raise Blocker('EMPTY_PARAMETER_TYPE')
    return result


def make_signature(row: dict) -> str:
    method, short = row['method'], row['short_signature']
    if not short.startswith(method + '(') or not short.endswith(')'):
        raise Blocker('UNSUPPORTED_COMPILER_SHORT_SIGNATURE')
    parts = split_types(short[len(method) + 1:-1])
    if len(parts) != int(row['arity']):
        raise Blocker('COMPILER_PARAMETER_COUNT_MISMATCH')
    result = row['return_type'] + ' ' + method + '(' + ', '.join(
        '%s p%d' % (ty, i) for i, ty in enumerate(parts)) + ')'
    parameter_names(result)
    return result


def read_calls(path: Path, target: Path) -> tuple[list[dict], list[dict]]:
    with path.open(newline='', encoding='utf-8-sig') as f:
        raw = list(csv.DictReader(f))
    required = {'uri', 'start_line', 'start_column', 'end_line', 'end_column',
                'package', 'clazz', 'method', 'compiler_signature', 'short_signature',
                'return_type', 'arity', 'is_static'}
    if not raw or any(set(r) != required for r in raw):
        raise Blocker('MISSING_OR_UNEXPECTED_CODEQL_CALL_COLUMNS')
    unique, calls = {}, []
    for r in raw:
        sig = make_signature(r)
        case = {'package': r['package'], 'class': r['clazz'], 'method': r['method'],
                'signature': sig, 'cwe': '89', 'is_static': r['is_static'] == 'true',
                'receiver_policy': 'HOLD_THIS_UNTIL_SEMANTIC_REVIEW',
                'compiler_signature': r['compiler_signature'], 'arity': int(r['arity'])}
        if r['is_static'] not in ('true', 'false'):
            raise Blocker('INVALID_COMPILER_STATIC_FLAG')
        key = digest([case[k] for k in IDENTITY])
        provenance = {k: v for k, v in case.items() if k != 'source_record_sha256'}
        case['source_record_sha256'] = digest(provenance)
        if key in unique and unique[key] != case:
            raise Blocker('NATIVE_IDENTITY_COLLISION_BETWEEN_COMPILER_OVERLOADS')
        unique[key] = case
        loc = dict(case, uri=normalized_uri(r['uri'], target), case_key=key)
        for k in ('start_line', 'start_column', 'end_line', 'end_column'):
            loc[k] = int(r[k])
            if loc[k] < 1:
                raise Blocker('INVALID_COMPILER_LOCATION')
        if not (target / loc['uri']).is_file():
            raise Blocker('EXTRACTED_CALL_NOT_IN_FIXTURE')
        calls.append(loc)
    cases = [unique[k] for k in sorted(unique)]
    if len(cases) > 40:
        raise Blocker('UNEXPECTED_FIXTURE_CANDIDATE_VOLUME')
    return cases, calls


def read_arguments(path: Path, target: Path) -> list[dict]:
    with path.open(newline='', encoding='utf-8-sig') as f:
        result = list(csv.DictReader(f))
    for r in result:
        r['uri'] = normalized_uri(r['uri'], target)
        for k in ('call_line', 'call_column', 'argument_index', 'start_line', 'start_column',
                  'end_line', 'end_column'):
            r[k] = int(r[k])
    return result


def label_key(label: dict) -> tuple:
    return tuple(label[k] for k in IDENTITY)


def emit_flow(template: str, cases: list[dict], labels: list[dict], arm: str) -> tuple[str, list[dict]]:
    if arm not in ('base', 'epoch_1', 'epoch_2'):
        raise Blocker('INVALID_ARM')
    mapping = {label_key(c): c for c in cases}
    proof, bodies, seen = [], [], set()
    for label in labels:
        if label.get('type') != 'sink':
            raise Blocker('NON_SINK_IN_SINK_ARTIFACT')
        key = label_key(label)
        if key not in mapping or key in seen:
            raise Blocker('UNKNOWN_OR_DUPLICATE_NATIVE_SINK')
        seen.add(key)
        case = mapping[key]
        params = parameter_names(case['signature'])
        arguments = label.get('sink_args', [])
        if not arguments:
            raise Blocker('EMPTY_SINK_ARGUMENTS')
        indices = []
        for arg in arguments:
            if arg == 'this' or arg not in params or not re.fullmatch(r'p[0-9]+', arg):
                raise Blocker('UNPROVEN_RECEIVER_OR_SINK_PARAMETER')
            index = params.index(arg)
            if index >= case['arity'] or index in indices:
                raise Blocker('INVALID_OR_DUPLICATE_SINK_PARAMETER')
            indices.append(index)
        q = lambda value: json.dumps(value, ensure_ascii=True)
        body = ('exists(MethodCall call |\n'
                '      call.getMethod().getDeclaringType().hasQualifiedName(%s, %s) and\n'
                '      call.getMethod().getSignature() = %s and\n'
                '      call.getMethod().getNumberOfParameters() = %d and\n'
                '      (%s)\n    )') % (q(case['package']), q(case['class']),
                q(case['compiler_signature']), case['arity'], ' or '.join(
                    'sink.asExpr() = call.getArgument(%d)' % n for n in indices))
        bodies.append(body)
        proof.append({'candidate': case, 'label': label, 'argument_indices': indices,
                      'match': 'EXACT_DECLARING_OWNER_AND_COMPILER_SIGNATURE_AND_ARGUMENT_POSITION',
                      'semantic_gold': False})
    text = template.replace('__ARM__', arm).replace('__SINK_BODY__',
                                                 '\n    or '.join(bodies) if bodies else '1 = 0')
    if '__SINK_BODY__' in text or '__ARM__' in text:
        raise Blocker('UNEXPANDED_QUERY_TEMPLATE')
    return text, proof


def contains(span: dict, line: int, column: int) -> bool:
    return (span['start_line'], span.get('start_column', 1)) <= (line, column) <= (
        span['end_line'], span.get('end_column', 10**9))


def physical_location(location: dict, run: dict, target: Path) -> dict:
    physical = location.get('physicalLocation', location)
    artifact = physical.get('artifactLocation', {})
    if 'uri' not in artifact and 'index' in artifact:
        artifact = run.get('artifacts', [])[artifact['index']]['location']
    uri = artifact.get('uri')
    if not isinstance(uri, str):
        raise Blocker('SARIF_LOCATION_MISSING_URI')
    # Relative source URIs are evaluated against the known database source root.
    # Absolute/base-resolved URIs may not escape it.
    region = physical.get('region', {})
    result = {'uri': normalized_uri(uri, target), 'start_line': int(region['startLine']),
              'start_column': int(region.get('startColumn', 1)),
              'end_line': int(region.get('endLine', region['startLine'])),
              'end_column': int(region.get('endColumn', region.get('startColumn', 1)))}
    return result


def parse_flows(sarif: dict, target: Path, calls: list[dict], arguments: list[dict],
                proof: list[dict]) -> list[dict]:
    flows = []
    allowed = {(p['candidate']['package'], p['candidate']['class'],
                p['candidate']['compiler_signature'], n) for p in proof for n in p['argument_indices']}
    for run in sarif.get('runs', []):
        for index, result in enumerate(run.get('results', [])):
            loc = physical_location(result['locations'][0], run, target)
            matches = [a for a in arguments if a['uri'] == loc['uri'] and
                       contains(a, loc['start_line'], loc['start_column']) and
                       (a['package'], a['clazz'], a['compiler_signature'], a['argument_index']) in allowed]
            if len(matches) != 1:
                raise Blocker('FLOW_SINK_NOT_UNIQUELY_BOUND_TO_LIVE_API_AND_ARGUMENT')
            arg = matches[0]
            call = [c for c in calls if c['uri'] == arg['uri'] and c['start_line'] == arg['call_line'] and
                    c['start_column'] == arg['call_column'] and c['compiler_signature'] == arg['compiler_signature']]
            if len(call) != 1:
                raise Blocker('FLOW_CALLSITE_BINDING_NOT_UNIQUE')
            paths = []
            for cf in result.get('codeFlows', []):
                for tf in cf.get('threadFlows', []):
                    nodes = [physical_location(t['location'], run, target) for t in tf.get('locations', [])]
                    if len(nodes) < 2:
                        continue
                    first, last = nodes[0], nodes[-1]
                    source_calls = [c for c in calls if c['uri'] == first['uri'] and
                                    c['package'] == 'java.lang' and c['class'] == 'System' and
                                    c['compiler_signature'] == 'getenv(java.lang.String)' and
                                    contains(c, first['start_line'], first['start_column'])]
                    if not source_calls or last['uri'] != arg['uri'] or not contains(
                            arg, last['start_line'], last['start_column']):
                        raise Blocker('CODEQL_PATH_ENDPOINTS_NOT_PROVEN')
                    paths.append(nodes)
            if not paths:
                raise Blocker('SARIF_RESULT_WITHOUT_VERIFIABLE_SOURCE_TO_SINK_PATH')
            flows.append({'id': digest([result.get('ruleId'), index, loc]), 'cwe': '89',
                          'location': loc, 'callsite': call[0], 'argument_index': arg['argument_index'],
                          'paths': paths, 'raw_result': result, 'source_policy': SOURCE_POLICY,
                          'source_discovered_by_llm': False, 'origin': 'REAL_CODEQL_PATH_QUERY'})
    return flows


def load_scorer(path: Path):
    from ntk_b33.common import sha_file
    if sha_file(path) != SCORER_SHA:
        raise Blocker('FROZEN_SCORER_SHA_MISMATCH')
    spec = importlib.util.spec_from_file_location('ntk_frozen_scorer', path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.SASTScoringEngine()


def fuse(opengrep: dict, flows: list[dict], trace: list[dict], calls: list[dict],
         target: Path, scorer) -> list[dict]:
    records, consumed = [], set()
    verdicts = {label_key(t['candidate']): t for t in trace if t.get('phase') == 'cold'}
    for i, raw in enumerate(opengrep.get('results', [])):
        uri = normalized_uri(raw['path'], target)
        st, en = raw['start'], raw['end']
        span = {'start_line': st['line'], 'start_column': st.get('col', 1),
                'end_line': en['line'], 'end_column': en.get('col', 10**9)}
        matched = [c for c in calls if c['uri'] == uri and c['package'] == 'java.sql' and
                   contains(span, c['start_line'], c['start_column'])]
        call = matched[0] if len(matched) == 1 else None
        linked = [f for f in flows if call is not None and f['callsite'] == call]
        consumed.update(f['id'] for f in linked)
        extra = raw.get('extra', {})
        record = {'id': 'opengrep:' + str(i), 'origin': 'OPENGREP', 'cwe': '89',
                  'rule_id': raw['check_id'], 'severity': extra.get('severity', 'ERROR'),
                  'message': extra.get('message', ''), 'metadata': extra.get('metadata', {'cwe': ['CWE-89']}),
                  'location': dict(span, uri=uri), 'original_opengrep': raw,
                  'callsite': call, 'linked_codeql_flow_ids': [f['id'] for f in linked]}
        apply_evidence(record, linked, verdicts.get(label_key(call)) if call else None, scorer)
        records.append(record)
    for f in flows:
        if f['id'] in consumed:
            continue
        record = {'id': 'codeql:' + f['id'], 'origin': 'CODEQL_ADDITIONAL', 'cwe': '89',
                  'rule_id': f['raw_result'].get('ruleId', 'ntk/b34/cwe89'), 'severity': 'ERROR',
                  'message': 'CodeQL source-to-sink path with live IRIS sink label.',
                  'metadata': {'cwe': ['CWE-89'], 'confidence': 'UNKNOWN'},
                  'location': f['location'], 'callsite': f['callsite'],
                  'linked_codeql_flow_ids': [f['id']]}
        apply_evidence(record, [f], verdicts.get(label_key(f['callsite'])), scorer)
        records.append(record)
    if sum(r['origin'] == 'OPENGREP' for r in records) != len(opengrep.get('results', [])):
        raise Blocker('OPENGREP_AUDIT_TRAIL_LOST')
    return records


def apply_evidence(record: dict, flows: list[dict], verdict: dict | None, scorer):
    record['dataflow'] = []
    if flows:
        path = flows[0]['paths'][0]
        record['dataflow'] = [dict(n, type='source' if i == 0 else 'sink' if i == len(path)-1 else 'intermediate',
                                    origin='CODEQL_SARIF_THREADFLOW') for i, n in enumerate(path)]
    record['model_observation'] = verdict
    # The scorer receives positive API-role evidence only, never an inferred FP verdict.
    # All non-sink/abstain/unbound cases remain neutral, with their raw observations retained.
    is_sink = bool(verdict and verdict.get('status') == 'ACCEPTED' and
                   verdict.get('label', {}).get('type') == 'sink')
    record['ai_validation'] = {'api_role': 'sink' if is_sink else 'unknown',
                              'parse_status': 'OK' if is_sink else 'NOT_APPLIED',
                              'verdict': 'API_ROLE_EVIDENCE' if is_sink else 'NEEDS_REVIEW'}
    record['score'] = dataclasses.asdict(scorer.score_finding(record))
    record['score_semantics'] = 'PRIORITIZATION_ONLY_NOT_PROBABILITY_NOT_VULNERABILITY_CONFIRMATION'
    record['retained'] = True


def to_sarif(records: list[dict]) -> dict:
    results = []
    for r in records:
        l = r['location']
        out = {'ruleId': r['rule_id'], 'level': 'warning', 'message': {'text': r['message']},
               'locations': [{'physicalLocation': {'artifactLocation': {'uri': l['uri']},
                    'region': {'startLine': l['start_line'], 'startColumn': l['start_column']}}}],
               'properties': {'ntk_id': r['id'], 'origin': r['origin'], 'retained': True,
                              'priority_score': r['score'], 'cwe': 'CWE-89'}}
        if r['dataflow']:
            out['codeFlows'] = [{'threadFlows': [{'locations': [{'location': {'physicalLocation': {
                'artifactLocation': {'uri': n['uri']}, 'region': {'startLine': n['start_line'],
                'startColumn': n['start_column']}}}} for n in r['dataflow']]}]}]
        results.append(out)
    return {'version': '2.1.0', '$schema': 'https://json.schemastore.org/sarif-2.1.0.json',
            'runs': [{'tool': {'driver': {'name': 'NTK-B34-local-fusion', 'version': '0.0.1'}}, 'results': results}]}
