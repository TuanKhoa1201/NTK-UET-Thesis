"""B37A: explicit CWE-89 SQL grammar sink policy and evidence-gated ranking.

No alteration to native Stage3 JSON. The policy classifies exact compiler
identities, not Java source filenames, statement kinds guessed from strings,
or whether a finding is expected positive/negative.
"""
from __future__ import annotations
import dataclasses
from copy import deepcopy
from typing import Iterable
from ntk_b33.common import Blocker, IDENTITY, digest, parameter_names
from ntk_b34.core import fuse, to_sarif

# Exact Java compiler overload names, no wildcards or simple-method shortcuts.
POLICY = {
    'id': 'NTK_CWE89_SQL_GRAMMAR_SINK_V2_B37A',
    'scope': 'JDK_ONLY_JAVA_PROJECTS_SQL_TEXT_ONLY_NOT_GENERAL_PRODUCTION_COVERAGE',
    'threat_model': 'System.getenv(String) callsites must exist in current CodeQL database; values assumed untrusted for demo',
    'allow_sql_text': [
        {'package': 'java.sql', 'class': 'Statement', 'method': 'execute',
         'compiler_signature': 'execute(java.lang.String)', 'argument_index': 0},
        {'package': 'java.sql', 'class': 'Statement', 'method': 'executeQuery',
         'compiler_signature': 'executeQuery(java.lang.String)', 'argument_index': 0},
        {'package': 'java.sql', 'class': 'Connection', 'method': 'prepareStatement',
         'compiler_signature': 'prepareStatement(java.lang.String)', 'argument_index': 0},
    ],
    'exclude_binding_values': [
        {'package': 'java.sql', 'class': 'PreparedStatement', 'method': 'setString',
         'compiler_signature': 'setString(int,java.lang.String)', 'argument_index': 1},
    ],
    'unknown_behavior': 'NEEDS_SEMANTIC_REVIEW_NOT_NONE_NOT_FALSE_POSITIVE',
    'score_condition': 'VERIFIED_CODEQL_SOURCE_TO_SQL_GRAMMAR_SINK_AND_ACCEPTED_MODEL_LABEL',
    'score_without_qualified_flow': 'NEUTRAL_UNKNOWN_PRESERVE_ORIGINAL_FINDING',
    'source_policy': 'DATABASE_DISCOVERED_GETENV_CALL_UNTRUSTED_BY_DECLARED_DEMO_POLICY_NOT_LLM',
    'raw_predictions_immutable': True,
    'raw_codeql_paths_immutable': True,
}
POLICY_SHA = digest(POLICY)


def strict_identity(case):
    return tuple(case[k] for k in IDENTITY)


def choose(candidate: dict, index: int) -> str:
    key = {k: candidate.get(k) for k in ('package', 'class', 'method', 'compiler_signature')}
    key['argument_index'] = index
    if key in POLICY['allow_sql_text']:
        return 'SQL_GRAMMAR_SINK_ELIGIBLE'
    if key in POLICY['exclude_binding_values']:
        return 'PARAMETER_BINDING_VALUE_NOT_SQL_GRAMMAR_SINK'
    return 'NEEDS_SEMANTIC_REVIEW_UNKNOWN_SINK'


def adjudicate(candidates: list[dict], labels: list[dict]) -> tuple[list[dict], list[dict]]:
    """Return copy of accepted SQL grammar sink labels and detailed decisions.

    Every accepted raw sink argument is accounted for, including withheld
    binder/unknown ones. The raw label object is never modified.
    """
    keyed = {strict_identity(c): c for c in candidates}
    if len(keyed) != len(candidates):
        raise Blocker('B35_DUPLICATE_COMPILER_CANDIDATE_IDENTITY')
    eligible, records, seen = [], [], set()
    for raw in labels:
        if raw.get('type') != 'sink':
            raise Blocker('B35_NON_SINK_IN_SINK_OUTPUT')
        key = strict_identity(raw)
        if key not in keyed or key in seen:
            raise Blocker('B35_SINK_NOT_UNIQUE_IN_COMPILER_CANDIDATES')
        seen.add(key)
        case = keyed[key]
        params = parameter_names(case['signature'])
        if not raw.get('sink_args') or not isinstance(raw['sink_args'], list):
            raise Blocker('B35_SINK_WITHOUT_VALID_ARG_LIST')
        accepted_args, seen_args = [], set()
        for name in raw['sink_args']:
            if name not in params or name in seen_args:
                raise Blocker('B35_INVALID_OR_DUPLICATE_SINK_ARG')
            seen_args.add(name)
            n = params.index(name)
            if n >= case['arity'] or n < 0:
                raise Blocker('B35_OVERLOAD_SINK_ARG_OUT_OF_BOUNDS')
            decision = choose(case, n)
            records.append({
                'candidate': deepcopy(case), 'raw_label': deepcopy(raw),
                'argument': name, 'argument_index': n, 'decision': decision,
                'reason': ('SQL_QUERY_TEXT_ARGUMENT' if decision == 'SQL_GRAMMAR_SINK_ELIGIBLE'
                           else 'JDBC_PARAMETER_VALUE_BINDING_NOT_QUERY_TEXT' if decision == 'PARAMETER_BINDING_VALUE_NOT_SQL_GRAMMAR_SINK'
                           else 'UNKNOWN_CWE89_ARGUMENT_SEMANTICS_NEEDS_MANUAL_REVIEW'),
                'policy_id': POLICY['id'], 'policy_sha256': POLICY_SHA,
                'not_ground_truth': True,
            })
            if decision == 'SQL_GRAMMAR_SINK_ELIGIBLE':
                accepted_args.append(name)
        if accepted_args:
            eligible.append({**deepcopy(raw), 'sink_args': accepted_args})
    return eligible, records


def guarded_flows(flows: list[dict], decisions: list[dict]) -> tuple[list[dict], list[dict]]:
    allow = {(tuple(d['candidate'][k] for k in IDENTITY), d['argument_index'])
             for d in decisions if d['decision'] == 'SQL_GRAMMAR_SINK_ELIGIBLE'}
    result, rejected = [], []
    for f in flows:
        key = (strict_identity(f['callsite']), f['argument_index'])
        if key in allow:
            result.append(deepcopy(f))
        else:
            rejected.append({'flow_id': f['id'], 'uri': f['location']['uri'],
                             'case': f['callsite']['compiler_signature'],
                             'argument_index': f['argument_index'],
                             'decision': 'NOT_CWE89_SQL_GRAMMAR_SINK',
                             'raw_codeql_path_preserved_in_b34r5': True})
    return result, rejected


def calibrated_fusion(opengrep: dict, valid_flows: list[dict], trace: list[dict],
                      calls: list[dict], target, scorer, decisions: list[dict]) -> list[dict]:
    """Use the pinned B34 fusion and V2.2 scorer; condition AI signal on flow.

    No detection suppression: all original OpenGrep records are preserved.
    The safety invariant applies to analysis output, not raw B34 observations.
    """
    records = fuse(opengrep, valid_flows, trace, calls, target, scorer)
    qualified_ids = {f['id'] for f in valid_flows}
    policy_matches = {(strict_identity(d['candidate']), d['argument_index'])
                      for d in decisions if d['decision'] == 'SQL_GRAMMAR_SINK_ELIGIBLE'}
    flow_by_id = {f['id']: f for f in valid_flows}
    for r in records:
        raw_eval = deepcopy(r.get('ai_validation'))
        linked = list(r.get('linked_codeql_flow_ids', []))
        if any(fid not in qualified_ids for fid in linked):
            raise Blocker('B35_FUSION_LINKS_UNQUALIFIED_PATH')
        proven = bool(linked and all(
            (strict_identity(flow_by_id[fid]['callsite']), flow_by_id[fid]['argument_index']) in policy_matches
            for fid in linked))
        observation = r.get('model_observation')
        if proven:
            if (not isinstance(observation, dict) or observation.get('status') != 'ACCEPTED' or
                    observation.get('label', {}).get('type') != 'sink'):
                raise Blocker('B35_PROVEN_PATH_WITHOUT_ACCEPTED_NATIVE_ROLE')
            r['ai_validation'] = {'api_role': 'sink', 'parse_status': 'OK',
                                  'verdict': 'API_ROLE_PLUS_CODEQL_SQL_GRAMMAR_EVIDENCE'}
        else:
            r['ai_validation'] = {'api_role': 'unknown', 'parse_status': 'NOT_APPLIED',
                                  'verdict': 'NEEDS_REVIEW'}
            if r['dataflow']:
                raise Blocker('B35_UNQUALIFIED_DATAFLOW_WAS_NOT_REMOVED')
        r['original_fusion_ai_evidence'] = raw_eval
        r['score'] = dataclasses.asdict(scorer.score_finding(r))
        r['b35_evidence_decision'] = {
            'classification': 'QUALIFIED_SQL_GRAMMAR_FLOW' if proven else 'NO_QUALIFIED_SQL_GRAMMAR_FLOW',
            'linked_verified_flow_ids': linked,
            'policy_sha256': POLICY_SHA,
            'vulnerability_confirmed': False,
            'role_alone_not_confirmation': True,
            'source_is_declared_demo_policy_not_llm': True,
            'retain_even_if_no_path': True,
        }
        r['score_semantics'] = 'PRIORITY_ONLY_NOT_PROBABILITY_OR_CVSS'
        if r.get('retained') is not True:
            raise Blocker('B35_DROPPED_FINDING_IN_FUSION')
    raw_count = len(opengrep.get('results', []))
    kept = [x for x in records if x['origin'] == 'OPENGREP']
    if len(kept) != raw_count or [x['id'] for x in kept] != [f'opengrep:{i}' for i in range(raw_count)]:
        raise Blocker('B35_OPENGREP_FINDINGS_NOT_PRESERVED_ONE_TO_ONE')
    if len({r['id'] for r in records}) != len(records):
        raise Blocker('B35_DUPLICATE_FUSION_IDS')
    return records
