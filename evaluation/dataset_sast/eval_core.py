"""B39B6: deterministic testcase/CWE evaluation, never an automatic safety verdict.
All routines are CPU/stdlib only. Labels must be explicitly reviewed and locked.
"""
from __future__ import annotations
from collections import Counter
from copy import deepcopy
from dataclasses import asdict
import math
from typing import Any
from ntk_core import Blocker, CWES, IDENTITY, digest, require

ARMS = ('opengrep_only', 'base', 'epoch_1', 'epoch_2')
POLICY = 'CODEQL_CONTEXTUAL_POLICY_ASSISTED'
MODEL = 'MODEL_DERIVED'
TRUTHS = ('POSITIVE', 'NEGATIVE', 'UNKNOWN')

PROTOCOL = {
    'schema': 'NTK_B39B6_CASE_CWE_EVAL_V1',
    'unit': 'ONE_DECLARED_JAVA_TESTCASE_AND_ITS_TARGET_CWE',
    'scope': 'POSTHOC_DEVELOPMENT_EVALUATION_NOT_INDEPENDENT_GOLD',
    'truth': {'POSITIVE': 'VULNERABILITY_PRESENT_UNDER_REVIEWED_THREAT_MODEL',
              'NEGATIVE': 'TARGET_CWE_ABSENT_UNDER_REVIEWED_ASSUMPTIONS_NOT_UNIVERSAL_SAFETY',
              'UNKNOWN': 'NOT_ADJUDICATED_OR_UNCERTAIN_NOT_A_NEGATIVE'},
    'selectors': {
        'raw_opengrep': 'AT_LEAST_ONE_ORIGIN_OPENGREP_FINDING_SAME_CASE_AND_CWE',
        'any_reported_alert': 'AT_LEAST_ONE_RETAINED_FINDING_SAME_CASE_AND_CWE',
        'qualified_evidence': 'AT_LEAST_ONE_EXPLICIT_QUALIFIED_LINKED_PATH_NOT_ALL_RAW_PATHS',
    },
    'qualified_evidence_for_opengrep_only': 'NOT_APPLICABLE_CODEQL_NOT_RUN',
    'no_evidence_is_safe': False,
    'unknown_policy': 'DETECTION_KNOWN_SUBSET_WITH_COVERAGE; RANKING_WITHHELD_UNTIL_ENTIRE_SCOPE_REVIEWED',
    'ranking_universe': 'ALL_REGISTERED_UNITS; ONLY_ALERTED_UNITS_ARE_RETURNED; MISSED_POSITIVES_REMAIN_IN_RECALL_AP_DENOMINATOR',
    'ranking_score': 'MAX_FROZEN_FINAL_SCORE_PER_CASE_CWE; NO_FINDINGS_MEANS_NOT_RETRIEVED_NOT_SCORE_ZERO',
    'ranking_gain': 'BINARY_POSITIVE_1_NEGATIVE_0',
    'ranking_k': [1, 3, 5, 10],
    'k_larger_than_retrieved': 'NULL_NOT_SILENTLY_CLAMPED',
    'ties': 'SCORE_DESC_THEN_UNIT_SHA_ASC; ALSO_EXACT_EXPECTATION_UNDER_UNIFORM_WITHIN_SCORE_TIES_AND_PRECISION_BOUNDS',
    'average_precision': 'SINGLE_RANKED_LIST_AP_NOT_MAP; DIVIDE_BY_ALL_RELEVANT_REGISTERED_UNITS',
    'ndcg': 'BINARY_DCG_LOG2_RANK_PLUS_1_OVER_IDEAL_ALL_RELEVANT_REGISTERED_UNITS',
    'zero_denominators': 'NULL; F1_DIRECT_2TP_OVER_2TP_FP_FN',
    'aggregation': 'GLOBAL_POOLED_MICRO_PLUS_PER_CWE; MACRO_REPORTS_DEFINED_CWES',
    'score_threshold_tuning': 'NOT_PERFORMED',
    'scorer_weights_changed': False,
    'cwe79_policy_is_lora_gain': False,
    'quality_acceptance_threshold': None,
    'references': [
        'https://nlp.stanford.edu/IR-book/html/htmledition/evaluation-of-unranked-retrieval-sets-1.html',
        'https://nlp.stanford.edu/IR-book/html/htmledition/evaluation-of-ranked-retrieval-results-1.html'],
}


def finite_number(x: Any, lo: float = 0.0, hi: float = 100.0) -> bool:
    return type(x) in (float, int) and math.isfinite(x) and lo <= x <= hi


def unit_id(input_sha: str, uri: str, cwe: str) -> str:
    return digest({'input_sha256': input_sha, 'uri': uri, 'cwe': cwe})


def validate_units(units: list[dict]) -> dict[tuple[str, str], dict]:
    require(isinstance(units, list) and bool(units), 'EMPTY_UNIT_MANIFEST')
    out = {}; ids = set()
    for u in units:
        require(isinstance(u, dict) and all(isinstance(u.get(k), str) and u[k]
                for k in ('unit_id', 'uri', 'cwe', 'source_sha256', 'input_sha256')), 'UNIT_SCHEMA')
        require(u['cwe'] in CWES, 'UNIT_CWE')
        from ntk_core import safe_member
        safe_member(u['uri'])
        require(u['uri'].endswith('.java'), 'UNIT_NOT_JAVA')
        require(u['unit_id'] == unit_id(u['input_sha256'], u['uri'], u['cwe']), 'UNIT_ID_DRIFT')
        key = (u['uri'], u['cwe'])
        require(key not in out and u['unit_id'] not in ids, 'DUPLICATE_UNIT')
        out[key] = u; ids.add(u['unit_id'])
    return out


def normalize_reports(reports: dict, units: list[dict], input_sha: str,
                      scorer: Any = None) -> tuple[dict, dict]:
    """Map real findings without using truths, filenames-as-labels, or model predictions as labels."""
    universe = validate_units(units)
    require(set(reports) == set(ARMS), 'INCOMPLETE_ARM_SET')
    normalized = {}; audits = {}; raw_lineage = {}
    for arm in ARMS:
        report = reports[arm]
        require(report.get('arm') == arm and report.get('input_sha256') == input_sha, 'RESULT_IDENTITY')
        require(report.get('model_xss_gate_granted') is False and report.get('independent_gold') is False, 'RESULT_SCOPE')
        findings = report.get('findings')
        require(isinstance(findings, list), 'FINDINGS_NOT_LIST')
        rows = {u['unit_id']: {'unit_id': u['unit_id'], 'cwe': u['cwe'], 'finding_count': 0,
            'opengrep_count': 0, 'score': None, 'qualified_model': False,
            'qualified_policy': False, 'raw_policy_path_ids': set(),
            'qualified_path_ids': set(), 'model_observation_statuses': Counter()}
            for u in units}
        ids = set(); lineage = {}; used = Counter(); n_replayed = 0
        for f in findings:
            require(isinstance(f, dict) and isinstance(f.get('id'), str), 'FINDING_SCHEMA')
            require(f['id'] not in ids, 'DUPLICATE_FINDING_ID'); ids.add(f['id'])
            require(f.get('retained') is True and f.get('vulnerability_confirmed') is False, 'FINDING_SAFETY_FLAGS')
            loc = f.get('location', {})
            key = (loc.get('uri'), f.get('cwe'))
            require(key in universe, 'UNMAPPED_CASE_OR_CWE_REQUIRES_EXPLICIT_MANIFEST')
            require(type(loc.get('start_line')) is int and loc['start_line'] > 0, 'LOCATION_LINE')
            row = rows[universe[key]['unit_id']]
            score = f.get('score', {})
            require(isinstance(score, dict) and finite_number(score.get('final_score')), 'INVALID_SCORE')
            if scorer is not None:
                require(asdict(scorer.score_finding(deepcopy(f))) == score, 'FROZEN_SCORER_REPLAY_MISMATCH')
                n_replayed += 1
            row['finding_count'] += 1
            row['score'] = score['final_score'] if row['score'] is None else max(row['score'], score['final_score'])
            require(f.get('origin') in ('OPENGREP','CODEQL_ADDITIONAL','CODEQL_POLICY_ADDITIONAL'), 'UNKNOWN_FINDING_ORIGIN')
            if f['origin'] == 'OPENGREP':
                require(isinstance(f.get('original_opengrep'), dict), 'RAW_OPENGREP_MISSING')
                lineage[f['id']] = digest(f['original_opengrep'])
                row['opengrep_count'] += 1
            linked = f.get('linked_codeql_flow_ids')
            flow = f.get('dataflow')
            require(isinstance(linked, list) and all(isinstance(x, str) for x in linked), 'PATH_LINK_SCHEMA')
            require(isinstance(flow, list) and all(isinstance(x, dict) for x in flow), 'DATAFLOW_SCHEMA')
            require(bool(linked) == bool(flow), 'QUALIFIED_LINK_FLOW_DISAGREEMENT')
            require(len(linked) == len(set(linked)), 'DUPLICATE_QUALIFIED_LINK')
            if arm == 'opengrep_only':
                require(f['origin'] == 'OPENGREP' and not linked and f.get('model_observation') is None,
                        'OPENGREP_BASELINE_HAS_MODEL_OR_FLOW')
                require(score.get('ai_confidence_score') == 0.5, 'OPENGREP_BASELINE_NON_NEUTRAL_AI')
            elif f['cwe'] == '79':
                require(f.get('evidence_origin') == POLICY and score.get('ai_confidence_score') == 0.5,
                        'XSS_POLICY_MISATTRIBUTED')
                raw_ids = f.get('raw_policy_flow_ids', [])
                require(isinstance(raw_ids, list) and all(isinstance(x, str) for x in raw_ids), 'RAW_POLICY_IDS')
                require(set(linked).issubset(raw_ids), 'QUALIFIED_POLICY_WITHOUT_RAW_PATH')
                row['raw_policy_path_ids'].update(raw_ids)
            else:
                require(f.get('evidence_origin') == MODEL, 'MODEL_PROVENANCE_MISSING')
            observation = f.get('model_observation')
            if observation is not None:
                require(isinstance(observation, dict) and observation.get('status') in ('ACCEPTED','ABSTAIN'), 'MODEL_OBSERVATION_STATUS')
                row['model_observation_statuses'][observation['status']] += 1
            if linked:
                require(len(flow) >= 2 and flow[0].get('type') == 'source' and flow[-1].get('type') == 'sink', 'INCOMPLETE_QUALIFIED_PATH')
                if f['cwe'] == '79':
                    require(f.get('evidence_status') == 'POLICY_QUALIFIED_UNENCODED_HTML_PATH', 'POLICY_STATUS_NOT_QUALIFIED')
                    row['qualified_policy'] = True
                else:
                    require(f.get('evidence_status') == 'CODEQL_CWE_'+f['cwe']+'_QUALIFIED_PATH', 'MODEL_STATUS_NOT_QUALIFIED')
                    require(observation and observation.get('status') == 'ACCEPTED' and
                            observation.get('label', {}).get('type') == 'sink', 'MODEL_PATH_WITHOUT_ACCEPTED_SINK')
                    require(bool(observation['label'].get('sink_args')), 'MODEL_PATH_WITHOUT_SINK_ARGS')
                    row['qualified_model'] = True
                row['qualified_path_ids'].update(linked)
            used[f['origin']] += 1
        for row in rows.values():
            row['raw_opengrep'] = row['opengrep_count'] > 0
            row['any_reported_alert'] = row['finding_count'] > 0
            row['qualified_evidence'] = row['qualified_model'] or row['qualified_policy']
            row['raw_policy_paths'] = len(row.pop('raw_policy_path_ids'))
            row['qualified_paths'] = len(row.pop('qualified_path_ids'))
            row['model_observation_statuses'] = dict(row['model_observation_statuses'])
        normalized[arm] = sorted(rows.values(), key=lambda x: x['unit_id'])
        audits[arm] = {'findings': len(findings), 'origins': dict(used), 'scorer_replayed': n_replayed,
            'mapping_unassigned_findings': 0, 'case_cwe_units': len(rows),
            'alerted_units': sum(r['any_reported_alert'] for r in rows.values()),
            'qualified_model_units': sum(r['qualified_model'] for r in rows.values()),
            'qualified_policy_units': sum(r['qualified_policy'] for r in rows.values()),
            'observation_counts_are_finding_level_not_unique_api_predictions': True}
        raw_lineage[arm] = lineage
    require(all(x == raw_lineage['opengrep_only'] for x in raw_lineage.values()), 'CROSS_ARM_RAW_FINDINGS_NOT_IDENTICAL')
    policy_views = []
    for arm in ARMS[1:]:
        policy_views.append([{k: r[k] for k in ('unit_id','score','qualified_policy','raw_policy_paths','qualified_paths')}
                             for r in normalized[arm] if r['cwe'] == '79'])
    require(all(v == policy_views[0] for v in policy_views), 'CWE79_POLICY_NOT_SHARED')
    return normalized, {'arms': audits, 'raw_opengrep_preserved': True, 'policy79_shared': True,
        'numeric_scorer_modified': False, 'label_based_predictions': False}


def initial_labels(units: list[dict]) -> list[dict]:
    return [dict(unit_id=u['unit_id'], cwe=u['cwe'], source_sha256=u['source_sha256'],
                 truth='UNKNOWN', review_status='UNREVIEWED', reviewer='', reviewed_at='', rationale='',
                 evidence_lines=[], assumptions='', provenance='POSTHOC_DEVELOPMENT_REVIEW',
                 predictions_exposed_before_review=True) for u in sorted(units, key=lambda x: x['unit_id'])]


def validate_labels(units: list[dict], labels: list[dict], for_lock: bool = False) -> dict[str, dict]:
    validate_units(units)
    require(isinstance(labels, list), 'LABELS_NOT_LIST')
    by_id = {u['unit_id']: u for u in units}; out = {}
    for label in labels:
        require(isinstance(label, dict), 'LABEL_NOT_OBJECT')
        ident = label.get('unit_id')
        require(ident in by_id and ident not in out, 'LABEL_ID_SET_OR_DUPLICATE')
        u = by_id[ident]
        require(label.get('cwe') == u['cwe'] and label.get('source_sha256') == u['source_sha256'], 'LABEL_SOURCE_OR_CWE_DRIFT')
        require(label.get('truth') in TRUTHS, 'UNKNOWN_TRUTH_VALUE')
        require(label.get('provenance') == 'POSTHOC_DEVELOPMENT_REVIEW' and
                label.get('predictions_exposed_before_review') is True, 'CANNOT_UPGRADE_DEVELOPMENT_TO_GOLD')
        require(label.get('review_status') in ('UNREVIEWED','REVIEWED'), 'REVIEW_STATUS')
        for k in ('reviewer','reviewed_at','rationale','assumptions'):
            require(isinstance(label.get(k), str) and len(label[k]) <= 8000, 'REVIEW_FIELD_SCHEMA')
        lines = label.get('evidence_lines')
        require(isinstance(lines, list) and all(type(x) is int and x > 0 for x in lines), 'EVIDENCE_LINES')
        if label['truth'] != 'UNKNOWN' or label['review_status'] == 'REVIEWED':
            require(label['review_status'] == 'REVIEWED' and bool(label['reviewer'].strip()) and
                bool(label['reviewed_at'].strip()) and bool(label['rationale'].strip()) and
                bool(label['assumptions'].strip()) and bool(lines), 'REVIEW_EVIDENCE_REQUIRED')
            from datetime import datetime
            try:
                when = datetime.fromisoformat(label['reviewed_at'].replace('Z', '+00:00'))
                require(when.utcoffset() is not None, 'REVIEW_TIMEZONE_REQUIRED')
            except (ValueError, TypeError):
                raise Blocker('REVIEW_TIMESTAMP_INVALID') from None
            require(max(lines) <= u.get('source_line_count', max(lines)), 'REVIEW_LINE_OUTSIDE_SOURCE')
        if for_lock:
            require(label['review_status'] == 'REVIEWED', 'ALL_UNITS_MUST_BE_REVIEWED_OR_EXPLICITLY_UNKNOWN')
        out[ident] = label
    require(set(out) == set(by_id), 'LABEL_ID_SET_INCOMPLETE')
    return out


def ratio(num: float, den: float) -> float | None:
    return num/den if den else None


def counts_metric(c: dict) -> dict:
    tp, fp, fn, tn = (c[k] for k in ('tp','fp','fn','tn'))
    return {**c, 'precision': ratio(tp, tp+fp), 'recall': ratio(tp, tp+fn),
        'f1': ratio(2*tp, 2*tp+fp+fn), 'specificity': ratio(tn, tn+fp),
        'positive_support': tp+fn, 'negative_support': tn+fp}


def detection(rows: list[dict], labels: dict, selector: str) -> dict:
    c = dict(tp=0, fp=0, fn=0, tn=0); unknown = 0
    for r in rows:
        y = labels[r['unit_id']]['truth']
        require(type(r[selector]) is bool, 'PREDICTION_NOT_BOOLEAN')
        if y == 'UNKNOWN': unknown += 1; continue
        if y == 'POSITIVE': c['tp' if r[selector] else 'fn'] += 1
        else: c['fp' if r[selector] else 'tn'] += 1
    return {'universe': len(rows), 'unknown': unknown, 'reviewed_binary': len(rows)-unknown,
        'reviewed_fraction': ratio(len(rows)-unknown, len(rows)),
        'denominator_scope': 'ALL_UNITS' if not unknown else 'REVIEWED_BINARY_SUBSET_NOT_FULL_DATASET',
        'not_retrieved_is_not_runtime_safe_verdict': True, **counts_metric(c)}


def ranking(rows: list[dict], labels: dict, ks: list[int]) -> dict:
    require(all(type(k) is int and k > 0 for k in ks) and len(ks) == len(set(ks)), 'INVALID_K_VALUES')
    if not rows:
        return {'status': 'NOT_COMPUTABLE_EMPTY_UNIVERSE', 'metrics': None}
    unknown = sum(labels[r['unit_id']]['truth'] == 'UNKNOWN' for r in rows)
    if unknown:
        return {'status': 'WITHHELD_UNREVIEWED_UNITS', 'unknown': unknown, 'universe': len(rows), 'metrics': None}
    for r in rows:
        require((r['score'] is None and not r['any_reported_alert']) or
                (finite_number(r['score']) and r['any_reported_alert']), 'RANKING_SCORE_PRESENCE')
    ordered = sorted((r for r in rows if r['any_reported_alert']), key=lambda r: (-r['score'], r['unit_id']))
    gains = [int(labels[r['unit_id']]['truth'] == 'POSITIVE') for r in ordered]
    total_positive = sum(labels[r['unit_id']]['truth'] == 'POSITIVE' for r in rows)
    expected_gains = []; groups = []; offset = 0; before_positive = 0; exp_ap_sum = 0.0
    while offset < len(ordered):
        end = offset+1
        while end < len(ordered) and ordered[end]['score'] == ordered[offset]['score']: end += 1
        n = end-offset; m = sum(gains[offset:end]); p = m/n
        groups.append({'offset': offset, 'size': n, 'positives': m, 'score': ordered[offset]['score']})
        expected_gains.extend([p]*n)
        for j in range(1,n+1):
            second = (j-1)*m*(m-1)/(n*(n-1)) if n > 1 else 0.0
            exp_ap_sum += ((before_positive+1)*p+second)/(offset+j)
        before_positive += m; offset = end
    seen = 0; ap_sum = 0.0
    for i, g in enumerate(gains, 1):
        seen += g
        if g: ap_sum += seen/i
    topk = {}
    for k in ks:
        if k > len(ordered):
            topk[str(k)] = {'status': 'INSUFFICIENT_RETRIEVED_K', 'requested_k': k, 'retrieved': len(ordered), 'metrics': None}
            continue
        hits = sum(gains[:k]); ehits = sum(expected_gains[:k])
        lower = upper = 0
        for group in groups:
            take = max(0, min(group['size'], k-group['offset']))
            if not take: continue
            n, m = group['size'], group['positives']
            lower += max(0, take-(n-m)); upper += min(take, m)
        dcg = sum(g/math.log2(i+2) for i,g in enumerate(gains[:k]))
        expected_dcg = sum(g/math.log2(i+2) for i,g in enumerate(expected_gains[:k]))
        ideal = sum(1/math.log2(i+2) for i in range(min(k,total_positive)))
        topk[str(k)] = {'status': 'COMPUTED', 'precision': hits/k, 'recall': ratio(hits,total_positive),
            'ndcg_binary': ratio(dcg,ideal), 'tie_expected_precision': ehits/k,
            'tie_expected_recall': ratio(ehits,total_positive), 'tie_expected_ndcg_binary': ratio(expected_dcg,ideal),
            'within_tie_precision_min': lower/k, 'within_tie_precision_max': upper/k}
    return {'status': 'COMPUTED', 'universe':len(rows), 'retrieved':len(ordered),
        'positive_support':total_positive, 'positive_not_retrieved': total_positive-sum(gains),
        'ap_single_list_not_map':ratio(ap_sum,total_positive),
        'tie_expected_ap':ratio(exp_ap_sum,total_positive),
        'tie_groups_with_multiple_units':sum(g['size']>1 for g in groups), 'top_k':topk}


def evaluate_vectors(vectors: dict, units: list[dict], labels: list[dict], protocol: dict) -> dict:
    require(protocol == PROTOCOL, 'EVAL_PROTOCOL_DRIFT')
    reference = validate_labels(units,labels, for_lock=True)
    require(set(vectors) == set(ARMS), 'MISSING_ARM_NOT_EMPTY_OUTPUT')
    expected_ids = {u['unit_id']:u['cwe'] for u in units}
    for arm, rows in vectors.items():
        require(len(rows) == len(expected_ids) and {r['unit_id']:r['cwe'] for r in rows} == expected_ids,
                'MISSING_OR_DUPLICATE_PREDICTION_UNIT')
    outputs = {}
    for arm, rows in vectors.items():
        per_scope = {}
        for scope in ('all', *CWES):
            sub = rows if scope=='all' else [r for r in rows if r['cwe']==scope]
            selectors = {}
            for selector in PROTOCOL['selectors']:
                selectors[selector] = ({'status':'NOT_APPLICABLE_CODEQL_NOT_RUN','metrics':None}
                    if arm=='opengrep_only' and selector=='qualified_evidence'
                    else detection(sub,reference,selector))
            per_scope[scope] = {'detection':selectors,'ranking':ranking(sub,reference,protocol['ranking_k'])}
        macros = {}
        for selector in PROTOCOL['selectors']:
            macros[selector] = {}
            for metric in ('precision','recall','f1'):
                present = {c:per_scope[c]['detection'][selector].get(metric) for c in CWES}
                present = {c:v for c,v in present.items() if v is not None}
                macros[selector][metric] = {'value': sum(present.values())/len(present) if present else None,
                    'defined_cwes':sorted(present), 'count':len(present)}
        outputs[arm] = {'scopes':per_scope, 'macro_across_defined_cwes':macros}
    return {'schema':PROTOCOL['schema'], 'scope':PROTOCOL['scope'], 'independent_gold':False,
        'protocol_sha256':digest(protocol), 'units':len(units),
        'truth_counts':dict(Counter(x['truth'] for x in labels)), 'arms':outputs,
        'contribution_caveat':'CWE79_POLICY_IS_NOT_LORA_GAIN; OPENGREP_TO_HYBRID_IS_NOT_AN_ADAPTER_ONLY_ABLATION',
        'runtime_verdicts_modified':False, 'new_inference':False, 'new_codeql':False}
