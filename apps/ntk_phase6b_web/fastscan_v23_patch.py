#!/usr/bin/env python3
"""Deterministic fail-closed speed guard for the byte-pinned experimental Fast E1 runner.

No dataflow semantic expansion; may skip only a query proved unable to return
any JDK java.lang.System.getenv(String) source in the uploaded Java sources.
Original accepted runner, its four-arm comparator, and B38 gates stay untouched.
"""
from __future__ import annotations
import ast
import hashlib
from pathlib import Path

BASE_SHA = '4ccc5dae1083085412bf5900bd1b89d72d8a453f07d85fece431d8515530c82c'
RESEARCH_SHA = 'b74075eb834ef563af235c183f82d7ba855adf36dd4d9198b85e63d08e274e1e'
POLICY_PINS = {
    'NtkScope.qll': '80bdc103c34eabb4b0f24f46b936715c79f06576fd251c7778669cd829d51ece',
    'Source.template': '25191def624031b11f0a9c0c9d98a72ead348dcbf1e0dd7c274dc924b02ec6c3',
    'Flow.template': '3459e7a9ba7684e23a461f8df31782224c917b4355db92ef61460eee8aaf72df',
}

# Text inserted into the new runner; cannot rely on side files being importable
# because the native runner uses isolated Python execution (-I).
GUARD = '''def _ntkfast_source_absence_proof(target, qp, pins=None):
    """Conservative, pinned proof: zero JDK getenv sources among uploaded .java.

    This is NOT a generic Java taint source finder and NOT a proof that the
    program is secure. Uncertainty always executes original CodeQL queries.
    """
    import hashlib
    from pathlib import Path
    expected = pins if pins is not None else {
        'NtkScope.qll': '80bdc103c34eabb4b0f24f46b936715c79f06576fd251c7778669cd829d51ece',
        'Source.template': '25191def624031b11f0a9c0c9d98a72ead348dcbf1e0dd7c274dc924b02ec6c3',
        'Flow.template': '3459e7a9ba7684e23a461f8df31782224c917b4355db92ef61460eee8aaf72df',
    }
    result = {'guard':'PINNED_SOURCE_POLICY_NO_ENV_FAST_PATH',
              'env_source_proven_absent':False, 'query_pins_verified':False,
              'skips_only_cwes':['22','78','89'],
              'no_source_is_not_safe':True,
              'model_inference_still_executed_if_candidates':True,
              'verified_java_files':0, 'source_sha256':{},
              'query_sha256':{}, 'reason':'GUARD_UNAVAILABLE_RUN_FULL_CODEQL'}
    try:
        qp, target = Path(qp), Path(target)
        for name, expected_sha in expected.items():
            p=qp/name
            if not p.is_file() or p.is_symlink():
                result['reason']='QUERY_MISSING_OR_LINKED'
                return result
            observed=hashlib.sha256(p.read_bytes()).hexdigest()
            result['query_sha256'][name]=observed
            if observed != expected_sha:
                result['reason']='QUERY_PIN_DRIFT_RUN_FULL_CODEQL'
                return result
        result['query_pins_verified']=True
        files=sorted(target.rglob('*.java'))
        if not 1 <= len(files) <= 24:
            result['reason']='JAVA_COUNT_OUT_OF_SCOPE_RUN_FULL_CODEQL'
            return result
        total=0
        for p in files:
            if p.is_symlink() or not p.is_file():
                result['reason']='JAVA_LINK_OR_NONFILE_RUN_FULL_CODEQL'
                return result
            raw=p.read_bytes()
            total+=len(raw)
            if len(raw)>2*1024*1024 or total>16*1024*1024:
                result['reason']='JAVA_INPUT_TOO_LARGE_RUN_FULL_CODEQL'
                return result
            result['verified_java_files']+=1
            result['source_sha256'][str(p.relative_to(target))]=hashlib.sha256(raw).hexdigest()
            # A JDK System.getenv(String) call must lexically include the ASCII
            # method identifier 'getenv' unless Java Unicode escapes are used.
            # Any Unicode escape possibility -> fail closed, even in comments.
            if b'getenv' in raw or b'\\\\u' in raw:
                result['reason']='POSSIBLE_ENV_SOURCE_OR_UNICODE_ESCAPE_RUN_FULL_CODEQL'
                return result
        result['env_source_proven_absent']=True
        result['reason']='NO_GETENV_IDENTIFIER_OR_UNICODE_ESCAPE_IN_PINNED_JAVA_INPUT'
        return result
    except (OSError,ValueError):
        result['reason']='SOURCE_GUARD_IO_UNCERTAIN_RUN_FULL_CODEQL'
        return result

'''


class PatchRejected(RuntimeError):
    pass


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def exactly_once(src: str, old: str, new: str, label: str) -> str:
    n=src.count(old)
    if n!=1:
        raise PatchRejected(f'REFUSE_SOURCE_ANCHOR_{label}_COUNT_{n}')
    return src.replace(old,new,1)


def upgrade_text(src: str) -> str:
    """Only two CodeQL shortcuts, source provenance, and a zero-candidate repair."""
    src=exactly_once(src, '\ndef main(argv=None):\n', '\n'+GUARD+'def main(argv=None):\n', 'INSTALL_PROOF')
    src=exactly_once(src,
        "        sources={c:[] for c in CWES}\n        for c in active_cwes:\n            extract_query('Sources_'+c)\n            sources[c]=rp.tagged(rp.read_calls(private/('Sources_'+c+'.csv'),target)[1],c)\n",
        """        fast_source_proof=_ntkfast_source_absence_proof(target,qp)
        fast_no_env=fast_source_proof['env_source_proven_absent']
        fast_source_proof['skipped_source_queries']=[c for c in active_cwes if fast_no_env and c in ('22','78','89')]
        write_json(run/'FAST_SOURCE_ABSENCE_PROOF.json',fast_source_proof)
        print('FAST_ENV_SOURCE_PROOF='+('ABSENT' if fast_no_env else 'FALLBACK_FULL_CODEQL'),flush=True)
        sources={c:[] for c in CWES}
        for c in active_cwes:
            if fast_no_env and c in ('22','78','89'):
                continue  # Exact compiler source policy cannot yield a getenv source.
            extract_query('Sources_'+c)
            sources[c]=rp.tagged(rp.read_calls(private/('Sources_'+c+'.csv'),target)[1],c)
""", 'SKIP_VERIFIED_EMPTY_SOURCE_QUERY')
    src=exactly_once(src,
        "                    if c=='79' or not eligible:\n",
        "                    if c=='79' or not eligible or (fast_no_env and c in ('22','78','89')):\n",
        'SKIP_IMPOSSIBLE_ENV_DATAFLOW')
    src=exactly_once(src,
        "                    per_cwe[c]={'qualified_paths':len(flows),'model_only_paths':len(model_flows),\n                        'evidence_origin':POLICY if c=='79' else MODEL,'candidates':len(cases[c]),'sources':len(sources[c])}\n",
        """                    per_cwe[c]={'qualified_paths':len(flows),'model_only_paths':len(model_flows),
                        'evidence_origin':POLICY if c=='79' else MODEL,'candidates':len(cases[c]),'sources':len(sources[c]),
                        'source_query_skipped_proven_absent':bool(fast_no_env and c in ('22','78','89')),
                        'dataflow_query_skipped_proven_absent':bool(fast_no_env and c in ('22','78','89') and eligible)}
""", 'EVIDENCE_QUERY_PROVENANCE')
    # The V2.2 generator left this second native_inputs(flattened) call following
    # its already conditional assignment. It blocks the zero-candidate branch.
    src=exactly_once(src,
        "        flattened=[x for c in CWES for x in cases[c]];raw_cases=native_inputs(flattened)\n        astproof=rp.bind_ast",
        "        # Do not re-run native_inputs([]): zero-candidate raw-only output is valid.\n        astproof=rp.bind_ast",
        'ZERO_CANDIDATE_DUPLICATE')
    ast.parse(src,filename='run_fastscan.py')
    if src.count('FAST_SOURCE_ABSENCE_PROOF.json')!=1 or 'FOUR_PROFILE_COMPARISON_REQUIRES_CANDIDATES_IN_EACH_CWE' in src:
        raise PatchRejected('POST_PATCH_SEMANTIC_CHECK_FAILED')
    return src


def upgrade_bytes(raw: bytes) -> bytes:
    if sha(raw)!=BASE_SHA:
        raise PatchRejected('REFUSE_FAST_RUNNER_SOURCE_HASH_DRIFT')
    return upgrade_text(raw.decode('utf-8')).encode('utf-8')
