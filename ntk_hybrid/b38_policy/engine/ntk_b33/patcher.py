from __future__ import annotations
import ast
import difflib
import hashlib
from pathlib import Path
from .common import Blocker, IRIS_BLOB, digest

STAGE3 = 'query_gpt_for_api_src_tp_sink_batched'
DISPATCH = '_stage3_predict_with_exact_cache'


def method_spans(text: str):
    tree = ast.parse(text)
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'SAPipeline')
    return {n.name: n for n in cls.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def fragment(text: str, node) -> str:
    return ''.join(text.splitlines(keepends=True)[node.lineno - 1:node.end_lineno])


def once(text: str, old: str, new: str) -> str:
    if text.count(old) != 1:
        raise Blocker('PATCH_ANCHOR_NOT_UNIQUE: ' + repr(old[:100]))
    return text.replace(old, new, 1)


def native_system_prompt(source: str) -> str:
    node = method_spans(source)[STAGE3]
    choices = [n.value.value for n in ast.walk(node)
               if isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant)
               and isinstance(n.value.value, str)
               and any(isinstance(t, ast.Name) and t.id == 'system_prompt' for t in n.targets)]
    if len(choices) != 1 or 'exactly ONE API' not in choices[0]:
        raise Blocker('NATIVE_SINGLE_API_SYSTEM_PROMPT_NOT_FOUND')
    return choices[0]


def patch_source(source: str, *, verify_blob: bool = True) -> tuple[str, dict]:
    original = source.encode('utf-8')
    actual_blob = hashlib.sha1(b'blob ' + str(len(original)).encode() + b'\0' + original).hexdigest()
    if verify_blob and actual_blob != IRIS_BLOB:
        raise Blocker('FROZEN_IRIS_BLOB_MISMATCH: ' + actual_blob)
    if '_ntk_get_stage3_provider' in source:
        raise Blocker('Snapshot already patched; create a new versioned run')
    methods = method_spans(source)
    before = {name: digest(fragment(source, node)) for name, node in methods.items()}
    body = fragment(source, methods[STAGE3])
    first_line, rest = body.split('\n', 1)
    body = first_line + '\n' + '''        # NTK_B33: isolated provider; legacy Stage 4/get_model remain untouched.
        ntk_provider = self._ntk_get_stage3_provider()
        ntk_stage3 = ntk_provider is not None
        if ntk_stage3:
            ntk_provider.begin(self)
''' + rest
    body = once(body, '            not self._resume_valid_stage3_bundle()',
                '            ntk_stage3\n            or not self._resume_valid_stage3_bundle()')
    body = once(body, '            if self.overwrite_llm_cache:',
                '            if ntk_stage3 or self.overwrite_llm_cache:')
    old_if = '            if self.llm.lower().startswith("ollama"):'
    # Only system prompt and one-API batching; not the legacy normalization block.
    if body.count(old_if) != 3:
        raise Blocker('Unexpected number of Stage 3 Ollama branches')
    body = body.replace(old_if, '            if ntk_stage3 or self.llm.lower().startswith("ollama"):', 2)
    body = body.replace('"  ==> Ollama Stage 3 batch size forced to 1 "',
                        '"  ==> Local Stage 3 batch size forced to 1 "')
    body = once(body, '                prompt = process_candidate_batch(i)', '''                prompt = process_candidate_batch(i)
                if ntk_stage3:
                    ntk_provider.prepare(to_query_candidates[i], self.cwe_id, prompt)''')
    body = once(body, '                json_result = self.parse_json(response)', '''                if ntk_stage3:
                    json_result = ntk_provider.validate_response(response, self.cwe_id)
                else:
                    json_result = self.parse_json(response)''')
    body = once(body, '                if self.llm.lower().startswith("ollama"):',
                '                if not ntk_stage3 and self.llm.lower().startswith("ollama"):')
    body = once(body, '            merged_llm_results=self.filter_invalid_entries(merged_llm_results)',
                '            if not ntk_stage3:\n                merged_llm_results=self.filter_invalid_entries(merged_llm_results)')
    body = once(body, '            merged_overall_results = self.merge_llm_labeled_apis_and_cache(candidates, merged_llm_results)',
                '''            merged_overall_results = (
                merged_llm_results if ntk_stage3 else
                self.merge_llm_labeled_apis_and_cache(candidates, merged_llm_results)
            )''')
    body = once(body, '            if not self.test_run:\n                self.cache_llm_results(',
                '            if not self.test_run and not ntk_stage3:\n                self.cache_llm_results(')
    body = body.rstrip() + '\n        if ntk_stage3:\n            ntk_provider.finish(self)\n'
    dispatch = fragment(source, methods[DISPATCH])
    # Insert before any call to get_model; only this Stage 3 dispatcher is changed.
    dispatch = once(dispatch, '        model = self.get_model()', '''        ntk_provider = self._ntk_get_stage3_provider()
        if ntk_provider is not None:
            return ntk_provider.predict_cached(prompt, self.cwe_id)

        model = self.get_model()''')
    lines = source.splitlines(keepends=True)
    changes = [(methods[STAGE3], body), (methods[DISPATCH], dispatch)]
    for node, content in sorted(changes, key=lambda pair: pair[0].lineno, reverse=True):
        lines[node.lineno - 1:node.end_lineno] = [content]
    changed = ''.join(lines)
    # Class-local getter is activated only by an explicit provider/config.
    getter = '''    def _ntk_get_stage3_provider(self):
        provider = getattr(self, "_ntk_stage3_provider", None)
        if provider is not None:
            return provider
        config_path = os.environ.get("NTK_STAGE3_CONFIG")
        if not config_path:
            return None
        from src.ntk_stage3_native.provider import NativeProvider
        provider = NativeProvider.from_config(config_path)
        self._ntk_stage3_provider = provider
        return provider

'''
    changed = once(changed, '    def get_model(self):\n', getter + '    def get_model(self):\n')
    after_nodes = method_spans(changed)
    untouched = {}
    for name, old_hash in before.items():
        if name not in (STAGE3, DISPATCH):
            new_hash = digest(fragment(changed, after_nodes[name]))
            if old_hash != new_hash:
                raise Blocker('UNEXPECTED_CHANGE_OUTSIDE_STAGE3: ' + name)
            untouched[name] = new_hash
    return changed, {
        'original_git_blob': actual_blob,
        'changed_existing_methods': [STAGE3, DISPATCH],
        'added_method': '_ntk_get_stage3_provider',
        'unchanged_method_hashes': untouched,
        'stage4_and_get_model_body_unchanged': all(k in untouched for k in (
            'get_model', '_stage4_predict_with_exact_cache', 'query_gpt_for_func_param_src')),
        'native_system_prompt': native_system_prompt(source),
    }


def apply(snapshot: Path, payload: Path) -> dict:
    import shutil
    source_path = snapshot / 'src/iris.py'
    before = source_path.read_text(encoding='utf-8')
    after, report = patch_source(before)
    source_path.write_text(after, encoding='utf-8')
    target = snapshot / 'src/ntk_stage3_native'
    target.mkdir(exist_ok=False)
    for name in ('__init__.py', 'common.py', 'provider.py', 'worker.py'):
        shutil.copy2(payload / 'ntk_b33' / name, target / name)
    report['diff'] = ''.join(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                                               'a/src/iris.py', 'b/src/iris.py'))
    return report
