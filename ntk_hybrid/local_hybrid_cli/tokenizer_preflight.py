#!/usr/bin/env python3
"""CPU tokenizer-only preflight: no model loading, training, or GPU generation."""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
from ntk_core import IDENTITY, digest, loads, require, write_json
from vendor.common import deny_inet


def tokenize_cases(tok,cases,max_input_tokens):
    rows=[]
    for case in cases:
        messages=case['expected_messages']
        require(len(messages)==2 and [m['role'] for m in messages]==['system','user'],'TOKENIZER_INPUT_HAS_TARGET')
        rendered=tok.apply_chat_template(messages,tokenize=False,add_generation_prompt=True)
        ids=tok(rendered,add_special_tokens=False)['input_ids']
        require(len(ids)<=max_input_tokens,'NATIVE_PROMPT_EXCEEDS_TOKEN_LIMIT_NO_TRUNCATION')
        rows.append({'case_key':digest([case['cwe'],[case[k] for k in IDENTITY]]),
                     'prompt_sha256':digest(messages),'input_tokens':len(ids),'input_token_ids_sha256':digest(ids)})
    return rows


def main():
    cfg=loads(Path(sys.argv[1]).read_bytes())
    isolation=deny_inet()
    import transformers
    from transformers import AutoTokenizer
    require(transformers.__version__==cfg['runtime_versions']['transformers'],'TOKENIZER_TRANSFORMERS_VERSION_DRIFT')
    tok=AutoTokenizer.from_pretrained(cfg['base_dir'],local_files_only=True,trust_remote_code=False)
    rows=tokenize_cases(tok,cfg['cases'],cfg['generation']['max_input_tokens'])
    write_json(Path(sys.argv[2]),{'status':'TOKENIZER_CPU_PREFLIGHT_COMPLETE','n':len(rows),
        'maximum_input_tokens':max(r['input_tokens'] for r in rows),
        'token_limit':cfg['generation']['max_input_tokens'],'rows':rows,
        'tokenizer_chat_template_sha256':digest(tok.chat_template),'isolation':isolation,
        'model_loaded':False,'gpu_generation':'NOT_EXECUTED','target_messages_sent':False})


if __name__=='__main__':main()
