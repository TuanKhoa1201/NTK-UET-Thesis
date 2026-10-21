from __future__ import annotations
import contextlib
import json
import os
from pathlib import Path
import sys
import time
import traceback
if __package__:
    from .common import Blocker, ADAPTER_CONFIG_SHA, ADAPTER_SHA, deny_inet, digest, sha_file
else:
    sys.path.insert(0, str(Path(__file__).parent))
    from common import Blocker, ADAPTER_CONFIG_SHA, ADAPTER_SHA, deny_inet, digest, sha_file


def emit(value):
    sys.stdout.write(json.dumps(value, ensure_ascii=False) + '\n')
    sys.stdout.flush()


def main():
    cfg = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
    for key in ('HF_HUB_OFFLINE', 'TRANSFORMERS_OFFLINE', 'HF_HUB_DISABLE_TELEMETRY'):
        os.environ[key] = '1'
    os.environ['TOKENIZERS_PARALLELISM'] = 'false'
    isolation = deny_inet()
    started = time.monotonic()
    with contextlib.redirect_stdout(sys.stderr):
        import torch
        import transformers
        import peft
        import accelerate
        from transformers import AutoTokenizer, AutoModelForCausalLM, StoppingCriteria, StoppingCriteriaList
        from peft import PeftModel
        versions = dict(torch=torch.__version__.split('+')[0], transformers=transformers.__version__,
                        peft=peft.__version__, accelerate=accelerate.__version__)
        if versions != cfg['runtime_versions']:
            raise Blocker('ML_RUNTIME_VERSION_DRIFT: ' + repr(versions))
        if not torch.cuda.is_available():
            raise Blocker('CUDA_UNAVAILABLE_NO_SILENT_CPU_FALLBACK')
        torch.set_num_threads(2)
        generation = cfg['generation']
        torch.manual_seed(generation['seed'])
        torch.cuda.manual_seed_all(generation['seed'])
        base = Path(cfg['base_dir']).resolve()
        if not base.is_dir():
            raise Blocker('LOCAL_BASE_MISSING')
        tokenizer = AutoTokenizer.from_pretrained(str(base), local_files_only=True, trust_remote_code=False)
        model = AutoModelForCausalLM.from_pretrained(
            str(base), local_files_only=True, trust_remote_code=False, use_safetensors=True,
            torch_dtype=torch.float16, attn_implementation=generation['attention'],
            low_cpu_mem_usage=True,
        )
        total_base_params = sum(p.numel() for p in model.parameters())
        if not 100_000_000 < total_base_params < 700_000_000:
            raise Blocker('EXPECTED_0_5B_BASE_PARAMETER_COUNT_GUARD')
        if cfg['arm'] != 'base':
            adapter = Path(cfg['adapter_dir'])
            if sha_file(adapter / 'adapter_model.safetensors') != ADAPTER_SHA[cfg['arm']]:
                raise Blocker('ADAPTER_WEIGHT_SHA_MISMATCH')
            if sha_file(adapter / 'adapter_config.json') != ADAPTER_CONFIG_SHA:
                raise Blocker('ADAPTER_CONFIG_SHA_MISMATCH')
            model = PeftModel.from_pretrained(model, str(adapter), is_trainable=False,
                                             local_files_only=True)
        model = model.to('cuda').eval()
        for param in model.parameters():
            param.requires_grad_(False)
        torch.cuda.synchronize()
        trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
        if trainable != 0:
            raise Blocker('INFERENCE_MUST_NOT_HAVE_TRAINABLE_PARAMETERS')
    emit({'ready': True, 'versions': versions, 'isolation': isolation,
          'arm': cfg['arm'], 'device': torch.cuda.get_device_name(0),
          'load_s': time.monotonic() - started, 'base_parameters': total_base_params,
          'trainable_parameters': trainable, 'tokenizer_chat_template_sha256': digest(tokenizer.chat_template),
          'training_executed': False})

    class Deadline(StoppingCriteria):
        def __init__(self, deadline):
            self.deadline = deadline
        def __call__(self, input_ids, scores, **kwargs):
            if time.monotonic() > self.deadline:
                raise TimeoutError('PER_REQUEST_GENERATION_DEADLINE')
            return False

    for line in sys.stdin:
        if not line.strip():
            continue
        began = time.monotonic()
        try:
            request = json.loads(line)
            messages = request['messages']
            with contextlib.redirect_stdout(sys.stderr), torch.inference_mode():
                rendered = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
                tokens = tokenizer(rendered, add_special_tokens=False, return_tensors='pt')
                input_tokens = tokens['input_ids'].shape[-1]
                if input_tokens > generation['max_input_tokens']:
                    raise Blocker('PROMPT_TOO_LONG_NO_SILENT_TRUNCATION')
                ids_sha = digest(tokens['input_ids'][0].tolist())
                tokens = {k: v.to('cuda') for k, v in tokens.items()}
                torch.cuda.reset_peak_memory_stats()
                output = model.generate(
                    **tokens, do_sample=False, max_new_tokens=generation['max_new_tokens'],
                    pad_token_id=tokenizer.eos_token_id,
                    stopping_criteria=StoppingCriteriaList([Deadline(began + generation['generation_timeout_s'])]),
                )
                torch.cuda.synchronize()
                generated = output[0, input_tokens:]
                raw = tokenizer.decode(generated, skip_special_tokens=True)
                result = {'ok': True, 'raw': raw, 'generation_s': time.monotonic() - began,
                          'input_tokens': input_tokens, 'output_tokens': len(generated),
                          'input_token_ids_sha256': ids_sha,
                          'peak_vram_allocated_bytes': torch.cuda.max_memory_allocated(),
                          'peak_vram_reserved_bytes': torch.cuda.max_memory_reserved()}
                del output, generated, tokens
            emit(result)
        except Exception as exc:
            kind = 'CUDA_OOM' if isinstance(exc, torch.cuda.OutOfMemoryError) else type(exc).__name__
            traceback.print_exc(file=sys.stderr)
            emit({'ok': False, 'error_kind': kind, 'error': str(exc),
                  'elapsed_s': time.monotonic() - began})
            # An error must be a blocker, not a stream of invented "none" labels.
            break


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        traceback.print_exc(file=sys.stderr)
        emit({'ready': False, 'error_kind': type(exc).__name__, 'error': str(exc)})
        sys.exit(2)
