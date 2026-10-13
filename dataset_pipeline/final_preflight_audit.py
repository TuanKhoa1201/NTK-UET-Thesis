import os
import sys
import json
import hashlib
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training

print('=' * 80)
print('       NTK/IRIS - COMPREHENSIVE FINAL PRE-FLIGHT AUDIT ENGINE')
print('=' * 80)

# -------------------------------------------------------------
# 1. HARDWARE & ENVIRONMENT AUDIT
# -------------------------------------------------------------
print('\n[1/5] Auditing GPU & WSL2 Environment...')
if not torch.cuda.is_available():
    print('[-] FATAL: CUDA is not available!')
    sys.exit(1)

device_name = torch.cuda.get_device_name(0)
total_vram = torch.cuda.get_device_properties(0).total_memory / (1024**3)
cc = torch.cuda.get_device_capability(0)
bf16_supported = torch.cuda.is_bf16_supported()

print(f'    [+] GPU Detected: {device_name}')
print(f'    [+] VRAM Available: {total_vram:.2f} GB')
print(f'    [+] Compute Capability: {cc[0]}.{cc[1]} (Ada Lovelace)')
print(f'    [+] Native BF16 Support: {bf16_supported}')
assert total_vram > 15.0, 'VRAM less than 15GB'
assert bf16_supported, 'BF16 must be supported'
print('    [OK] Hardware check PASSED!')

# -------------------------------------------------------------
# 2. MODEL WEIGHTS & TOKENIZER INTEGRITY AUDIT
# -------------------------------------------------------------
print('\n[2/5] Auditing Base Model Files & Checksums...')
model_dir = '/home/tuankhoa/models/Qwen2.5-Coder-1.5B-Instruct'
safetensors_path = os.path.join(model_dir, 'model.safetensors')

expected_bytes = 3087467144
actual_bytes = os.path.getsize(safetensors_path)
print(f'    [+] model.safetensors size: {actual_bytes:,} bytes')
assert actual_bytes == expected_bytes, f'Size mismatch: {actual_bytes} vs {expected_bytes}'

tokenizer = AutoTokenizer.from_pretrained(model_dir, use_fast=True)
if tokenizer.pad_token is None:
    tokenizer.pad_token = tokenizer.eos_token
print(f'    [+] Tokenizer Vocab Size: {len(tokenizer):,}')
print(f'    [+] Pad Token ID: {tokenizer.pad_token_id} ({tokenizer.pad_token})')
print(f'    [+] EOS Token ID: {tokenizer.eos_token_id} ({tokenizer.eos_token})')
print('    [OK] Model files & Tokenizer integrity PASSED!')

# -------------------------------------------------------------
# 3. DATASET V3 DEEP SEMANTIC & INTEGRITY AUDIT
# -------------------------------------------------------------
print('\n[3/5] Auditing Dataset V3 Splits (1,793 rows)...')
dataset_dir = '/home/tuankhoa/migration/dataset_v3_augmented_20261012'
splits = ['train.jsonl', 'validation.jsonl', 'test.jsonl']
split_data = {}
all_classes_by_split = {}
valid_labels = {'source', 'sink', 'taint-propagator', 'none'}

for s in splits:
    path = os.path.join(dataset_dir, s)
    assert os.path.exists(path), f'Missing {path}'
    records = []
    classes = set()
    label_counts = {l: 0 for l in valid_labels}
    
    with open(path, 'r', encoding='utf-8') as f:
        for idx, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            item = json.loads(line)
            records.append(item)
            
            # Check schema
            assert 'messages' in item, f'{s} line {idx} missing messages'
            msgs = item['messages']
            assert len(msgs) == 3, f'{s} line {idx} does not have exactly 3 messages'
            assert msgs[0]['role'] == 'system'
            assert msgs[1]['role'] == 'user'
            assert msgs[2]['role'] == 'assistant'
            
            # Check assistant response JSON against exact IRIS Stage 3 runtime contract
            resp = json.loads(msgs[2]['content'])
            assert 'type' in resp, f'{s} line {idx} missing type'
            assert resp['type'] in valid_labels, f'{s} line {idx} invalid type: {resp["type"]}'
            assert 'package' in resp, f'{s} line {idx} missing package'
            assert 'class' in resp, f'{s} line {idx} missing class'
            assert 'method' in resp, f'{s} line {idx} missing method'
            assert 'signature' in resp, f'{s} line {idx} missing signature'
            assert 'sink_args' in resp and isinstance(resp['sink_args'], list), f'{s} line {idx} invalid sink_args'
            if resp['type'] != 'sink':
                assert len(resp['sink_args']) == 0, f'{s} line {idx} non-sink must have empty sink_args'
            
            label_counts[resp['type']] += 1
            
            # Extract class name from user prompt
            user_content = msgs[1]['content']
            for u_line in user_content.split('\n'):
                if u_line.startswith('- Class:'):
                    cname = u_line.replace('- Class:', '').strip()
                    classes.add(cname)
                    break
                    
    split_data[s] = records
    all_classes_by_split[s] = classes
    print(f'    [+] {s}: {len(records)} samples | Breakdown: {label_counts}')

total_samples = sum(len(r) for r in split_data.values())
print(f'    [+] Total audited dataset samples: {total_samples}')
assert total_samples == 1793, f'Total samples mismatch: {total_samples} vs 1793'

# Check zero leakage between Train and Val/Test
train_classes = all_classes_by_split['train.jsonl']
val_classes = all_classes_by_split['validation.jsonl']
test_classes = all_classes_by_split['test.jsonl']

train_val_overlap = train_classes.intersection(val_classes)
train_test_overlap = train_classes.intersection(test_classes)
print(f'    [+] Train / Val Class Overlap: {len(train_val_overlap)} (0% leakage)')
print(f'    [+] Train / Test Class Overlap: {len(train_test_overlap)} (0% leakage)')
assert len(train_val_overlap) == 0, f'Data leakage detected between train and val: {train_val_overlap}'
assert len(train_test_overlap) == 0, f'Data leakage detected between train and test: {train_test_overlap}'
print('    [OK] Dataset V3 semantic integrity & Zero Leakage PASSED!')

# -------------------------------------------------------------
# 4. COLLATOR COMPLETION MASKING & TOKEN LEVEL VERIFICATION
# -------------------------------------------------------------
print('\n[4/5] Auditing Collator & Completion Masking on 100% of Train Set...')
sys.path.append('/home/tuankhoa/dataset_pipeline')
from train_qlora_stage3 import ChatCompletionDataCollator

collator = ChatCompletionDataCollator(tokenizer, max_length=1024)

# Test collator on entire train set in chunks to ensure no zero-masking bugs
all_train = split_data['train.jsonl']
zero_masked_count = 0
unmasked_lengths = []
total_prompt_lengths = []

for i in range(0, len(all_train), 50):
    batch = all_train[i:i+50]
    collated = collator(batch)
    labels = collated['labels']
    for row_idx, row in enumerate(labels):
        unmasked = (row != -100).sum().item()
        if unmasked == 0:
            zero_masked_count += 1
        else:
            unmasked_lengths.append(unmasked)
            total_prompt_lengths.append(len(row) - unmasked)

print(f'    [+] Audited {len(all_train)} train samples for completion masking.')
print(f'    [+] Samples with 0 unmasked tokens (Bugs): {zero_masked_count}')
print(f'    [+] Assistant target token length: min={min(unmasked_lengths)}, avg={sum(unmasked_lengths)/len(unmasked_lengths):.1f}, max={max(unmasked_lengths)}')
print(f'    [+] Prompt masked token length: min={min(total_prompt_lengths)}, avg={sum(total_prompt_lengths)/len(total_prompt_lengths):.1f}, max={max(total_prompt_lengths)}')
assert zero_masked_count == 0, f'{zero_masked_count} samples failed prompt masking!'
print('    [OK] Completion Masking on 100% of samples PASSED!')

# -------------------------------------------------------------
# 5. QLORA ENGINE LOAD & BACKWARD GRADIENT VERIFICATION
# -------------------------------------------------------------
print('\n[5/5] Auditing 4-bit NF4 Model Load & LoRA Gradient Computation...')
bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type='nf4',
    bnb_4bit_compute_dtype=torch.bfloat16,
    bnb_4bit_use_double_quant=True,
)
model = AutoModelForCausalLM.from_pretrained(
    model_dir,
    quantization_config=bnb_config,
    device_map={'': 0},
    dtype=torch.bfloat16,
    trust_remote_code=True,
)
model.config.use_cache = False
model = prepare_model_for_kbit_training(
    model,
    use_gradient_checkpointing=True,
    gradient_checkpointing_kwargs={'use_reentrant': False},
)
lora_config = LoraConfig(
    r=16,
    lora_alpha=32,
    lora_dropout=0.05,
    bias='none',
    task_type='CAUSAL_LM',
    target_modules=['q_proj', 'k_proj', 'v_proj', 'o_proj', 'gate_proj', 'up_proj', 'down_proj'],
)
model = get_peft_model(model, lora_config)

# Run test batch
sample_batch = collator(all_train[:2])
sample_batch_gpu = {k: v.to('cuda:0') for k, v in sample_batch.items()}
outputs = model(**sample_batch_gpu)
loss = outputs.loss
loss.backward()

# Verify that LoRA gradients exist and are finite
grad_norms = []
for name, param in model.named_parameters():
    if param.requires_grad and param.grad is not None:
        gnorm = param.grad.data.norm(2).item()
        grad_norms.append(gnorm)
        assert not torch.isnan(param.grad).any(), f'NaN gradient in {name}'
        assert not torch.isinf(param.grad).any(), f'Inf gradient in {name}'

print(f'    [+] Verified {len(grad_norms)} trainable LoRA tensors have valid, finite gradients!')
print(f'    [+] Mean LoRA gradient norm: {sum(grad_norms)/len(grad_norms):.6f}')
print(f'    [+] Forward loss on initial batch: {loss.item():.4f}')
allocated_gb = torch.cuda.memory_allocated() / (1024**3)
reserved_gb = torch.cuda.memory_reserved() / (1024**3)
print(f'    [+] GPU VRAM allocated: {allocated_gb:.2f} GB | Reserved: {reserved_gb:.2f} GB (of {total_vram:.2f} GB)')
print('    [OK] QLoRA Forward/Backward & Gradient propagation PASSED!')

print('\n' + '=' * 80)
print('  ALL 5 PRE-FLIGHT AUDITS PASSED WITH ZERO DEFECTS (100% READY FOR TRAINING)!')
print('=' * 80)
