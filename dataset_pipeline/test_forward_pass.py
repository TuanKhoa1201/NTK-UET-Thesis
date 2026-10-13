import os
import sys
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from train_qlora_stage3 import ChatCompletionDataCollator, load_jsonl_dataset

model_dir = '/home/tuankhoa/models/Qwen2.5-Coder-1.5B-Instruct'
dataset_dir = '/home/tuankhoa/migration/dataset_v3_augmented_20261012'

print('[+] 1. Loading tokenizer...')
tokenizer = AutoTokenizer.from_pretrained(model_dir, use_fast=True)
if tokenizer.pad_token is None:
    tokenizer.pad_token = tokenizer.eos_token

print('[*] 2. Loading sample batch from train.jsonl...')
records = load_jsonl_dataset(os.path.join(dataset_dir, 'train.jsonl'))[:2]
collator = ChatCompletionDataCollator(tokenizer, max_length=1024)
batch = collator(records)

print(f'[*] Batch input_ids shape: {batch["input_ids"].shape}')
print(f'[+] Batch labels shape: {batch["labels"].shape}')
unmasked_tokens = (batch["labels"] != -100).sum().item()
total_tokens = batch["labels"].numel()
print(f'[*] Target assistant unmasked tokens: {unmasked_tokens} / {total_tokens}')

print('[+] 3. Loading model in 4-bit NF4...')
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

print('[+] 4. Running Forward and Backward Pass on RTX 4060 Ti...')
batch_gpu = {k: v.to('cuda:0') for k, v in batch.items()}
outputs = model(**batch_gpu)
print('[*] 4. Running Forward and Backward Pass on RTX 4060 Ti...')
batch_gpu = {k: v.to('cuda:0') for k, v in batch.items()}
outputs = model(**batch_gpu)
loss = outputs.loss
print(f'[OK] Forward loss computed: {loss.item():.4f}')

loss.backward()
print('[OK] Backward pass completed! Gradients computed on LoRA parameters!')

allocated = torch.cuda.memory_allocated() / (1024**3)
reserved = torch.cuda.memory_reserved() / (1024**3)
print(f'[OK] GPU Memory: {allocated:.2f} GB allocated, {reserved:.2f} GB reserved (of 16 GB)')
print('[OK] Forward/Backward smoke test PASSED 100%!')
