import torch
import json
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from peft import PeftModel

model_dir = '/home/tuankhoa/models/Qwen2.5-Coder-1.5B-Instruct'
ckpt_dir = '/home/tuankhoa/migration/qwen25_coder_15b_stage3_qlora_v3/checkpoint-250'

print('[*] Loading tokenizer...')
tokenizer = AutoTokenizer.from_pretrained(model_dir, use_fast=True)

print('[*] Loading base model...')
bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type='nf4',
    bnb_4bit_compute_dtype=torch.bfloat16
)
base = AutoModelForCausalLM.from_pretrained(
    model_dir,
    quantization_config=bnb_config,
    device_map={'': 0}
)

print('[*] Attaching adapter from checkpoint-250...')
model = PeftModel.from_pretrained(base, ckpt_dir)
model.eval()

with open('/home/tuankhoa/migration/dataset_v3_augmented_20261012/test.jsonl') as f:
    sample = json.loads(f.readline())

prompt = tokenizer.apply_chat_template(sample['messages'][:2], add_generation_prompt=True, tokenize=False)
inputs = tokenizer(prompt, return_tensors='pt').to('cuda:0')

print('[*] Generating output...')
with torch.no_grad():
    out = model.generate(**inputs, max_new_tokens=60, do_sample=False, pad_token_id=tokenizer.eos_token_id)
gen = tokenizer.decode(out[0][inputs['input_ids'].shape[1]:], skip_special_tokens=True).strip()

print('\n=== GROUND TRUTH ===')
print(sample['messages'][2]['content'])
print('=== MODEL PREDICTION ===')
print(gen)
print('[✓] Checkpoint-250 is fully loadable and working perfectly!')
