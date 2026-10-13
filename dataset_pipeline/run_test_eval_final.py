import os
import sys
import json
import torch
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from peft import PeftModel

MODEL_DIR = '/home/tuankhoa/models/Qwen2.5-Coder-1.5B-Instruct'
ADAPTER_DIR = '/home/tuankhoa/migration/qwen25_coder_15b_stage3_qlora_v3/best_adapter'
TEST_FILE = '/home/tuankhoa/migration/dataset_v3_augmented_20261012/test.jsonl'
OUTPUT_DIR = '/home/tuankhoa/migration/qwen25_coder_15b_stage3_qlora_v3'

print('[*] Loading tokenizer...', flush=True)
tokenizer = AutoTokenizer.from_pretrained(ADAPTER_DIR, use_fast=True)
if tokenizer.pad_token is None:
    tokenizer.pad_token = tokenizer.eos_token
tokenizer.padding_side = 'left'

print('[*] Loading base model in 4-bit NF4...', flush=True)
bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type='nf4',
    bnb_4bit_compute_dtype=torch.bfloat16
)
base = AutoModelForCausalLM.from_pretrained(
    MODEL_DIR,
    quantization_config=bnb_config,
    device_map={'': 0}
)

print(f'[*] Attaching best adapter from {ADAPTER_DIR}...', flush=True)
model = PeftModel.from_pretrained(base, ADAPTER_DIR)
model.eval()
if hasattr(model.config, 'use_cache'):
    model.config.use_cache = True

print(f'[*] Loading test dataset from {TEST_FILE}...', flush=True)
test_records = []
with open(TEST_FILE, 'r', encoding='utf-8') as f:
    for line in f:
        line = line.strip()
        if line:
            test_records.append(json.loads(line))
print(f'[✓] Total test samples: {len(test_records)}', flush=True)

valid_classes = ['source', 'sink', 'taint-propagator', 'none']
y_true = []
y_pred = []
raw_results = []

BATCH_SIZE = 8
total_samples = len(test_records)

print('=' * 70, flush=True)
print(f'  STARTING HELD-OUT TEST EVALUATION (BATCH_SIZE={BATCH_SIZE})', flush=True)
print('=' * 70, flush=True)

for b_start in range(0, total_samples, BATCH_SIZE):
    batch = test_records[b_start : b_start + BATCH_SIZE]
    batch_prompts = []
    batch_gt_types = []
    
    for rec in batch:
        msgs = rec['messages']
        gt_obj = json.loads(msgs[2]['content'])
        gt_type = gt_obj.get('type', 'none')
        batch_gt_types.append(gt_type)
        y_true.append(gt_type)
        
        prompt_text = tokenizer.apply_chat_template(msgs[:2], add_generation_prompt=True, tokenize=False)
        batch_prompts.append(prompt_text)
        
    inputs = tokenizer(batch_prompts, return_tensors='pt', padding=True, truncation=True, max_length=1024).to('cuda:0')
    
    with torch.no_grad():
        out_ids = model.generate(
            **inputs,
            max_new_tokens=60,
            do_sample=False,
            pad_token_id=tokenizer.pad_token_id
        )
        
    input_len = inputs['input_ids'].shape[1]
    
    for i, rec in enumerate(batch):
        completion = tokenizer.decode(out_ids[i][input_len:], skip_special_tokens=True).strip()
        pred_type = 'unknown'
        try:
            parsed = json.loads(completion)
            pred_type = parsed.get('type', 'unknown')
        except Exception:
            for c in valid_classes:
                if f'"{c}"' in completion or f"'{c}'" in completion:
                    pred_type = c
                    break
                    
        y_pred.append(pred_type)
        raw_results.append({
            'idx': b_start + i,
            'ground_truth': batch_gt_types[i],
            'prediction': pred_type,
            'raw_output': completion
        })
        
    curr_done = min(b_start + BATCH_SIZE, total_samples)
    curr_acc = accuracy_score(y_true, y_pred)
    print(f'  --> Progress: {curr_done}/{total_samples} samples | Current Running Accuracy: {curr_acc:.4f} ({curr_acc*100:.2f}%)', flush=True)

acc = accuracy_score(y_true, y_pred)
clf_report = classification_report(y_true, y_pred, labels=valid_classes, output_dict=True, zero_division=0)
clf_text = classification_report(y_true, y_pred, labels=valid_classes, zero_division=0)
cm = confusion_matrix(y_true, y_pred, labels=valid_classes).tolist()

report_payload = {
    'accuracy': acc,
    'classification_report': clf_report,
    'confusion_matrix': {
        'labels': valid_classes,
        'matrix': cm
    },
    'total_test_samples': len(test_records),
    'raw_results': raw_results
}

report_path = os.path.join(OUTPUT_DIR, 'test_evaluation_report.json')
with open(report_path, 'w', encoding='utf-8') as f:
    json.dump(report_payload, f, indent=2)

text_report_path = os.path.join(OUTPUT_DIR, 'test_classification_report.txt')
with open(text_report_path, 'w', encoding='utf-8') as f:
    f.write('=' * 70 + '\n')
    f.write('  NTK/IRIS STAGE 3 - HELD-OUT TEST EVALUATION REPORT\n')
    f.write('=' * 70 + '\n\n')
    f.write(f'Total Test Samples: {len(test_records)}\n')
    f.write(f'Overall Accuracy:   {acc:.4f} ({acc*100:.2f}%)\n\n')
    f.write('Classification Report:\n')
    f.write(clf_text + '\n\n')
    f.write('Confusion Matrix:\n')
    f.write(f'Labels: {valid_classes}\n')
    for row, label in zip(cm, valid_classes):
        f.write(f'{label:18}: {row}\n')

print('\n' + '=' * 70, flush=True)
print('  FINAL HELD-OUT TEST METRICS (BEST ADAPTER AFTER 3 EPOCHS):', flush=True)
print('=' * 70, flush=True)
print(clf_text, flush=True)
print(f'[✓] Evaluation report saved to {report_path}', flush=True)
print(f'[✓] Text classification report saved to {text_report_path}', flush=True)
print(f'[✓] OVERALL TEST ACCURACY: {acc*100:.2f}%', flush=True)
