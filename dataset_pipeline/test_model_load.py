import torch
from transformers import AutoModelForCausalLM, BitsAndBytesConfig
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training

model_dir = '/home/tuankhoa/models/Qwen2.5-Coder-1.5B-Instruct'

print(f'[*] Testing loading {model_dir} in 4-bit NF4 on physical GPU...')

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
print('[✓] PEFT LoRA model initialized successfully!')
model.print_trainable_parameters()

allocated_mem = torch.cuda.memory_allocated() / (1024**3)
reserved_mem = torch.cuda.memory_reserved() / (1024**3)
print(f'[✓] GPU VRAM allocated: {allocated_mem:.2f} GB | Reserved: {reserved_mem:.2f} GB | Total: 16 GB')
print('[✓] QLoRA Configuration on RTX 4060 Ti is 100% READY!')
