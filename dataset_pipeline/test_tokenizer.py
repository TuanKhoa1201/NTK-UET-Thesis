from transformers import AutoTokenizer

model_id = "Qwen/Qwen2.5-Coder-1.5B-Instruct"
revision = "2e1fd397ee46e1388853d2af2c993145b0f1098a"

print(f"[*] Testing loading tokenizer for {model_id} (revision: {revision})...")
try:
    tokenizer = AutoTokenizer.from_pretrained(model_id, revision=revision)
    print(f"[✓] Tokenizer loaded successfully! Vocab size: {len(tokenizer)}")
except Exception as e:
    print(f"[-] Tokenizer error: {e}")
