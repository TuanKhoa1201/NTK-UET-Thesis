from huggingface_hub import snapshot_download
import os

model_id = "Qwen/Qwen2.5-Coder-1.5B-Instruct"
revision = "2e1fd397ee46e1388853d2af2c993145b0f1098a"
local_dir = "/home/tuankhoa/models/Qwen2.5-Coder-1.5B-Instruct"

print(f"[*] Downloading {model_id} (revision: {revision}) to {local_dir}...")
os.makedirs(local_dir, exist_ok=True)

snapshot_download(
    repo_id=model_id,
    revision=revision,
    local_dir=local_dir,
    max_workers=4
)
print("[✓] Model download complete!")
