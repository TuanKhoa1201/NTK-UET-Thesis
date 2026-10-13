# DANH MỤC BẰNG CHỨNG THỰC TẾ (NTK_EVIDENCE_INVENTORY)
**Hệ thống:** NTK / IRIS / simple_semgrepAI
**Branch:** ntk-thesis-final-scientific-closeout
**Ngày lập:** 13/10/2026

---

## 1. MÔI TRƯỜNG PHẦN CỨNG VÀ HỆ ĐIỀU HÀNH
- **OS:** Linux WSL2 (Ubuntu-IRIS, kernel 5.15.167.4-microsoft-standard-WSL2)
- **Host:** Windows 11 Pro, máy chủ Admin-PC
- **GPU:** NVIDIA GeForce RTX 4060 Ti 16GB (VRAM khả dụng: ~15.4 GB, Driver 591.86, CUDA 13.1)
- **Python:** Python 3.10.22 trong Conda environment iris (/home/tuankhoa/miniconda3/envs/iris)
- **PyTorch:** Đã kiểm chứng CUDA available = True, nhận diện chuẩn GPU RTX 4060 Ti.
- **Ollama Engine:** /usr/local/bin/ollama, đang phục vụ model qwen2.5-coder:1.5b (Q4_K_M, size 986MB).
- **OpenGrep Binary:** /usr/local/bin/opengrep (phiên bản 1.25.0).
- **Semgrep Binary:** Không cài đặt trên môi trường native (command not found).

---

## 2. ARTIFACTS DỮ LIỆU VÀ MÔ HÌNH
- **Base Model Local:**
  - Đường dẫn: /home/tuankhoa/models/Qwen2.5-Coder-1.5B-Instruct
  - Tệp: model.safetensors (3.09 GB), đầy đủ tokenizer và configs.
- **LoRA Adapter Weights (Stage 3):**
  - Đường dẫn lưu trữ gốc: /home/tuankhoa/migration/qwen25_coder_15b_stage3_qlora_v3/best_adapter/adapter_model.safetensors
  - Kích thước: 73,911,112 bytes (~73.9 MB)
  - SHA-256 Checksum: 9b764d06b8def2a5e8de334dbe9fc58f373329969b3e15d3d7a8ed8556096de7
  - Thời điểm tạo: 12/10/2026 23:53
  - Trạng thái kiểm chứng tải trọng số: Đã load thành công với PeftModel trong 2.1s trên GPU RTX 4060 Ti.
- **Dataset V3 Artifacts:**
  - Thư mục: /home/tuankhoa/migration/dataset_v3_augmented_20261012
  - Đã có mã nguồn trích xuất và tiền xử lý trong dataset_pipeline/.
- **Test Evaluation Report (330 mẫu):**
  - Tệp: /home/tuankhoa/migration/qwen25_coder_15b_stage3_qlora_v3/test_evaluation_report.json
  - Tổng số mẫu: 330
  - Phân bổ Ground Truth: source (109), taint-propagator (86), none (76), sink (59).
  - Phân bổ Dự đoán: none (141), source (81), sink (57), taint-propagator (50), unknown (1).
  - Mẫu ngoại lệ: Mẫu thứ 242 (UsersResource.generateNewToken) có raw output bị cắt cụt dấu ngoặc nhọn, dẫn đến phân loại unknown.

---

## 3. MÃ NGUỒN VÀ KIỂM CHỨNG GIT
- **Git HEAD:** 17642b825bfd279fab636fbc00387bbb7860d4b
- **Git Branch làm việc chính thức:** 
tk-thesis-final-scientific-closeout
- **Production Closeout Tag bất biến:** 
tk-production-closeout-20261008 (commit ee5ac1c76bec3e7d952354debf81d699eddebe0e)
