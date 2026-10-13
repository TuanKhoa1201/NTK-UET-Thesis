# MA TRẬN TRUY VẾT YÊU CẦU ĐỒ ÁN (NTK_REQUIREMENTS_TRACEABILITY)
**Hệ thống:** NTK / IRIS / simple_semgrepAI
**Branch:** ntk-thesis-final-scientific-closeout
**Ngày lập:** 13/10/2026

---

## 1. YÊU CẦU CỦA GIẢNG VIÊN HƯỚNG DẪN & CHUẨN ĐỒ ÁN

| STT | Yêu cầu chính thức | Thành phần đảm nhiệm | Trạng thái hiện tại | Bằng chứng thực tế |
|---|---|---|---|---|
| REQ-01 | Kết nối mô hình LLM chạy cục bộ 100% | LocalLoRAVerifier + Ollama runtime | VERIFIED | Đã tải Qwen2.5-Coder-1.5B QLoRA adapter trên GPU RTX 4060 Ti không cần kết nối mạng |
| REQ-02 | Không gửi mã nguồn tới LLM cloud | THESIS_LOCAL_ONLY_MODE fail-closed | IN_PROGRESS (Phase B) | Cấu hình mặc định cũ còn chứa openai/anthropic, đang được chốt chặn fail-closed |
| REQ-03 | Sử dụng engine phân tích tĩnh mã nguồn mở | OpenGrep 1.25.0 native | IN_PROGRESS (Phase B) | OpenGrep đã cài tại /usr/local/bin/opengrep; đang loại bỏ fallback Semgrep trong code |
| REQ-04 | Quy trình huấn luyện/tinh chỉnh mô hình thực tế (Training Pipeline) | dataset_pipeline/train_qlora_stage3.py | VERIFIED | Trọng số LoRA 73.9MB đã được huấn luyện và lưu vết log chi tiết |
| REQ-05 | Phương pháp chấm điểm, đánh giá và ưu tiên cảnh báo SAST | SASTScoringEngine (Evidence-Aware) | IN_PROGRESS (Phase E) | Có thuật toán composite scoring; đang bổ sung sensitivity analysis và chuẩn hóa đặc tả |
| REQ-06 | Có đầy đủ Training Pipeline và Operation Pipeline | dataset_pipeline/ & simple_semgrepAI/ + IRIS | VERIFIED / IN_PROGRESS | Training đã hoàn thành stage 3; Operation pipeline đang được hoàn thiện tích hợp |
| REQ-07 | Công cụ thực tế có thể thực thi, kiểm thử và demo | simple_semgrepAI/run_pipeline_demo.sh + HTML Dashboard | VERIFIED | Có HTML report và scanner runner, đang gắn kết trơn tru |
| REQ-08 | Kế thừa từ simple_semgrepAI và thay thế hoàn toàn Semgrep | simple_semgrepAI/ trong repository | IN_PROGRESS (Phase B, D) | Thay thế Semgrep trên CLI, Scanner, Rules và Documentation |

---

## 2. TRẠNG THÁI 8 GIAI ĐOẠN THỰC THI (PHASES A -> H)

- [x] **PHASE A: Kiểm toán và bảo toàn trạng thái (Audit & Inventory)** - HOÀN THÀNH
- [ ] **PHASE B: Khắc phục vấn đề khoa học (Scientific Remediation)** - TIẾP THEO
- [ ] **PHASE C: Hoàn thiện và kiểm định Dataset/Training Pipeline** - CHỜ THỰC THI
- [ ] **PHASE D: Hoàn thiện Operation Pipeline (OpenGrep + Local LLM + Scoring)** - CHỜ THỰC THI
- [ ] **PHASE E: Chuẩn hóa đặc tả và kiểm thử SAST Scoring** - CHỜ THỰC THI
- [ ] **PHASE F: Xây dựng Scientific Benchmark độc lập & Error Analysis** - CHỜ THỰC THI
- [ ] **PHASE G: Sửa CI, đóng gói và kiểm chứng tính tái lập (Reproducibility)** - CHỜ THỰC THI
- [ ] **PHASE H: Hiệu đính hồ sơ luận văn tốt nghiệp, slides và demo** - CHỜ THỰC THI
