# BÁO CÁO KIỂM TOÁN MÃ NGUỒN VÀ BẰNG CHỨNG THỰC NGHIỆM (NTK_FINAL_CODE_AUDIT)
**Đồ án Tốt nghiệp:** Phát triển công cụ phát hiện lỗ hổng mã nguồn kết hợp phân tích tĩnh nguồn mở và mô hình ngôn ngữ lớn
**Hệ thống:** NTK / IRIS / simple_semgrepAI
**Branch:** ntk-thesis-final-scientific-closeout
**Baseline Commit:** a17642b825bfd279fab636fbc00387bbb7860d4b
**Production Closeout Tag:** ntk-production-closeout-20261008 (ee5ac1c76bec3e7d952354debf81d699eddebe0e)
**Ngày thực hiện kiểm toán:** 13/10/2026
**Trạng thái kiểm toán:** HOÀN THÀNH - TOÀN DIỆN 12 PHÁT HIỆN

---

## 1. MỤC TIÊU VÀ PHẠM VI KIỂM TOÁN
Kiểm toán độc lập toàn bộ mã nguồn, cấu hình, dữ liệu huấn luyện, mô hình QLoRA, engine chấm điểm SAST, CI/CD và tài liệu luận văn nhằm nhận diện và khoanh vùng 100% các sai lệch kỹ thuật và khoa học.

---

## 2. MA TRẬN ĐÁNH GIÁ 12 PHÁT HIỆN KIỂM TOÁN (AUDIT FINDINGS)

| Mã ID | Vấn đề kiểm toán | Trạng thái xác minh | Bằng chứng thực tế (Ground Truth) | Mức độ nghiêm trọng | Hướng xử lý |
|---|---|---|---|---|---|
| F-01 | Benchmark 100 alerts giả định trong enchmark_scientific_evaluation.py | VERIFIED | File tự tạo 55 TP và 45 FP với AI verdict cố định, công bố F1=1.0 phi thực tế | P0 (Khoa học) | Đổi thành synthetic_scoring_sanity_check.py, xây dựng empirical benchmark độc lập |
| F-02 | Category error: Suy diễn API role thành finding TP/FP trong local_lora_verifier.py | VERIFIED | Lines 231-248 gán sink/source thành TRUE_POSITIVE, none thành FALSE_POSITIVE | P0 (Kỹ thuật/Khoa học) | Tách bạch API_ROLE_PREDICTION khỏi Finding-level validation (LIKELY_VULNERABLE, LIKELY_FALSE_POSITIVE, NEEDS_REVIEW, UNKNOWN) |
| F-03 | Hardcoded confidence (0.92, 0.82, 0.88) | VERIFIED | Giá trị số học cố định được gán trực tiếp vào kết quả mà không qua calibrated probability | P1 (Khoa học) | Loại bỏ xác suất giả, chuyển sang mức độ bằng chứng định tính có cơ sở |
| F-04 | Rủi ro ô nhiễm nhãn trong Dataset V3 & split rò rỉ | VERIFIED | Heuristic substring và codeql mapping; chia tập theo class thay vì repository family | P1 (Dữ liệu) | Đánh giá provenance, ghi nhận rủi ro leakage rõ ràng trong limitations |
| F-05 | Lệch số liệu confusion matrix 329 vs 330 test samples | VERIFIED | Mẫu idx 242 có prediction là 'unknown' do JSON trích xuất bị cắt cụt, sklearn drop khỏi 4-class matrix | P1 (Thực nghiệm) | Chuẩn hóa audit raw results, báo cáo chi tiết schema validity và unknown count |
| F-06 | Thiếu trọng số dapter_model.safetensors trên Git tree | VERIFIED | Git tree chỉ có config/tokenizer; file weights thực tế 73.9MB nằm tại /home/tuankhoa/migration/qwen25_coder_15b_stage3_qlora_v3/best_adapter/ (SHA256: 9b764d06b8def2a5e8de334dbe9fc58f373329969b3e15d3d7a8ed8556096de7) | P0 (Tái lập) | Tích hợp script nạp trọng số, cấu hình đường dẫn qua biến môi trường hoặc release artifact |
| F-07 | Phân mảnh 2 pipeline và 2 scoring engines | VERIFIED | Song song IRIS runner và simple_semgrepAI pipeline | P1 (Kiến trúc) | Hợp nhất contract, xác định OpenGrep + Local LoRA/Ollama + Evidence-Aware Scoring là authoritative |
| F-08 | Rò rỉ cấu hình Cloud API (Anthropic/OpenAI) | VERIFIED | semgrepai.yml mặc định anthropic, config.py mặc định openai | P0 (Quyền riêng tư) | Cưỡng chế THESIS_LOCAL_ONLY_MODE=true với cơ chế fail-closed |
| F-09 | OpenGrep scanner còn fallback sang Semgrep | VERIFIED | Lines 20-25 trong scanner.py tự động append 'semgrep' vào candidates | P0 (Yêu cầu GV) | Enforce OpenGrep-only mode trong thesis production, cấm silent fallback |
| F-10 | Scoring heuristic chưa qua phân tích độ nhạy | VERIFIED | Trọng số 0.35/0.30/0.25/0.10 và hệ số phạt 0.15 gán cứng; tự xưng CVSS/CWSS | P1 (Khoa học) | Chuẩn hóa đặc tả Observable Evidence Risk Scoring, bổ sung sensitivity analysis |
| F-11 | CI gãy do disk exhaustion (No space left on device) | VERIFIED | .dockerignore thiếu data/ (5.1GB) và output/ (3.9GB) khiến docker context phình to 9GB+ | P1 (MLOps/CI) | Bổ sung .dockerignore, tách CPU unit test workflow khỏi nặng integration |
| F-12 | Luận văn và slides chứa overclaims | VERIFIED | Tuyên bố hoàn hảo 100%, zero leakage tuyệt đối dựa trên benchmark mô phỏng | P0 (Học thuật) | Rà soát và chỉnh sửa trung thực, minh bạch hoá hạn chế và kết quả âm tính |

---

## 3. KẾT LUẬN KIỂM TOÁN VÀ ĐIỀU KIỆN TIẾP TỤC
Môi trường thực tế sở hữu đầy đủ GPU NVIDIA RTX 4060 Ti (16GB VRAM), OpenGrep 1.25.0, adapter weights LoRA 73.9MB và base model Qwen2.5-Coder-1.5B.
Không tồn tại hard blocker về mặt tài nguyên phần cứng. Kế hoạch chuyển tiếp sang Phase B đã sẵn sàng.
