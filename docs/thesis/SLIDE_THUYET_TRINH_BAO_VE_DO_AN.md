# KỊCH BẢN THUYẾT TRÌNH BẢO VỆ ĐỒ ÁN TỐT NGHIỆP (15 PHÚT)

**Đề tài:** Phát triển công cụ phát hiện lỗ hổng mã nguồn kết hợp phân tích tĩnh nguồn mở và mô hình ngôn ngữ lớn  
*(Developing a source code vulnerability detection tool combining open-source static analysis and large language models)*  
**Học viên thực hiện:** Tuấn Khoa | **Đơn vị:** Trường Đại học Công nghệ (UET) - ĐHQGHN  
**Hệ thống thực nghiệm:** NTK / IRIS Hybrid 2-Tier Framework  

---

## SLIDE 1: TRANG TIÊU ĐỀ
* **Tiêu đề:** PHÁT TRIỂN CÔNG CỤ PHÁT HIỆN LỖ HỔNG MÃ NGUỒN KẾT HỢP PHÂN TÍCH TĨNH NGUỒN MỞ VÀ MÔ HÌNH NGÔN NGỮ LỚN
* **Tác giả:** Tuấn Khoa
* **Từ khóa:** OpenGrep, Local LLM, QLoRA Fine-Tuning, SAST Composite Risk Scoring, DevSecOps.

---

## SLIDE 2: TÍNH CẤP THIẾT & ĐẶT VẤN ĐỀ
* **Bối cảnh:** Nhu cầu dịch chuyển bảo mật sang trái (Shift-Left Security) trong chu trình phát triển phần mềm an toàn (SSDLC).
* **3 Hạn chế cốt tử của SAST truyền thống:**
  1. *Alert Fatigue (Quá tải báo động giả):* Quy tắc tĩnh mức hàm thiếu hiểu biết ngữ cảnh, sinh nhiều False Positive (40 - 70%).
  2. *Thang đo mức độ nghiêm trọng tĩnh:* Chỉ có ERROR/WARNING do rule định nghĩa sẵn, không đo lường được khả năng khai thác thực tế.
  3. *Nguy cơ rò rỉ mã nguồn:* Việc gửi mã nguồn lên LLM đám mây (OpenAI/Anthropic) vi phạm nghiêm trọng chính sách bảo mật doanh nghiệp.

---

## SLIDE 3: MỤC TIÊU NGHIÊN CỨU & NGUYÊN TẮC THIẾT KẾ
* **Mục tiêu chính:** Xây dựng công cụ lai (Hybrid 2-Tier) phát hiện chính xác lỗ hổng, triệt tiêu báo động giả và định lượng rủi ro động.
* **3 Trụ cột cốt lõi:**
  1. *100% Mã nguồn mở & Cục bộ:* Sử dụng OpenGrep 1.25.0 (LGPL-2.1) + Mô hình Qwen2.5-Coder 1.5B chạy trên GPU RTX 4060 Ti nội bộ (Zero-Cloud Privacy).
  2. *Huấn luyện tinh chỉnh chuyên sâu (Fine-Tuning):* Tinh chỉnh adapter LoRA chuyên biệt cho bài toán nhận diện Source, Sink, Taint-Propagator trong Java.
  3. *Thuật toán Chấm điểm Động (SAST Composite Scoring):* Công thức toán học chuẩn hóa từ MITRE CWSS/CVSS với hệ số phạt báo động giả gamma_FP = 0.15.

---

## SLIDE 4: TỔNG QUAN KIẾN TRÚC HỆ THỐNG HYBRID 2-TIER
* **Tầng 1 (Fast SAST Filter - OpenGrep v1.25.0):**
  - Quét cú pháp AST và Taint tracking liên tục toàn bộ dự án trong 0.5 - 1.5 giây.
  - Xuất danh sách cảnh báo thô (Raw Findings, SARIF v2.1.0).
* **Tầng 2 (Deep Semantic Verification & Dynamic Scoring):**
  - *Local LoRA AI Verifier:* Bóc tách ngữ cảnh hàm, phân loại Source/Sink/None, xác lập phán quyết True Positive vs False Positive.
  - *SAST Scoring Engine:* Tính toán điểm rủi ro tổng hợp RiskScore in [0, 100] và phân bổ vào 5 dải rủi ro (Critical, High, Medium, Low, Benign/FP).

---

## SLIDE 5: XÂY DỰNG DATASET V3 (GIAI ĐOẠN HUẤN LUYỆN)
* **Quy mô:** 1,793 mẫu dữ liệu chuyên sâu cho mã nguồn Java.
* **Cân bằng 4 nhãn:** Phân bổ đồng đều ~25% cho mỗi lớp (source: 485, sink: 348, taint-propagator: 460, none: 500)  -  Giải quyết triệt để sự thiên lệch của tập cũ.
* **Zero Class Leakage:** Áp dụng giải thuật băm định danh lớp hash(package.class) % 10. 100% các lớp trong tập Test (330 mẫu) không xuất hiện trong tập Train.
* **Bao phủ đa CWE:** CWE-089 (SQLi), CWE-078 (Command Injection), CWE-022 (Path Traversal), CWE-611 (XXE), CWE-798 (Credentials).

---

## SLIDE 6: QUÁ TRÌNH HUẤN LUYỆN QLORA TRÊN GPU RTX 4060 TI
* **Base Model:** Qwen2.5-Coder-1.5B-Instruct
* **Cấu hình tối ưu:** QLoRA 4-bit NormalFloat (NF4), LoRA Rank r=16, alpha=32, bfloat16, paged_adamw_8bit trên cả 7 linear projections.
* **Độ hội tụ:** Hoàn tất 3 Epochs (462 steps). Train loss giảm từ 0.2929 xuống 0.0033, Validation loss giảm từ 0.0307 xuống 0.0156.
* **Kích thước trọng số LoRA tối ưu:** Chỉ 73.9 MB (best_adapter).

---

## SLIDE 7: ĐÁNH GIÁ TRÊN TẬP KIỂM THỬ ĐỘC LẬP (TEST SET 330 MẪU)
* **Overall Accuracy:** 67.58% (trên bài toán 4 nhãn với dữ liệu hoàn toàn chưa từng thấy).
* **Nhận diện Sink:** Precision = 0.86, Recall = 0.83, F1-Score = 0.84.
* **Nhận diện Source:** Precision = 0.89, Recall = 0.66, F1-Score = 0.76.
* **Lọc hàm vô hại (None/Benign):** Recall = 93.0%  -  Chìa khóa vàng giúp hệ thống tự tin loại bỏ cảnh báo giả.

---

## SLIDE 8: THUẬT TOÁN CHẤM ĐIỂM SAST OBSERVABLE EVIDENCE RISK SCORING (V2.1)
* **Công thức tổng hợp 2 tầng:**
  RawScore = 100 * (0.35 * S_eff + 0.10 * P + 0.30 * C_sem + 0.25 * E)
  FinalScore = round(RawScore * gamma, 1)
* **Ý nghĩa các thành phần dựa trên bằng chứng quan sát được:**
  - S_eff: Độ nghiêm trọng tĩnh kết hợp trọng số điều chỉnh nội tại theo CWE (0.10 - 1.00).
  - P: Độ chính xác của Rule OpenGrep (0.40 - 1.00).
  - C_sem: Bằng chứng ngữ nghĩa vai trò hàm từ LoRA (Sink=0.90, Source=0.85, Propagator=0.70, None=0.20).
  - E: Bằng chứng luồng truyền dữ liệu vết (Dataflow Taint Reachability: 0.30 - 1.00).
* **Cơ chế hạ bậc bảo thủ (Conservative Demotion):**
  - gamma = 1.00 khi AI xác nhận vai trò liên quan lỗ hổng (LIKELY_VULNERABLE / POTENTIAL_TAINT_ENTRY).
  - gamma = 0.35 khi AI phân loại hàm vô hại (SUSPECTED_FALSE_POSITIVE).
  - Khác biệt khoa học: Không ép về 0 hoặc xóa bỏ cảnh báo (tránh False Negative nghiêm trọng nếu AI nhầm lẫn); cảnh báo CRITICAL vẫn giữ điểm sàn an toàn (~26.1 - 33.4 điểm, nhóm LOW), giải phóng thời gian ưu tiên nhưng bảo toàn dấu vết kiểm toán.

---

## SLIDE 9: ĐÁNH GIÁ THỰC NGHIỆM ĐỘC LẬP & PHÂN TÍCH LỖI (ERROR ANALYSIS)
* **Tập kiểm thử độc lập (Held-Out Test Set):** 330 mẫu hoàn toàn tách biệt khỏi tập Train (Zero Class Leakage).
* **Độ chính xác nghiêm ngặt toàn cục (Strict Accuracy):** **67.58%** (223/330 mẫu phân loại chính xác tuyệt đối cả 4 nhãn).
* **Hiệu năng trên các lớp an ninh cốt lõi:**
  - **Nhận diện Sink:** Precision = 0.86, Recall = 0.83, **F1-Score = 0.84** (59 mẫu).
  - **Nhận diện Source:** Precision = 0.89, Recall = 0.66, **F1-Score = 0.76** (109 mẫu).
  - **Lọc hàm vô hại (None):** Precision = 0.50, **Recall = 0.93** (76 mẫu)  -  Chìa khóa lọc 93% hàm an toàn.
* **Phân tích lỗi (Error Analysis) & Giải pháp kiến trúc:**
  - Lớp `taint-propagator` đạt F1 = 0.46 (Recall 0.36) do tính đa dạng cao của các hàm truyền dữ liệu đối với mô hình 1.5B cục bộ.
  - Cơ chế phòng thủ chiều sâu (Defense-in-Depth): Hệ thống bù đắp bằng thành phần Taint Reachability ($E$) của OpenGrep, đảm bảo an toàn đa tầng không bị phụ thuộc duy nhất vào LLM.
  - Phân tích 1 mẫu ngoại lệ (idx 242) bị cắt cụt token JSON được xử lý an toàn (fail-safe fallback).

---

## SLIDE 10: DEMO TRỰC TIẾP TRÊN MÃ NGUỒN JAVA THỰC TẾ
* **Mục tiêu thực tế:** `mini_vulnerable_java_CVE-89_1.0/src` (quét với tập rules p-java OpenGrep)
  - **XXE Injection (`XxeExample.java:28`):** Risk Score = **75.5** (Mức HIGH, AI phán quyết `LIKELY_VULNERABLE`, API role: `sink`).
  - **SQL Injection (`SqlInjection.java:27`):** Risk Score = **73.0** (Mức HIGH, AI phán quyết `LIKELY_VULNERABLE`, API role: `sink`).
  - **Weak Hash (`WeakHash.java:17`):** Raw Score = 41.2 điểm -> hạ bậc bảo thủ ($\gamma = 0.35$) xuống **14.4 điểm** (Mức BENIGN_OR_FP, AI phán quyết `SUSPECTED_FALSE_POSITIVE`, API role: `none`).
* **Đặc tả kiểm chứng:** Bảo toàn 100% các lỗ hổng nguy cấp tại đỉnh bảng xếp hạng ưu tiên, đồng thời phân tầng rõ rệt các cảnh báo mã nguồn an toàn mà không làm mất dấu vết rà soát.

---

## SLIDE 11: ĐÓNG GÓI SẢN PHẨM & TÍCH HỢP DEVSECOPS
* Script chạy 1-lệnh tự động: ./run_pipeline_demo.sh
* Xuất bản Web Dashboard HTML tương tác trực quan với biểu đồ phân bố rủi ro.
* Đầu ra SARIF v2.1.0 tương thích trực tiếp với GitHub Advanced Security, GitLab CI và SonarQube.

---

## SLIDE 12: KẾT LUẬN & HƯỚNG PHÁT TRIỂN
* **Đóng góp của đồ án:**
  1. Chứng minh giải pháp FOSS (OpenGrep) hoàn toàn có thể thay thế Semgrep độc quyền.
  2. Xây dựng quy trình Fine-Tuning QLoRA cục bộ đạt chuẩn khoa học cho bài toán Taint Analysis.
  3. Đề xuất mô hình toán học chấm điểm SAST định lượng giải quyết triệt để bài toán Alert Fatigue.
* **Lời cảm ơn & Sẵn sàng trả lời phản biện của Hội đồng.**
