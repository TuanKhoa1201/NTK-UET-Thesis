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
* **Cân bằng 4 nhãn:** Phân bổ đồng đều ~25% cho mỗi lớp (source: 485, sink: 348, taint-propagator: 460, none: 500) — Giải quyết triệt để sự thiên lệch của tập cũ.
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
* **Lọc hàm vô hại (None/Benign):** Recall = 93.0% — Chìa khóa vàng giúp hệ thống tự tin loại bỏ cảnh báo giả.

---

## SLIDE 8: THUẬT TOÁN CHẤM ĐIỂM TOÁN HỌC SAST COMPOSITE RISK SCORING
* **Công thức tổng hợp:**
  RawScore = 100 * (0.35 * S_eff + 0.10 * P + 0.30 * C_AI + 0.25 * E)
  FinalScore = round(RawScore * gamma_FP, 1)
* **Ý nghĩa các thành phần:**
  - S_eff: Độ nghiêm trọng tĩnh kết hợp trọng số điều chỉnh CWE.
  - P: Độ chính xác của Rule OpenGrep (0.40 - 1.00).
  - C_AI: Độ tin cậy thẩm định ngữ nghĩa của mô hình LoRA.
  - E: Độ phủ luồng truyền dữ liệu Taint Source -> Sink.
  - gamma_FP: Hệ số phạt báo động giả (gamma_FP = 0.15 khi AI kết luận FALSE_POSITIVE, gamma_FP = 1.00 khi TRUE_POSITIVE).

---

## SLIDE 9: KẾT QUẢ THỰC NGHIỆM ĐỐI CHỨNG (BENCHMARK)
* So sánh OpenGrep Cơ sở vs Hệ thống Hybrid AI Đề xuất:
  - **Số cảnh báo cần xử lý thủ công:** Giảm 45% công sức cho đội ngũ bảo mật.
  - **Tỷ lệ giảm báo động giả (FPRR):** Đạt 100% (triệt tiêu 45/45 cảnh báo rác).
  - **Độ chính xác (Precision):** Tăng từ 55.0% lên 100.0%.
  - **Độ bao phủ (Recall):** Bảo toàn 100% lỗ hổng thật.
  - **F1-Score tổng hợp:** Tăng từ 0.710 lên 1.000.

---

## SLIDE 10: DEMO TRỰC TIẾP TRÊN MÃ NGUỒN JAVA THỰC TẾ
* **Mục tiêu 1:** mini_vulnerable_java_CVE-89_1.0
  - SQL Injection (SqlInjection.java): RiskScore = 73.6 (HIGH - Phán quyết TRUE_POSITIVE).
  - XXE Injection (XxeExample.java): RiskScore = 76.1 (HIGH - Phán quyết TRUE_POSITIVE).
  - Weak Hash (WeakHash.java): Raw score 36.8 điểm bị hạ xuống 5.5 điểm (BENIGN/FP).
* **Mục tiêu 2:** OWASP Benchmark v1.2 (BenchmarkTest00001.java)
  - Phát hiện Path Traversal (CWE-22) tại FileInputStream -> Khớp 100% với ground truth của OWASP.

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
