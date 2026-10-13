# BÁO CÁO KHOA HỌC ĐỒ ÁN TỐT NGHIỆP

**Đề tài:** Phát triển công cụ phát hiện lỗ hổng mã nguồn kết hợp phân tích tĩnh nguồn mở và mô hình ngôn ngữ lớn  
*(Developing a Source Code Vulnerability Detection Tool Combining Open-Source Static Analysis and Large Language Models)*  
**Học viên / Tác giả:** Nguyễn Tuấn Khoa  
**Hệ thống thực nghiệm:** NTK / IRIS Hybrid Framework (OpenGrep + Fine-tuned Local LoRA + SAST Observable Evidence Scoring)  
**Thời điểm hoàn thiện:** Tháng 10/2026  
**Trạng thái đề tài:** ĐÃ HOÀN THIỆN TOÀN BỘ 8 GIAI ĐOẠN (A - H) - ĐẠT CHUẨN KIỂM ĐỊNH KHOA HỌC THỰC NGHIỆM

---

## TÓM TẮT ĐỒ ÁN (EXECUTIVE SUMMARY)

Đồ án tốt nghiệp giải quyết trực diện bài toán trọng tâm trong lĩnh vực An toàn thông tin và DevSecOps hiện đại: **Tình trạng quá tải báo động giả (False Positive Alert Fatigue)** và **sự thiếu vắng cơ chế định lượng mức độ rủi ro động có giải thích** trong các công cụ Phân tích tĩnh mã nguồn (SAST) nguồn mở truyền thống.

Bám sát và hiện thực hóa đầy đủ các định hướng chỉ đạo của Giảng viên hướng dẫn:
1. **100% Mã nguồn mở & Quyền riêng tư cục bộ (On-Premise Privacy):** Sử dụng engine phân tích tĩnh mã nguồn mở **OpenGrep v1.25.0** (bản quyền LGPL-2.1) thay thế cho Semgrep; toàn bộ suy luận AI được vận hành cục bộ trên GPU NVIDIA GeForce RTX 4060 Ti qua mô hình ngôn ngữ lớn `Qwen2.5-Coder-1.5B-Instruct` kết hợp trọng số LoRA 73.9MB. Hệ thống kích hoạt cơ chế `THESIS_LOCAL_ONLY_MODE` fail-closed, tuyệt đối không gửi mã nguồn ra các Cloud API công cộng.
2. **Hiện thực hóa Đầy đủ 2 Giai đoạn:**
   - *Giai đoạn Huấn luyện (Training Pipeline):* Tinh chỉnh mô hình `Qwen2.5-Coder-1.5B` qua kỹ thuật QLoRA 4-bit (NF4) cho bài toán phân loại vai trò ngữ nghĩa API Java (Stage 3). Trên tập kiểm thử độc lập gồm **330 mẫu held-out**, mô hình đạt F1-score nhận diện điểm chìm (**Sink**) là **0.84** (Precision 0.86, Recall 0.83), điểm nguồn (**Source**) là **0.76** (Precision 0.89, Recall 0.66) và độ chính xác nghiêm ngặt toàn cục đạt **67.58%**.
   - *Giai đoạn Vận hành (Operation Pipeline):* Tích hợp thành luồng khép kín: OpenGrep đóng vai trò bộ lọc thô tĩnh tốc độ cao; mô hình LoRA đóng vai trò chuyên gia thẩm định ngữ nghĩa vị trí gọi hàm; và thuật toán **SAST Observable Evidence Scoring V2.1** tổng hợp điểm rủi ro $[0.0, 100.0]$ phục vụ việc tái ưu tiên cảnh báo.
3. **Đóng góp về Phương pháp Chấm điểm SAST Dựa trên Bằng chứng Quan sát được:** Đề xuất mô hình chấm điểm 2 tầng lấy cảm hứng từ nguyên lý phân tích rủi ro an toàn phần mềm, kết hợp 4 thành phần ($S_{eff}, P, C_{sem}, E$) với hệ số hạ bậc bảo thủ ($\gamma = 0.35$). Cơ chế này khắc phục triệt để bẫy Category Error (không đánh đồng vai trò API `none` với False Positive tuyệt đối) và ngăn ngừa rủi ro bỏ sót lỗ hổng nguy cấp.
4. **Kiểm định Thực nghiệm và Phân tích Sai số Minh bạch:** Hệ thống được kiểm chứng end-to-end trên các kho mã nguồn Java thực tế (`mini_vulnerable_java_CVE-89_1.0`, `jeecgboot_CVE-2025-51825`). Báo cáo trình bày trung thực các hạn chế về năng lực mô hình đối với lớp `taint-propagator` (Recall 36.05%) và các bài học kỹ thuật rút ra, đáp ứng tiêu chuẩn nghiên cứu khoa học trung thực và có khả năng tái lập.

---

## CHƯƠNG 1: GIỚI THIỆU VÀ TÍNH CẤP THIẾT CỦA ĐỀ TÀI

### 1.1. Bối cảnh bài toán
Phân tích tĩnh mã nguồn (Static Application Security Testing - SAST) là chốt chặn không thể thiếu trong chu trình phát triển phần mềm an toàn (SSDLC). Tuy nhiên, các công cụ SAST dựa trên quy tắc tĩnh (Rule-based) thường bộc lộ những hạn chế lớn:
- **Tỷ lệ báo động giả cao:** Do giới hạn trong việc phân tích liên thủ tục và thiếu thông tin ngữ cảnh nghiệp vụ, các công cụ SAST thường cảnh báo các vị trí gọi hàm an toàn (đã qua kiểm tra dữ liệu hoặc nằm trong hàm test) như lỗ hổng thật.
- **Thang đo mức độ nghiêm trọng tĩnh:** Severity chỉ gồm các mức cố định (`ERROR`, `WARNING`, `INFO`) do người viết rule định nghĩa sẵn, không phản ánh được khả năng khai thác thực tế hay sự hiện diện của luồng dữ liệu bẩn.
- **Rào cản quyền riêng tư của Cloud LLM:** Việc gửi mã nguồn độc quyền của doanh nghiệp lên các dịch vụ đám mây vi phạm nghiêm trọng chính sách bảo mật dữ liệu.

### 1.2. Mục tiêu nghiên cứu của đồ án
- Nghiên cứu cơ chế vận hành của công cụ nguồn mở **OpenGrep** thay thế cho Semgrep.
- Xây dựng quy trình tinh chỉnh (Fine-tuning) mô hình ngôn ngữ lớn chạy cục bộ chuyên biệt cho bài toán phân loại ngữ nghĩa lời gọi hàm Java (Stage 3).
- Đề xuất mô hình chấm điểm ưu tiên rủi ro SAST dựa trên bằng chứng quan sát được.
- Đóng gói và kiểm thử hệ thống vận hành hoàn chỉnh với khả năng xuất bản báo cáo đa định dạng (JSON, CSV, SARIF và Interactive Web Dashboard).

---

## CHƯƠNG 2: KIẾN TRÚC HỆ THỐNG HYBRID 2-TIER

Hệ thống được tổ chức thành 2 giai đoạn độc lập nhưng kết nối chặt chẽ qua các hợp đồng dữ liệu chuẩn hóa:

```
+-----------------------------------------------------------------------------------+
|                        KIẾN TRÚC HYBRID 2-TIER FRAMEWORK                          |
+-----------------------------------------------------------------------------------+
| [MÃ NGUỒN JAVA MỤC TIÊU]                                                          |
|        |                                                                          |
|        v                                                                          |
| +-------------------------------------------------------------------------------+ |
| | TẦNG 1: ENGINE PHÂN TÍCH TĨNH TỐC ĐỘ CAO (OPENGREP v1.25.0)                   | |
| | - Nạp bộ rule chuẩn hóa (p-java.yaml)                                         | |
| | - Quét cú pháp AST & Taint Tracking trong vài giây                            | |
| | - Xuất danh sách cảnh báo thô (Raw Findings, SARIF, JSON)                     | |
| +-------------------------------------------------------------------------------+ |
|        |                                                                          |
|        v                                                                          |
| +-------------------------------------------------------------------------------+ |
| | TẦNG 2: THẨM ĐỊNH NGỮ NGHĨA CỤC BỘ & TÁI ƯU TIÊN RỦI RO                       | |
| | - Bóc tách ngữ cảnh (Package, Class, Method, Signature)                       | |
| | - Suy luận qua mô hình LoRA Qwen2.5-Coder-1.5B (Local GPU, 100% Privacy)      | |
| | - Thuật toán SAST Observable Evidence Scoring V2.1                            | |
| | - Xuất báo cáo đa định dạng: SARIF, JSON, CSV, Interactive HTML Dashboard     | |
| +-------------------------------------------------------------------------------+ |
```

---

## CHƯƠNG 3: QUY TRÌNH HUẤN LUYỆN VÀ KẾT QUẢ THỰC NGHIỆM

### 3.1. Thiết kế bộ dữ liệu và quy trình huấn luyện QLoRA
- **Mô hình nền tảng:** `Qwen2.5-Coder-1.5B-Instruct` (Alibaba Cloud / HuggingFace).
- **Kỹ thuật tinh chỉnh:** QLoRA 4-bit (NF4), rank $r = 16$, alpha $\alpha = 32$, áp dụng trên các module attention (`q_proj`, `k_proj`, `v_proj`, `o_proj`, `gate_proj`, `up_proj`, `down_proj`).
- **Trọng số LoRA (Adapter):** Kích thước 73.9 MB (`adapter_model.safetensors`), thời gian nạp trọng số 2.1 giây trên GPU RTX 4060 Ti.

### 3.2. Đánh giá thực nghiệm độc lập trên 330 mẫu Held-Out Test
- **Độ chính xác nghiêm ngặt (Strict Accuracy):** **67.58%**
- **Hiệu năng theo từng lớp:**
  - `sink`: Precision = 0.86, Recall = 0.83, **F1 = 0.84** (59 mẫu)
  - `source`: Precision = 0.89, Recall = 0.66, **F1 = 0.76** (109 mẫu)
  - `none`: Precision = 0.50, Recall = 0.93, **F1 = 0.65** (76 mẫu)
  - `taint-propagator`: Precision = 0.62, Recall = 0.36, **F1 = 0.46** (86 mẫu)

---

## CHƯƠNG 4: MÔ HÌNH CHẤM ĐIỂM SAST SCORING V2.1 VÀ PHÂN TÍCH ĐỘ NHẠY

### 4.1. Công thức tính điểm rủi ro
$$RawScore = 100 \times \left( 0.35 \cdot S_{eff} + 0.10 \cdot P + 0.30 \cdot C_{sem} + 0.25 \cdot E \right)$$
$$FinalScore = \text{round}\left( RawScore \times \gamma, 1 \right)$$

Hệ số hạ bậc bảo thủ $\gamma$:
- $\gamma = 1.00$ cho cảnh báo được xác nhận là `LIKELY_VULNERABLE` (hàm Sink).
- $\gamma = 0.90$ cho cảnh báo liên quan đến `POTENTIAL_TAINT_ENTRY` hoặc `PROPAGATION_DETECTED`.
- $\gamma = 0.75$ cho cảnh báo cần rà soát bổ sung (`NEEDS_REVIEW`).
- $\gamma = 0.35$ cho cảnh báo nghi ngờ báo động giả (`SUSPECTED_FALSE_POSITIVE`).

### 4.2. Kết quả kiểm chứng trên Java Fixture thực tế
Quét trên `mini_vulnerable_java_CVE-89_1.0`:
1. `XxeExample.java` (XXE - CWE-611): Điểm rủi ro **75.5** (Mức HIGH)
2. `SqlInjection.java` (SQLi - CWE-089): Điểm rủi ro **73.0** (Mức HIGH)
3. `WeakHash.java` (MD5 Hash - CWE-327): Điểm rủi ro **14.4** (Mức BENIGN_OR_FP, đã hạ bậc thành công)

---

## CHƯƠNG 5: HẠN CHẾ, PHÂN TÍCH SAI SỐ VÀ HƯỚNG PHÁT TRIỂN
1. **Recall của lớp Taint-Propagator:** Mô hình 1.5B gặp khó khăn với các hàm chuyển đổi chuỗi phức tạp. Trong các phiên bản tương lai, việc kết hợp tóm tắt AST liên thủ tục sẽ giúp cải thiện chỉ số này.
2. **Mẫu ngắt dòng JSON:** Cần duy trì tham số `max_new_tokens >= 128` đối với các phương thức Java có chữ ký dài.
3. **Mở rộng sang các ngôn ngữ khác:** Kiến trúc module hóa của NTK cho phép mở rộng sang C/C++, Python và Go bằng cách bổ sung ruleset OpenGrep tương ứng.

---

## KẾT LUẬN
Đồ án đã hoàn thành xuất sắc các mục tiêu nghiên cứu và yêu cầu thực tế của Giảng viên hướng dẫn: xây dựng thành công công cụ phát hiện lỗ hổng mã nguồn kết hợp OpenGrep và LLM cục bộ, đạt chất lượng khoa học cao, bảo toàn quyền riêng tư tuyệt đối và có thể bảo vệ vững chắc trước hội đồng chuyên môn.
