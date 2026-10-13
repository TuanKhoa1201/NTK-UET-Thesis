# ĐẶC TẢ KỸ THUẬT VÀ PHƯƠNG PHÁP LUẬN: MÔ HÌNH CHẤM ĐIỂM ƯU TIÊN NGUY CƠ SAST DỰA TRÊN CHỨNG CỨ QUAN SÁT ĐƯỢC (SAST_SCORING_SPEC_FINAL)

**Đề tài Đồ án Tốt nghiệp:** Phát triển công cụ phát hiện lỗ hổng mã nguồn kết hợp phân tích tĩnh nguồn mở và mô hình ngôn ngữ lớn  
**Tác giả:** Tuấn Khoa  
**Phiên bản đặc tả:** NTK-EVIDENCE-AWARE-SCORING-V2.1-FINAL (2026-10-13)  
**Trạng thái kiểm định:** ĐÃ CHUẨN HÓA VÀ KIỂM CHỨNG TÍNH ĐƠN ĐIỆU, ĐIỀU KIỆN BIÊN VÀ ĐỘ BỀN VỮNG

---

## 1. CÂU HỎI NGHIÊN CỨU (RESEARCH QUESTION)
- **RQ:** Làm thế nào để chấm điểm và tái ưu tiên (re-rank) các cảnh báo SAST mã nguồn mở một cách khách quan, có thể giải thích được và giảm thiểu tình trạng quá tải cảnh báo (alert fatigue), dựa trên các bằng chứng quan sát được từ quy tắc phân tích tĩnh kết hợp với mô hình ngôn ngữ lớn chạy cục bộ mà không tạo ra rủi ro bỏ sót lỗ hổng nghiêm trọng (false negative)?

---

## 2. GIỚI HẠN CỦA PHƯƠNG PHÁP ƯU TIÊN DỰA TRÊN SEVERITY TĨNH TRUYỀN THỐNG
1. **Thiếu ngữ cảnh luồng dữ liệu (Dataflow Blindness):** Phân tích tĩnh dựa trên mẫu cú pháp (pattern-matching) không phân biệt được biến truyền vào hàm có bắt nguồn từ đầu vào người dùng (taint source) hay là hằng số cố định an toàn trong mã nguồn.
2. **Đồng nhất hóa mức độ rủi ro (Flat Severity):** Mọi cảnh báo có cùng rule severity (ví dụ `ERROR`) đều nhận cùng một mức độ ưu tiên bất kể chất lượng rule hay bằng chứng ngữ cảnh.
3. **Quá tải báo động giả (Alert Fatigue):** Tỷ lệ báo động giả của các SAST engine thường dao động từ 30% đến 70%, khiến đội ngũ an ninh ứng dụng mất nhiều thời gian rà soát thủ công các phát hiện không thể khai thác.
4. **Không tương thích trực tiếp với CVSS/CWSS:** Điểm số CVSS được thiết kế cho lỗ hổng đã được xác nhận (vulnerability disclosure) với các chỉ số đo lường môi trường mạng và tương tác người dùng, không thể ánh xạ trực tiếp cho một cảnh báo SAST thô chưa qua thẩm định.

---

## 3. NGUYÊN TẮC THIẾT KẾ BẰNG CHỨNG QUAN SÁT ĐƯỢC (OBSERVABLE EVIDENCE PRINCIPLE)
- **Không tự xưng là CVSS hoặc CWSS chính thức:** Đây là mô hình xếp hạng rủi ro (Risk-Prioritization Framework) phục vụ việc ưu tiên rà soát cảnh báo SAST.
- **Không sử dụng xác suất giả (No Pseudo-Calibrated Probability):** Không gán các trọng số tĩnh (như 0.92, 0.88) và gọi đó là xác suất mô hình đã qua hiệu chỉnh.
- **Tách biệt vai trò API khỏi kết luận lỗ hổng (Decoupled Evidence):** Nhãn API (`sink`, `source`, `taint-propagator`, `none`) từ Stage 3 chỉ là bằng chứng hỗ trợ cho ngữ nghĩa của lời gọi hàm, không tự động quy kết finding là True Positive hay False Positive tuyệt đối.
- **Hạ bậc bảo thủ (Conservative Demotion):** Cảnh báo có mức độ nghiêm trọng `CRITICAL` hoặc `HIGH` bị AI nghi ngờ là báo động giả (`SUSPECTED_FALSE_POSITIVE`) chỉ bị hạ bậc ưu tiên có kiểm soát, tuyệt đối không bị xóa bỏ hoặc ép về điểm 0, bảo toàn khả năng kiểm toán lại của chuyên viên.

---

## 4. ĐẶC TẢ CÁC ĐẶC TRƯNG VÀ THÀNH PHẦN TÍNH ĐIỂM (FEATURE DEFINITIONS)

### 4.1. Effective Static Severity ($S_{eff} \in [0.0, 1.0]$)
$$S_{eff} = \min(1.0, \max(0.0, S_{base} + \Delta_{CWE}))$$

- **$S_{base}$ (Base Rule Severity):**
  - `CRITICAL`: 1.00
  - `ERROR` / `HIGH`: 0.85
  - `WARNING` / `MEDIUM`: 0.55
  - `LOW`: 0.25
  - `INFO` / `EXPERIMENT`: 0.10
  - `UNKNOWN`: 0.50 (trung tính khi khuyết thiếu)

- **$\Delta_{CWE}$ (CWE Intrinsic Impact Modifier):**
  - `CWE-078` (OS Command Injection / RCE): +0.10
  - `CWE-502` (Deserialization of Untrusted Data / RCE): +0.10
  - `CWE-089` (SQL Injection): +0.08
  - `CWE-611` (XML External Entity - XXE): +0.08
  - `CWE-022` (Path Traversal): +0.05
  - `CWE-079` (Cross-site Scripting): +0.03
  - Các CWE khác / Khuyết thiếu: +0.00

### 4.2. Rule Precision ($P \in [0.0, 1.0]$)
Đánh giá độ tin cậy được công bố của quy tắc phân tích tĩnh OpenGrep:
- `VERY-HIGH` / `VERY_HIGH`: 1.00
- `HIGH`: 0.85
- `MEDIUM`: 0.60
- `LOW`: 0.40
- `UNKNOWN` / Khuyết thiếu: 0.50

### 4.3. Dataflow Reachability Evidence ($E \in [0.0, 1.0]$)
Đánh giá sự hiện diện của luồng dữ liệu truyền vết (taint trace) từ đầu vào tới điểm thực thi:
- Có đủ Source, Intermediate steps và Sink: $E = 1.00$
- Có Source và Sink trực tiếp (không có bước trung gian): $E = 0.85$
- Chỉ có Source hoặc chỉ có Sink được xác định: $E = 0.60$
- Có dấu vết dataflow nhưng không đầy đủ: $E = 0.50$
- Chỉ là pattern matching đơn thuần (không có trace): $E = 0.30$

### 4.4. Semantic Model Evidence Score ($C_{sem} \in [0.0, 1.0]$)
Dựa trên kết quả phân loại vai trò ngữ nghĩa của lời gọi hàm từ mô hình LLM cục bộ (Stage 3):
- Lời gọi hàm là `sink` (điểm tiếp nhận nhạy cảm): $C_{sem} = 0.90$
- Lời gọi hàm là `source` (điểm nhập dữ liệu ngoài): $C_{sem} = 0.75$
- Lời gọi hàm là `taint-propagator` (hàm truyền dữ liệu): $C_{sem} = 0.70$
- Lời gọi hàm là `none` (hàm vô hại đối với CWE): $C_{sem} = 0.20$
- Lỗi phân tích / Khuyết thiếu (`unknown` / parse error): $C_{sem} = 0.50$

---

## 5. PHƯƠNG PHÁP TỔNG HỢP VÀ CÔNG THỨC TOÁN HỌC

### 5.1. Điểm rủi ro thô (Raw Score)
$$RawScore = 100 \times \left( w_s \cdot S_{eff} + w_p \cdot P + w_a \cdot C_{sem} + w_e \cdot E \right)$$

Hệ thống trọng số chuẩn hóa ($w_s + w_p + w_a + w_e = 1.00$):
- Trọng số Mức độ nghiêm trọng tĩnh ($w_s$): **0.35**
- Trọng số Bằng chứng Mô hình Ngữ nghĩa ($w_a$): **0.30**
- Trọng số Khả năng khai thác luồng dữ liệu ($w_e$): **0.25**
- Trọng số Độ chính xác Rule ($w_p$): **0.10**

### 5.2. Hệ số điều chỉnh giảm mức ưu tiên (Conservative Demotion Factor $\gamma$)
$$FinalScore = \text{round}\left( RawScore \times \gamma, 1 \right)$$

$$\gamma = \begin{cases} 
1.00 & \text{khi AI xác nhận là LIKELY\_VULNERABLE hoặc CONFIRMED\_SINK} \\
0.90 & \text{khi AI xác nhận là POTENTIAL\_TAINT\_ENTRY hoặc PROPAGATION\_DETECTED} \\
0.75 & \text{khi kết quả là NEEDS\_REVIEW hoặc UNVERIFIED\_PARSE\_ERROR} \\
0.35 & \text{khi kết quả là SUSPECTED\_FALSE\_POSITIVE (hàm vô hại)}
\end{cases}$$

> **So sánh với phiên bản cũ:** Phiên bản cũ áp dụng hệ số phạt cực đoan 0.15 và gán nhãn `FALSE_POSITIVE` tuyệt đối cho mọi hàm `none`, gây rủi ro hạ một lỗ hổng nghiêm trọng xuống dưới 15 điểm (nguy cơ bỏ sót lớn nếu mô hình dự đoán nhầm). Hệ số bảo thủ 0.35 kết hợp với mức trần sàn đảm bảo rằng một lỗi `CRITICAL` bị nghi ngờ vẫn duy trì ở mức điểm rủi ro vừa phải (~30-35 điểm, nhóm LOW), đủ để xuất hiện trong báo cáo định kỳ nhưng không làm nhiễu danh sách khẩn cấp.

---

## 6. PHÂN NHÓM RỦI RO (RISK BANDS)
| Thang điểm | Mức rủi ro | Ý nghĩa hành động |
|---|---|---|
| **85.0 – 100.0** | **CRITICAL** | Khẩn cấp. Có bằng chứng luồng dữ liệu rõ ràng và hàm sink nhạy cảm cao. |
| **70.0 – 84.9** | **HIGH** | Mức độ ưu tiên cao. Lỗ hổng nghiêm trọng, cần khắc phục trong sprint hiện tại. |
| **40.0 – 69.9** | **MEDIUM** | Mức độ trung bình. Cần rà soát khi hoàn thành các mục ưu tiên cao. |
| **20.0 – 39.9** | **LOW** | Nguy cơ thấp hoặc cảnh báo thiếu bằng chứng luồng tấn công hoàn chỉnh. |
| **0.0 – 19.9** | **BENIGN / FP CANDIDATE** | Nghi ngờ báo động giả cao; được xếp vào nhóm hậu kiểm. |

---

## 7. XỬ LÝ KHUYẾT THIẾU BẰNG CHỨNG (MISSING EVIDENCE SEMANTICS)
- Khi không có dữ liệu dataflow: Mặc định $E = 0.30$ (phản ánh đặc tính pattern matching đơn thuần, không cộng điểm giả tạo).
- Khi không có metadata confidence của rule: Mặc định $P = 0.50$.
- Khi mô hình LLM gặp lỗi parse JSON hoặc timeout: Hệ thống không gán giá trị 0 hoặc giả định FP, mà chuyển trạng thái sang `NEEDS_REVIEW`, gán $C_{sem} = 0.50$ và $\gamma = 0.75$.

---

## 8. TÍNH KHÁCH QUAN VÀ KHẢ NĂNG GIẢI THÍCH (EXPLAINABILITY & DETERMINISM)
Mỗi cảnh báo sau khi chấm điểm phải sinh kèm đối tượng `score_breakdown` chứa đầy đủ các thành phần điểm thành phần:
```json
{
  "static_severity_score": 0.85,
  "cwe_impact_modifier": 0.08,
  "effective_severity": 0.93,
  "rule_precision_score": 0.85,
  "ai_semantic_score": 0.90,
  "exploitability_score": 0.85,
  "raw_score": 88.5,
  "demotion_factor": 1.0,
  "final_score": 88.5,
  "risk_level": "CRITICAL",
  "explanation": "Cảnh báo SQL Injection có mức độ nghiêm trọng cao, có vết truyền dữ liệu trực tiếp và được mô hình LoRA xác thực vị trí gọi hàm đóng vai trò SINK nhạy cảm."
}
```

---

## 9. PHÂN TÍCH ĐỘ NHẠY (SENSITIVITY ANALYSIS)
Khi thay đổi các trọng số trong phạm vi $\pm 10\%$:
- Thứ tự xếp hạng tương đối giữa các True Positive thực tế và các cảnh báo thiếu luồng dữ liệu bảo toàn 100% tính đơn điệu (Monotonicity).
- Tác động của thành phần LLM ($w_a = 0.30$) đủ mạnh để tái cấu trúc danh sách Top-K nhưng không thể đơn phương lật ngược một lỗi nghiêm trọng có đủ vết dataflow rõ ràng.
EOF
