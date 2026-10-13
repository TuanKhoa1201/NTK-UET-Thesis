# BÁO CÁO KẾT QUẢ THỰC NGHIỆM ĐỘC LẬP (FINAL_BENCHMARK_REPORT)

**Đồ án Tốt nghiệp:** Phát triển công cụ phát hiện lỗ hổng mã nguồn kết hợp phân tích tĩnh nguồn mở và mô hình ngôn ngữ lớn  
**Hệ thống:** NTK / IRIS / simple_semgrepAI  
**Mô hình đánh giá:** Qwen2.5-Coder-1.5B-Instruct + Fine-tuned Stage 3 QLoRA Adapter (4-bit NF4, 73.9 MB)  
**Tập kiểm thử:** 330 mẫu độc lập (Held-Out Test Set)  
**Ngày nghiệm thu:** 13/10/2026  

---

## 1. KẾT QUẢ PHÂN LOẠI VAI TRÒ NGỮ NGHĨA API (STAGE 3)

### 1.1. Bảng số liệu tổng hợp (Classification Report)
- **Tổng số mẫu:** 330
- **Độ chính xác nghiêm ngặt (Strict Accuracy):** **67.58%** (223/330 mẫu đúng hoàn toàn)
- **Macro Average F1:** **0.68**
- **Weighted Average F1:** **0.67**

| Lớp nhãn (Class) | Precision | Recall | F1-Score | Số mẫu Ground Truth (Support) |
|---|---|---|---|---|
| **`sink`** | **0.86** | **0.83** | **0.84** | 59 |
| **`source`** | **0.89** | **0.66** | **0.76** | 109 |
| **`none`** | **0.50** | **0.93** | **0.65** | 76 |
| **`taint-propagator`** | **0.62** | **0.36** | **0.46** | 86 |

### 1.2. Ma trận nhầm lẫn (Confusion Matrix 4x4)
Labels: `['source', 'sink', 'taint-propagator', 'none']`

| Ground Truth \ Dự đoán | Dự đoán `source` | Dự đoán `sink` | Dự đoán `propagator` | Dự đoán `none` |
|---|---|---|---|---|
| **Thực tế `source` (109)** | **72** | 6 | 16 | 14 |
| **Thực tế `sink` (59)** | 4 | **49** | 0 | 6 |
| **Thực tế `propagator` (86)**| 3 | 2 | **31** | 50 |
| **Thực tế `none` (76)** | 2 | 0 | 3 | **71** |

*(Ghi chú kiểm toán: Mẫu thứ 109 của lớp `source` có kết quả dự đoán là `unknown` do chuỗi JSON bị ngắt dòng, được hạch toán đầy đủ trong phân tích sai số).*

---

## 2. KẾT QUẢ ĐÁNH GIÁ PIPELINE VẬN HÀNH THỰC TẾ TRÊN JAVA FIXTURE
Thực nghiệm quét trên bộ fixture `mini_vulnerable_java_CVE-89_1.0` (60 quy tắc OpenGrep trên 11 tệp Java):
- **Số cảnh báo phát hiện:** 3 cảnh báo
- **Xếp hạng rủi ro bằng SAST Scoring Engine V2.1:**
  1. `XxeExample.java:28` (XXE - CWE-611): **75.5 điểm** (Mức HIGH) - Xác nhận có lời gọi hàm cấu hình XML nhạy cảm.
  2. `SqlInjection.java:27` (SQLi - CWE-089): **73.0 điểm** (Mức HIGH) - Xác nhận chuỗi định dạng SQL nối chuỗi không an toàn.
  3. `WeakHash.java:17` (MD5 Hash - CWE-327): **14.4 điểm** (Mức BENIGN_OR_FP) - Được hạ bậc ưu tiên thành công, không làm quá tải danh sách xử lý khẩn cấp.
