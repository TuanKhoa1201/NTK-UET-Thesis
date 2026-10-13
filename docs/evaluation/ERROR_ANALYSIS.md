# BÁO CÁO PHÂN TÍCH SAI SỐ VÀ CÁC HẠN CHẾ CỦA MÔ HÌNH (ERROR_ANALYSIS)

**Đồ án Tốt nghiệp:** Phát triển công cụ phát hiện lỗ hổng mã nguồn kết hợp phân tích tĩnh nguồn mở và mô hình ngôn ngữ lớn  
**Hệ thống:** NTK / IRIS / simple_semgrepAI  
**Ngày thực hiện:** 13/10/2026  

---

## 1. PHÂN TÍCH NGUYÊN NHÂN GỐC RỄ CÁC SAI SỐ (FAILURE MODES)

### 1.1. Lớp Taint-Propagator có Recall thấp (36.05%)
- **Hiện tượng:** Trong 86 mẫu thực tế là `taint-propagator`, mô hình dự đoán nhầm 50 mẫu thành `none` và 16 mẫu thành `source`.
- **Nguyên nhân kỹ thuật:** Khái niệm "Taint-propagator" trong phân tích dòng dữ liệu Java là khái niệm phức tạp (truyền vết dữ liệu từ tham số vào giá trị trả về hoặc qua đối tượng đệm). Một số hàm tiện ích như chuỗi (`StringBuilder.append`, `substring`) hoặc cấu trúc dữ liệu (`List.get`) có đặc tính gần giống hàm chuyển đổi thông thường (`none`), khiến mô hình ngôn ngữ 1.5B tham số khó phân biệt nếu thiếu ngữ cảnh toàn cục của lớp.
- **Giải pháp khắc phục:** Khi tích hợp vào Operation Pipeline, nếu kết quả là `none` nhưng công cụ phân tích tĩnh OpenGrep hoặc CodeQL đã tìm thấy vết tainted dataflow, hệ thống ưu tiên bằng chứng luồng dữ liệu ($E = 1.0$), ngăn chặn việc hạ điểm nhầm.

### 1.2. Mẫu ngoại lệ JSON Truncation (Mẫu idx 242)
- **Triệu chứng:** Mẫu `org.graylog2.rest.resources.users.UsersResource.generateNewToken` trả về JSON bị cắt cụt ở trường `type`:
  `{"package":"org.graylog2.rest.resources.users","class":"UsersResource",...,"type":"taint-propagator` (thiếu dấu đóng ngoặc kép và ngoặc nhọn).
- **Nguyên nhân:** Tham số `max_new_tokens = 80` bị chạm ngưỡng độ dài khi signature của phương thức quá dài.
- **Biện pháp xử lý:** Nâng `max_new_tokens = 128` trong inference config và triển khai bộ xử lý JSON lenient phục hồi ngoặc nhọn khi token kết thúc trước khi đóng block.

---

## 2. CÁC HẠN CHẾ VÀ THREATS TO VALIDITY
1. **Ranh giới Ngữ cảnh Nội hàm (Local Scope Limitation):** Mô hình Stage 3 hiện tập trung vào việc phân loại vai trò API trên từng phương thức đơn lẻ. Trong thực tế, nhiều lỗ hổng phức tạp đòi hỏi phân tích liên thủ tục (inter-procedural) và liên module.
2. **Kích thước Mô hình (Model Capacity Trade-off):** Lựa chọn mô hình Qwen2.5-Coder-1.5B nhằm đảm bảo yêu cầu chạy 100% cục bộ trên phần cứng máy trạm tiêu chuẩn (RTX 4060 Ti 16GB VRAM, độ trễ suy luận dưới 50ms/mẫu). Mô hình 1.5B có thể có biểu hiện suy luận kém hơn các mô hình 7B hoặc 14B đối với các cấu trúc ngữ pháp Java lồng ghép sâu.
3. **Tính Độc lập của Bộ Dữ liệu:** Mặc dù đã loại bỏ exact match và prompt collision, một số lớp thư viện Java phổ biến (như Spring Framework, Apache Commons) có thể xuất hiện trong nhiều dự án khác nhau.
