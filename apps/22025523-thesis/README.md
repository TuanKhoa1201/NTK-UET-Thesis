# 22025523 — Nền tảng nghiên cứu phân tích mã nguồn Java

Ứng dụng React/Vite tiếng Việt trình bày đồ án tốt nghiệp về phân tích bảo mật mã nguồn Java.

## Chạy dự án

```bash
npm install
npm run dev
```

Tạo bản build production:

```bash
npm run build
npm run preview
```

## Chế độ dữ liệu

Giao diện hiển thị **MINH HỌA** khi backend chưa được xác minh. Các finding và tiến trình trong demo là dữ liệu synthetic, không phải kết quả scan thật. Chế độ LIVE chỉ gửi yêu cầu đến API đã cấu hình; frontend không giả lập trạng thái backend.

Tạo `.env.local` để đặt địa chỉ API:

```env
VITE_API_BASE_URL=http://localhost:8000
```

Nếu frontend và backend cùng origin, có thể để trống biến này và phục vụ bản build qua Python backend.

## API adapter

Các request được tập trung tại `src/services/api.js`. Hợp đồng mục tiêu hiện tại:

- `GET /api/health`
- `GET /api/model`
- `POST /api/scans`
- `POST /api/scans/upload` — chưa được xác nhận; giao diện ZIP LIVE giữ trạng thái chờ
- `GET /api/scans/{scan_id}`
- `GET /api/scans/{scan_id}/findings`
- `GET /api/findings/{finding_id}`
- `GET /api/scans/{scan_id}/report`

Đây là adapter dự phòng, không phải xác nhận rằng backend đã triển khai các endpoint. Khi có OpenAPI spec và `FINDING_SCHEMA_V2_FINAL.json`, cập nhật mapping tại `src/services/api.js` theo schema chính thức.

## Dataset và Excel

Data Explorer hiện dùng các bản ghi synthetic nhỏ để minh họa. Dataset chính thức chưa có trong source; chỉ kích hoạt tải dữ liệu nghiên cứu khi artifact thật cùng metadata, version, row count và SHA-256 được cung cấp.

## Logo UET

Đặt ảnh logo UET chính thức đã được xác minh tại `public/uet-logo.png`. Giao diện giữ nguyên tỷ lệ ảnh bằng `object-fit: contain`; không tự dựng logo hoặc sử dụng logo kỷ niệm làm mặc định.

## Tự host trên laptop

Build bằng `npm run build`, sau đó phục vụ nội dung `dist/` qua Python backend hoặc static server cùng origin. Việc giải nén ZIP, kiểm tra archive an toàn và chạy scanner thuộc backend Python. Không đưa secret/API key vào frontend.

## Nội dung nghiên cứu

Số liệu dataset, cấu hình EO06 và controlled benchmark nằm tách biệt trong `src/data/research.js` và các trang nghiên cứu. Metric API role classification không được diễn giải thành metric phát hiện vulnerability. Thông tin UET và đề tài được trình bày như sản phẩm đồ án, không phải cổng thông tin chính thức của trường.