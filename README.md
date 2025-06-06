# API Key Manager

Hệ thống quản lý API key theo địa chỉ IP người dùng, cho phép kiểm soát và giám sát việc sử dụng API.

## Tính năng

- Tạo và quản lý API key
- Xác thực API key theo địa chỉ IP
- Giới hạn thời gian sử dụng API key
- Theo dõi số lượt sử dụng API key
- Giao diện quản lý trực quan
- API đơn giản để tích hợp

## Yêu cầu

- Node.js (v14 trở lên)
- MongoDB

## Cài đặt

1. Clone repository
```
git clone https://github.com/your-username/api-key-manager.git
cd api-key-manager
```

2. Cài đặt dependencies
```
npm install
```

3. Tạo file `.env` với nội dung
```
PORT=3000
MONGO_URI=your_mongodb_connection_string
ADMIN_TOKEN=your_secure_admin_token
```

4. Khởi động server
```
npm start
```

## Triển khai trên Render.com

Repository này đã được cấu hình để triển khai trên Render.com. Chi tiết cấu hình có trong file `render.yaml`.

## Sử dụng API

### API Authentication

Sử dụng API key trong header:
```
x-api-key: your_api_key
```

### Admin API

Quản lý API key bằng admin token:
```
x-admin-token: your_admin_token
```

## Tài liệu API

### Admin Endpoints

- `POST /admin/keys` - Tạo API key mới
- `GET /admin/keys` - Lấy danh sách API key
- `GET /admin/keys/:id` - Lấy thông tin API key
- `PUT /admin/keys/:id` - Cập nhật API key
- `DELETE /admin/keys/:id` - Xóa API key
- `POST /admin/keys/:id/ip` - Thêm IP
- `DELETE /admin/keys/:id/ip/:ip` - Xóa IP

### Protected API Endpoints

- `GET /api/data` - Endpoint mẫu được bảo vệ

## Giao diện quản lý

Truy cập giao diện quản lý tại:
```
http://localhost:3000
```

## License

MIT#   a p i - k e y  
 #   a p i  
 