# SecureSign Cloud 2.1 — Hướng dẫn chi tiết (tiếng Việt)

> README chính của bài nộp nằm ở `../README.md`. Tài liệu này giữ hướng dẫn triển khai, phân quyền và danh sách API của SecureSign. Bản cuối kỳ bổ sung chữ ký ECDSA P-256, biên nhận ký số chống chối bỏ, tài khoản mẫu và biến `TRUST_PROXY_HEADERS` (chỉ tin `X-Forwarded-For` khi chạy sau reverse proxy như Caddy/Vercel).

Nền tảng web ký số PDF RSA-PSS/SHA-256 dành cho nhiều tài khoản. Người dùng tự đăng ký, đăng nhập, tạo khóa riêng, ký PDF, gửi tài liệu cho người dùng khác và xác thực chữ ký. Dữ liệu tài khoản, khóa, tài liệu và lịch sử được phân tách theo quyền truy cập.

> **Phạm vi:** Đây là bản MVP multi-user có cấu trúc triển khai Internet bằng Docker hoặc Vercel, PostgreSQL và HTTPS. Chưa phải dịch vụ ký số được cấp phép, chưa dùng chứng thư số CA/PAdES và chưa được kiểm toán bảo mật độc lập. Không dùng cho hợp đồng hoặc giao dịch pháp lý quan trọng.

## 1. Chức năng

- Đăng ký tự do và đăng nhập bằng email/mật khẩu; môi trường production yêu cầu xác minh email qua Resend API hoặc SMTP.
- Gửi lại email xác minh và đặt lại mật khẩu bằng liên kết dùng một lần, có thời hạn.
- Mật khẩu được băm bằng Argon2id; phiên đăng nhập là token ngẫu nhiên lưu dạng hash trong database, dùng cookie HttpOnly.
- CSRF token cho các thao tác thay đổi dữ liệu; kiểm tra Origin và bổ sung security headers.
- Vai trò `user` và `admin`; tài khoản mới luôn là `user`. Không có API tự nâng quyền.
- Admin có thể xem tài khoản, khóa/mở tài khoản và cấp/hạ quyền admin. Admin được khởi tạo từ biến môi trường, không có tài khoản admin mặc định.
- Mỗi người dùng tự tạo hoặc nhập lại file khóa mã hóa RSA-PSS trong trình duyệt; Private Key được bảo vệ bằng PBKDF2-HMAC-SHA-256 + AES-256-GCM và chỉ tải về/giải mã trên thiết bị người dùng.
- Public Key được đăng ký gắn với chủ sở hữu sau khi chứng minh quyền sở hữu Private Key bằng challenge RSA-PSS một lần; người dùng có thể tra cứu danh bạ và tự đánh dấu khóa của người khác là tin cậy.
- Ký PDF tách rời `.sig` bằng **RSA-PSS 2048 hoặc ECDSA P-256** (người dùng chọn khi tạo khóa); trình duyệt ký, sau đó máy chủ kiểm tra chữ ký với Public Key đã đăng ký trước khi ghi nhận.
- **Biên nhận ký số chống chối bỏ**: mỗi sự kiện đăng ký/thu hồi khóa, ký PDF, gửi tài liệu, người nhận xác thực được ghi thành biên nhận JSON có dấu thời gian, do máy chủ ký bằng ECDSA P-256 và nối chuỗi băm SHA-256 (`prev_hash`). Người dùng tải biên nhận ở trang Ký tài liệu / Hộp thư / Lịch sử, kiểm tra trong trang Xác thực chữ ký hoặc ngoại tuyến bằng `demos/verify_receipt.py`; admin kiểm tra toàn vẹn cả chuỗi.
- Chọn file bằng kéo thả, có nút **✕ Gỡ** để bỏ file đã chọn.
- Gửi PDF + chữ ký đến email của một tài khoản khác; máy chủ xác minh chữ ký trước khi lưu tài liệu.
- Hộp thư đến/đã gửi; chỉ người gửi và người nhận được tải PDF/chữ ký hoặc xác thực tài liệu.
- Lịch sử hoạt động riêng theo tài khoản.
- PostgreSQL cho môi trường triển khai; SQLite cho phát triển cục bộ.
- Docker Compose + Caddy tự cấp HTTPS khi triển khai với domain hợp lệ.

## Tài khoản mẫu (chạy cục bộ, không cần đăng ký)

Khi chạy cục bộ (không phải `APP_ENV=production`), máy chủ tự tạo các tài khoản sau lúc khởi động. Alice (RSA-PSS 2048) và Bob (ECDSA P-256) đã có Public Key được đăng ký sẵn; file Private Key đã mã hóa nằm trong `demo_data/`, mật khẩu khóa chung là `DemoKey@2026`.

| Vai trò | Email | Mật khẩu | File Private Key |
|---|---|---|---|
| Quản trị viên | `admin@securesign-demo.com` | `Admin@Demo2026` | – |
| Người ký | `alice@securesign-demo.com` | `Alice@Demo2026` | `demo_data/alice.key.json` |
| Người nhận | `bob@securesign-demo.com` | `Bob@Demo2026` | `demo_data/bob.key.json` (ECDSA P-256) |
| Người ngoài | `charlie@securesign-demo.com` | `Charlie@Demo2026` | – (dùng để kiểm tra không xem được tài liệu của người khác) |

File mẫu: `demo_data/contract-demo.pdf` (bản gốc) và `demo_data/contract-demo-tampered.pdf` (đã sửa 1,000 → 9,000 USD).

> Đây là tài khoản **công khai, chỉ để kiểm thử**. Máy chủ từ chối khởi động nếu bật `SECURESIGN_DEMO_ACCOUNTS=true` khi `APP_ENV=production`. Đặt `SECURESIGN_DEMO_ACCOUNTS=false` để tắt khi chạy cục bộ; xóa `storage/securesign.db` để đặt lại toàn bộ dữ liệu.

## 2. Chạy cục bộ trên Windows

Yêu cầu Python 3.11+.

1. Giải nén dự án.
2. Nhấn đúp `start.bat`.
3. Trình duyệt mở `http://127.0.0.1:8000`.
4. Đăng nhập bằng một tài khoản mẫu ở trên, hoặc đăng ký tài khoản mới. Tài khoản tự đăng ký **không tự động là admin**.

Hoặc chạy PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

Cục bộ dùng SQLite trong `storage/securesign.db`; xác minh email tắt mặc định để chạy không cần SMTP. Tính năng đặt lại mật khẩu qua email chỉ hoạt động khi cấu hình Resend API hoặc SMTP. Không chạy `--reload` trên production.

## 3. Tạo admin cục bộ

Đặt biến môi trường trước khi chạy server (PowerShell):

```powershell
$env:ADMIN_EMAIL="admin@example.com"
$env:ADMIN_PASSWORD="DoiMatKhauAdminThatDai_2026!"
$env:ADMIN_NAME="System Administrator"
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

Khi khởi động, ứng dụng tạo tài khoản admin nếu chưa tồn tại; nếu đã có, ứng dụng giữ mật khẩu hiện tại và bảo đảm role/status quản trị. Không đặt mật khẩu admin trong source code hoặc commit vào Git. Nếu cần đặt lại mật khẩu bootstrap, tạm đặt `ADMIN_RESET_PASSWORD=true`, khởi động một lần rồi chuyển lại `false`.

## 4. Triển khai Internet trên VPS bằng Docker

Bạn cần:

- Một VPS Linux có Docker Engine và Docker Compose plugin.
- Một domain/subdomain, ví dụ `sign.example.com`.
- DNS A record của domain trỏ đến IPv4 VPS (và AAAA nếu dùng IPv6 đúng cấu hình).
- Mở inbound TCP 80 và 443 trên firewall/VPS.

Các bước:

```bash
cp .env.example .env
```

Sửa `.env`:

- `DOMAIN`: domain thật trỏ đến VPS.
- `POSTGRES_PASSWORD`: mật khẩu database ngẫu nhiên dài, không dùng ví dụ.
- `ADMIN_EMAIL`: email quản trị.
- `ADMIN_PASSWORD`: mật khẩu admin mạnh, duy nhất.
- `RESEND_API_KEY` (khuyến nghị) hoặc `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, cùng `SMTP_FROM`: cấu hình gửi email xác minh tài khoản và đặt lại mật khẩu. Production cần một nhà cung cấp email và `PUBLIC_BASE_URL`.

Tạo mật khẩu database không cần URL-encode:

```bash
openssl rand -hex 32
```

Khởi động:

```bash
docker compose up -d --build
docker compose ps
docker compose logs -f app caddy
```

Truy cập `https://DOMAIN`. Caddy tự xin và gia hạn chứng chỉ TLS nếu DNS và cổng 80/443 hợp lệ. Database và tệp tài liệu nằm trong Docker volumes riêng; không public trực tiếp thư mục storage.

Cập nhật phiên bản:

```bash
docker compose up -d --build
```

Sao lưu volumes `postgres_data` và `app_storage` định kỳ; lưu bản sao mã hóa ngoài VPS. Không xóa volume khi nâng cấp. Tạo mật khẩu database bằng `openssl rand -hex 32` để tránh ký tự cần URL-encode trong `DATABASE_URL`.

## 5. Quy trình sử dụng

1. Đăng ký tài khoản A và B bằng hai email khác nhau.
2. A vào **Quản lý khóa**, tạo cặp RSA (hoặc nhập file khóa mã hóa đã có), tải Private Key đã mã hóa và Public Key PEM; đăng ký Public Key vào tài khoản A.
3. A vào **Ký tài liệu**, chọn PDF và file Private Key, nhập mật khẩu, tạo `.sig`. Khi đăng ký Public Key, trình duyệt ký một challenge ngẫu nhiên để chứng minh người đăng ký có Private Key tương ứng.
4. A vào **Gửi tài liệu**, nhập email B, chọn khóa A, tải PDF và `.sig`, sau đó gửi.
5. B vào **Hộp thư tài liệu**, xem tài liệu, tải PDF/chữ ký và nhấn **Kiểm tra**.
6. B có thể vào **Danh bạ Public Key** và đánh dấu khóa A là tin cậy sau khi đối chiếu fingerprint qua kênh độc lập.

## 6. Phân quyền và cô lập dữ liệu

- `user`: chỉ xem/sửa tài nguyên thuộc quyền của mình; khóa riêng do người dùng tự giữ; chỉ người gửi và người nhận mới truy cập một tài liệu đã trao đổi.
- `admin`: quản lý tài khoản và trạng thái/role; không mặc định có quyền đọc nội dung PDF riêng tư của người dùng.
- Public Key là dữ liệu công khai trong danh bạ; việc đánh dấu tin cậy là quan hệ riêng của từng người dùng.
- Tài khoản tự đăng ký luôn nhận role `user`. Role admin chỉ được cấp bởi admin hiện tại hoặc biến môi trường bootstrap.
- API kiểm tra quyền ở phía server; ẩn nút trên giao diện không được xem là biện pháp bảo mật.

## 7. API chính

| Endpoint | Chức năng | Quyền |
|---|---|---|
| `POST /api/auth/register` | Đăng ký | Công khai |
| `POST /api/auth/login` | Đăng nhập | Công khai |
| `GET /api/auth/verify-email` | Xác minh email | Token một lần |
| `POST /api/auth/forgot-password` | Yêu cầu đặt lại mật khẩu | Công khai, rate-limited |
| `POST /api/auth/reset-password` | Đặt lại mật khẩu | Token một lần |
| `GET /api/auth/verify-email` | Xác minh email qua token | Công khai, token một lần |
| `POST /api/auth/forgot-password` | Yêu cầu liên kết đặt lại mật khẩu | Công khai, rate-limited |
| `POST /api/auth/reset-password` | Đặt lại mật khẩu | Công khai, token một lần |
| `GET /api/auth/me` | Tài khoản hiện tại | Đăng nhập |
| `POST /api/auth/logout` | Đăng xuất | Đăng nhập + CSRF |
| `GET /api/keys/mine` | Khóa của tôi | Đăng nhập |
| `GET /api/keys/directory` | Danh bạ khóa công khai | Đăng nhập |
| `GET /api/keys/{id}/pem` | Tải Public Key PEM | Đăng nhập |
| `POST /api/keys/challenge` | Tạo challenge chứng minh sở hữu khóa | Đăng nhập + CSRF |
| `POST /api/keys` | Đăng ký Public Key của mình | Đăng nhập + CSRF + proof-of-possession |
| `POST /api/history/sign` | Kiểm tra chữ ký và ghi nhận sự kiện ký | Đăng nhập + CSRF |
| `POST /api/verify` | Xác thực PDF + chữ ký | Đăng nhập + CSRF |
| `POST /api/documents/send` | Gửi tài liệu | Đăng nhập + CSRF |
| `GET /api/documents/inbox` | Hộp thư đến | Đăng nhập |
| `GET /api/documents/sent` | Tài liệu đã gửi | Đăng nhập |
| `GET /api/receipts/server-key` | Khóa công khai ký biên nhận | Công khai |
| `GET /api/receipts/{seq}` | Tải biên nhận | Người thực hiện, bên gửi/nhận tài liệu, admin |
| `POST /api/receipts/verify` | Kiểm tra biên nhận (chữ ký máy chủ + có trong chuỗi) | Đăng nhập + CSRF |
| `GET /api/admin/evidence` | Kiểm tra toàn vẹn sổ bằng chứng | Admin |
| `/api/admin/*` | Quản trị tài khoản | Admin |

Tài liệu API: `/api/docs` trong môi trường development; endpoint tài liệu API được tắt ở production.

## 8. Thông số mật mã

| Thành phần | Giá trị |
|---|---|
| RSA | 2048-bit, public exponent 65537 |
| ECC | NIST P-256 (secp256r1), ECDSA SHA-256, chữ ký DER ~72 byte |
| Chữ ký | RSA-PSS hoặc ECDSA P-256 (theo khóa đã đăng ký) |
| Hash | SHA-256 |
| MGF | MGF1-SHA-256 |
| PSS salt | 32 bytes |
| Private Key at-rest | AES-256-GCM |
| KDF | PBKDF2-HMAC-SHA-256, 310,000 iterations |
| Password storage | Argon2id |
| Biên nhận | ECDSA P-256 / SHA-256 do máy chủ ký, chuỗi băm SHA-256 |

PDF không được mã hóa. Chữ ký là detached signature `.sig`, không phải chữ ký nhúng PAdES. Chữ ký xác minh được nội dung byte chính xác; việc mở và lưu lại PDF có thể làm thay đổi byte và làm chữ ký cũ không hợp lệ.

## 9. Những giới hạn cần hoàn thiện trước khi mở cho công chúng

- Đã có xác minh email và đặt lại mật khẩu qua Resend HTTPS API hoặc SMTP; chưa có MFA hoặc đăng nhập SSO.
- Chưa có quota dung lượng theo tài khoản, chính sách lưu trữ/xóa dữ liệu và quét mã độc file tải lên.
- Vercel production yêu cầu Upstash Redis REST để chia sẻ rate limit giữa các Function instance; local mode dùng rate limit trong process.
- Chưa có cơ chế email thông báo khi nhận tài liệu.
- Chưa có quy trình chứng thư số CA, OCSP/CRL, timestamp authority, PAdES hoặc bằng chứng danh tính pháp lý.
- Cần kiểm thử tải, backup/restore, kiểm thử xâm nhập, rà soát cấu hình VPS và đánh giá bảo mật độc lập.
- Admin bootstrap password trong `.env` phải được bảo vệ; đổi mật khẩu sau khi khởi tạo. Không chia sẻ file `.env`.

## 10. Kiểm thử

Cài dependencies kiểm thử và chạy:

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

Bộ kiểm thử bao gồm tạo tài khoản, không tự cấp quyền admin, chứng minh sở hữu khóa, ký/xác thực, gửi nhận PDF, phân tách dữ liệu và kiểm soát quyền truy cập.

## 11. Nâng cấp từ SecureSign 1.0

Phiên bản 2.x dùng schema và cơ sở dữ liệu mới (`storage/securesign.db` khi chạy SQLite); không tự chuyển dữ liệu từ `storage/pdfsign.db` của phiên bản 1.0. Hãy sao lưu thư mục cũ và các file Private Key trước khi thay thế. Có thể dùng mục **Đăng ký khóa đã có** để nhập file Private Key mã hóa từ phiên bản 1.0; trình duyệt giải mã cục bộ và chứng minh quyền sở hữu trước khi đăng ký lại Public Key.

## 12. Cấu trúc

```text
PDF-Digital-Signature-Complete/
├── backend/app/
│   ├── config.py
│   ├── storage_service.py
│   ├── crypto_service.py
│   ├── database.py
│   ├── main.py
│   ├── schemas.py
│   └── security.py
├── frontend/
│   ├── index.html
│   ├── app.js
│   └── style.css
├── storage/
├── tests/
├── docs/ARCHITECTURE.md
├── docs/VERCEL_DEPLOYMENT.md
├── index.py
├── vercel.json
├── .python-version
├── Dockerfile
├── docker-compose.yml
├── Caddyfile
├── .env.example
├── requirements.txt
└── start.bat
```


## 13. Triển khai trên Vercel (khuyến nghị cho đồ án sinh viên)

SecureSign 2.1 có entrypoint `index.py` cho Vercel Python Runtime, dùng Neon PostgreSQL, Vercel Blob **Private** cho PDF/chữ ký và Upstash Redis cho rate limit dùng chung. Email xác minh có thể gửi qua Resend HTTPS API hoặc SMTP.

Đọc hướng dẫn đầy đủ tại [`docs/VERCEL_DEPLOYMENT.md`](docs/VERCEL_DEPLOYMENT.md).

**Giới hạn upload trên Vercel:** PDF tối đa 4 MiB để tổng request multipart nằm dưới giới hạn 4.5 MB của Vercel Functions. Không tăng `SECURESIGN_MAX_UPLOAD_BYTES` nếu chưa triển khai direct-to-Blob client upload.
