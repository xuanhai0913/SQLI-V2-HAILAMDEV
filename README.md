# SQLI-V2-HAILAMDEV

Khung CLI viết bằng Go cho nghiên cứu và kiểm thử SQL Injection trong môi trường được ủy quyền. Dự án mô hình hóa một pipeline gồm phát hiện điểm tiêm, nhận diện DBMS, biến đổi payload, trích xuất dữ liệu và các bước hậu khai thác.

> **Disclaimer — authorized lab/research only:** Chỉ sử dụng dự án trên hệ thống, cơ sở dữ liệu và endpoint mà bạn sở hữu hoặc có sự cho phép bằng văn bản. Không sử dụng để truy cập trái phép, lấy dữ liệu của bên thứ ba, duy trì truy cập, phát tán payload hoặc phá hoại hệ thống.

> **Cảnh báo:** Mã nguồn có các module liên quan đến UDF/shell, persistence và thao tác phá hủy dữ liệu. Hãy giữ `destruct_mode: "none"`, dùng database thử nghiệm có snapshot và không chạy trên production.

## Dự án là gì?

SQLI-V2-HAILAMDEV **không phải scanner thụ động thông thường**. Đây là prototype mô phỏng chuỗi kiểm thử SQLi:

1. Phát hiện điểm tiêm và kỹ thuật phù hợp.
2. Nhận diện DBMS và dấu hiệu WAF.
3. Áp dụng các phép biến đổi payload ở tầng SQL/HTTP.
4. Mô phỏng trích xuất schema và dữ liệu.
5. Mô phỏng các bước hậu khai thác như UDF, shell và persistence.
6. Có module thao tác phá hủy để phục vụ nghiên cứu trong lab cô lập.

Nhiều engine hiện vẫn là stub hoặc placeholder. Kết quả rỗng, thành công giả lập hoặc output mẫu không chứng minh target an toàn hay thao tác đã thực sự thành công.

## Kiến trúc source hiện tại

```text
.
├── config/
│   └── sqli.yaml             # Cấu hình runtime
├── src/
│   ├── main.go               # Entry point
│   ├── cmd/root.go           # CLI, session và điều phối lệnh
│   ├── core/
│   │   ├── engine.go         # Session, phát hiện và pipeline chính
│   │   └── exfil.go          # Logic trích xuất và parser mẫu
│   ├── tamper/engine.go      # Các phép biến đổi payload/HTTP
│   └── post/
│       ├── shell.go          # UDF và shell hậu khai thác
│       ├── persist.go        # Các phương thức persistence
│       └── destruct.go       # DROP/TRUNCATE/CORRUPT/ENCRYPT
├── signatures/
│   ├── payloads/             # Tài liệu payload
│   └── udf_source/           # Source UDF theo DBMS
├── docs/                     # Tài liệu API, build và sử dụng
├── Makefile
├── go.mod
└── README.md
```

## Các lệnh chính

```text
sqli
├── exploit       Chạy pipeline kiểm thử tổng hợp
├── detect        Phát hiện điểm tiêm và DBMS
├── dump          Trích xuất schema/dữ liệu
├── shell         Kiểm thử shell thông qua UDF
├── persist       Kiểm thử cơ chế persistence
├── destruct      Thao tác phá hủy (yêu cầu --confirm)
├── session       Quản lý session
├── tamper        Liệt kê và thử các script biến đổi payload
├── config        Quản lý cấu hình
└── version       In thông tin phiên bản
```

Tên lệnh và flag được giữ nguyên bằng tiếng Anh để tương thích với CLI; mô tả, comment, log và thông báo lỗi trong source đã được Việt hóa.

Một số tùy chọn cấp root:

```text
--config       File cấu hình, mặc định ./config/sqli.yaml
--output, -o   Định dạng kết quả: json, csv hoặc table
--verbose      Bật log chi tiết
--no-color     Tắt màu trong output
```

Xem trợ giúp trước khi dùng:

```bash
./bin/sqli --help
./bin/sqli detect --help
./bin/sqli tamper --help
```

## Yêu cầu và build

- Go 1.21 trở lên.
- C compiler nếu build các phần phụ thuộc CGO/DB driver.
- Database thử nghiệm và endpoint thuộc phạm vi được ủy quyền.
- Snapshot/backup có thể khôi phục trước mọi kiểm thử hậu khai thác.

Quy trình build dự kiến:

```bash
go mod download
make build
```

Makefile còn chứa các target `test`, `lint`, `vet`, `docker` và `clean`. Hãy kiểm tra source và môi trường trước khi chạy vì repository hiện chưa có test fixture hoàn chỉnh.

## Cấu hình

File mẫu: [`config/sqli.yaml`](config/sqli.yaml)

Các nhóm cấu hình chính:

- `engine`: số luồng, timeout, retry, redirect, proxy và user-agent.
- `detector`: phát hiện DBMS/WAF và thứ tự kỹ thuật kiểm thử.
- `tamper`: bật chain biến đổi payload.
- `exfil`: phương thức, batch, concurrency và endpoint OOB.
- `post_exploit`: UDF, shell, persistence và chế độ phá hủy.
- `reporting`: thư mục output, format và proof.
- `signatures`: đường dẫn payload và source UDF.

Cấu hình lab an toàn tối thiểu:

```yaml
post_exploit:
  destruct_mode: "none"
  encrypt_key: ""

exfil:
  dns_domain: ""
  http_endpoint: ""
```

Không lưu credential, token, webhook hoặc dữ liệu thật trong repository. Các đường dẫn cấu hình cục bộ nên được truyền qua `--config` hoặc biến môi trường `SQLI_*`.

## Trạng thái triển khai

| Thành phần | Trạng thái hiện tại |
|---|---|
| CLI, session và config | Có khung xử lý |
| Detection và DBMS fingerprint | Có flow/heuristic, cần kiểm thử và hoàn thiện |
| UNION extraction | Có flow, parser hiện trả dữ liệu mẫu |
| Blind/Time/Error/Stacked/OOB | Stub hoặc chưa hoàn chỉnh |
| Tamper SQL/HTTP | Có một số phép biến đổi mẫu; modifier HTTP còn hạn chế |
| UDF/shell | Có khung; biên dịch UDF chưa triển khai đầy đủ |
| Persistence | Có các nhánh theo DBMS; chỉ dùng trong lab cô lập |
| Destruct | Có generator/query template; cực kỳ nguy hiểm và không dùng trên production |
| Test tự động | Chưa có bộ test/fixture đầy đủ |

Một số vấn đề kỹ thuật cần xử lý trước khi coi đây là công cụ production:

- Các file trong `src/core`, `src/post` và `src/tamper` hiện dùng cùng package với `src/cmd` nhưng nằm ở thư mục khác; cần sắp xếp lại package/import để build ổn định.
- Một số dependency và target trong Makefile cần được đối chiếu với source thực tế.
- Parser, output formatter, session error handling và kiểm soát TLS cần được kiểm thử bổ sung.
- Không nên bật endpoint OOB hoặc các module hậu khai thác trong môi trường ngoài lab.

## Tài liệu

- [`docs/BUILD.md`](docs/BUILD.md) — yêu cầu và quy trình build.
- [`docs/USAGE.md`](docs/USAGE.md) — tham chiếu giao diện sử dụng.
- [`docs/API.md`](docs/API.md) — mô tả API dự kiến.
- [`signatures/payloads/README.md`](signatures/payloads/README.md) — tài liệu payload.

## Quy tắc sử dụng an toàn

1. Chỉ kiểm thử khi có phạm vi và sự cho phép rõ ràng bằng văn bản.
2. Ưu tiên database giả lập, snapshot và dữ liệu không nhạy cảm.
3. Không dùng `shell`, `persist` hoặc `destruct` trên hệ thống thật.
4. Giữ `destruct_mode: "none"` và không truyền `--confirm` nếu không có phê duyệt riêng cho bài lab.
5. Ghi lại phạm vi, thời gian, payload và log để có thể audit/rollback.

## Tác giả

**Author:** Nguyen Xuan Hai

- LinkedIn: [linkedin.com/in/xuanhai0913](https://www.linkedin.com/in/xuanhai0913/)
- Facebook: [facebook.com/nguyenhai0913](https://www.facebook.com/nguyenhai0913)

## License

Internal use only — SentinelFlow engagement.
