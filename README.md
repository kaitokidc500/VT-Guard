# VT-Guard

Nghiên cứu phát hiện hành vi cho đúng năm kỹ thuật T1016, T1049, T1018,
T1087.002 và T1654. Đây là khung xử lý telemetry và kiểm tra chất lượng dữ
liệu; chưa có detector đã huấn luyện.

## Chạy lát cắt hiện tại

Cần Python 3.10 trở lên; phần này chỉ dùng thư viện chuẩn.

```powershell
$env:PYTHONPATH = 'src'
python -m vtguard.cli configs/smoke.json
python -m unittest discover -s tests -v
```

Kết quả smoke ở `artifacts/smoke/`: dữ liệu chuẩn hóa, phép chiếu đầu vào mô
hình, và báo cáo chất lượng. Tất cả đầu ra này chỉ từ fixture tổng hợp. Có thể
thay đường dẫn/cấu hình bằng tệp cục bộ hợp lệ; đường dẫn tương đối trong JSON
được tính từ thư mục gốc project khi tệp config nằm trong `configs/`.

`configs/audit_t1654.json` dùng một tệp Splunk nhỏ lưu riêng trong
`data/public/splunk/` (không đưa vào Git). Đường dẫn nguồn, commit và SHA-256
được ghi ở [docs/STATUS.md](docs/STATUS.md). Notebook Colab sau này chỉ gọi
các module trong `src/`; logic chuẩn hóa trong `vtguard.data.normalize` là
chung cho tệp offline và bản ghi online.

Đọc [kiến trúc](docs/architecture.md), [hợp đồng dữ liệu](docs/data_contract.md)
và [trạng thái](docs/STATUS.md) trước khi mở rộng.

## Kiểm toán nguồn và baseline

```powershell
python scripts/fetch_public.py
python scripts/audit_public.py
python scripts/smoke_baseline.py
```

Nguồn public được ghim checksum trong `configs/public_sources.json`. Kết luận
nhãn/phiên ở [kiểm toán dữ liệu](docs/public_data_audit.md). Smoke baseline
huấn luyện và nạp bundle chỉ bằng sự kiện **tổng hợp**; kết quả của nó không
là đánh giá phát hiện thật. [Protocol](docs/experiment_protocol.md) mô tả
manifest cần thiết trước khi huấn luyện thật. Notebook Colab chỉ điều phối
module và cần GitHub URL/commit cùng reviewed manifest trên Drive.
