# Hợp đồng dữ liệu v1.0

Ba lớp: tệp đầu vào nguyên gốc (không sửa), `normalized.jsonl` và
`model_inputs.jsonl`. `event_uid` là SHA-256 từ nguồn, phiên bản, đường dẫn và số
dòng; đây là định danh lần đọc, không phải bằng chứng hai bản ghi giống nhau.
`raw_ref` trỏ về dòng hoặc tài liệu XML gốc. Báo cáo chứa SHA-256 của tệp.

`event_time_utc` ưu tiên Sysmon `EventData.UtcTime`, kế đến Windows
`System.TimeCreated`, cuối cùng là `event_time` rõ ràng từ nguồn. Dấu thời gian
không có múi giờ được giữ là thiếu. `ingest_time_utc` lấy riêng từ timestamp
cấp bản ghi. Cả `system_time_utc` và `sysmon_utc_time` được bảo toàn.

Các trường không thấy được đặt `null`, và `missing` có boolean tương ứng.
Thông tin nguồn, phiên, run, scenario, nhãn và chứng cứ ở `provenance`/`labels`,
không đưa vào `model_input`. `model_input` là phép chiếu trường sự kiện; từ
vựng đặc trưng hành vi chỉ được fit trên train. Rule/ATT&CK metadata của Wazuh
không sinh nhãn. Fragment PowerShell được giữ riêng; chưa ghép script block.
Nội dung command/script có thể tự chứa tên host, người dùng hoặc dấu vết công cụ
automation; cần kiểm toán trước khi dùng làm đặc trưng học máy.

Adapter hỗ trợ Wazuh archive JSONL, Windows Event JSONL, XML một sự kiện mỗi dòng
(đã thấy ở tệp Splunk T1654), hoặc một tài liệu Windows Event XML hoàn chỉnh.
`EventData.UtcTime` của Sysmon được coi là UTC dù không có hậu tố múi giờ;
các timestamp khác thiếu múi giờ vẫn là null. Bảy tệp Splunk được chọn đã tải
và kiểm tra checksum; xem [kiểm toán](public_data_audit.md). XML đa dòng
nối nhiều Event, CSV Windows-APT và cấu trúc Wazuh Indexer `hits`
chưa được hỗ trợ. Loader reviewed manifest hiện kiểm run/split trước khi tạo
cửa sổ chuỗi, nhưng chưa có corpus thật đủ nhãn và ranh giới. Không suy ra TTP
từ đường dẫn tệp. Cửa sổ hiện chỉ chứa event đã được rà nhãn; event chưa rà
không được dùng làm ngữ cảnh.

Fixture trong `tests/fixtures` là dữ liệu tổng hợp chỉ để thử parser. Fixture
huấn luyện tổng hợp ở `artifacts/` chỉ smoke pipeline, không là bằng chứng lab
hay dữ liệu huấn luyện thật. Ánh xạ mới đã ghim Enterprise ATT&CK v19.2.
