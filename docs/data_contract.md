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
không đưa vào `model_input`. `model_input` hiện chỉ là phép chiếu trường sự kiện,
chưa phải vector số hay mô hình đã huấn luyện. Rule/ATT&CK metadata của Wazuh
không sinh nhãn. Fragment PowerShell được giữ riêng; chưa ghép script block.
Nội dung command/script có thể tự chứa tên host, người dùng hoặc dấu vết công cụ
automation; cần kiểm toán trước khi dùng làm đặc trưng học máy.

Adapter hỗ trợ Wazuh archive JSONL, Windows Event JSONL, XML một sự kiện mỗi dòng
(đã thấy ở tệp Splunk T1654), hoặc một tài liệu Windows Event XML hoàn chỉnh.
`EventData.UtcTime` của Sysmon được coi là UTC dù không có hậu tố múi giờ;
các timestamp khác thiếu múi giờ vẫn là null. Chưa xác nhận định dạng của tất
cả năm tệp công khai; cần kiểm tra mẫu tải có checksum/version. XML đa dòng
nối nhiều Event, CSV Windows-APT và cấu trúc Wazuh Indexer `hits`
chưa được hỗ trợ. Cần thêm run/session manifest độc lập trước tạo chuỗi và chia
train/validation/test. Không suy ra TTP từ đường dẫn tệp.

Fixture trong `tests/fixtures` là dữ liệu tổng hợp chỉ để thử parser. Nó không
là bằng chứng lab hay dữ liệu huấn luyện. Cần ghim phiên bản ATT&CK và quyết
định ánh xạ khi lập bộ dữ liệu có nhãn.
