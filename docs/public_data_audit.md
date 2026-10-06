# Kiểm toán dữ liệu công khai — Splunk attack_data

Phiên nguồn: commit `4389fa7a4e74a7c083c0fbe448fa2c7c32378981`.
Giấy phép repository: [Apache-2.0](https://raw.githubusercontent.com/splunk/attack_data/4389fa7a4e74a7c083c0fbe448fa2c7c32378981/LICENSE).
Bảy tệp đã tải có kích thước và SHA-256 khớp manifest
`configs/public_sources.json`. ATT&CK dùng cho quyết định ánh xạ từ thời điểm
này: [Enterprise v19.2](https://github.com/mitre-attack/attack-stix-data/releases/tag/v19.2).
Các metadata YAML gốc mô tả kịch bản, không cung cấp nhãn sự kiện hoặc run ID.

| Nguồn | Sự kiện | Event ID chính | Host | Run xác minh | Nhận xét nhãn |
|---|---:|---|---:|---:|---|
| T1016 discovery_commands Sysmon | 7.691 | 10: 7.267; 1: 286 | 2 | 0 | Chỉ thấy 1 lệnh `ipconfig /all` rõ ràng trong mẫu dò; 7.680 sự kiện ngày 2020-11-10 và 11 sự kiện ngày 2025-01-20 trên host khác. Một tệp không phải một phiên liên tục. |
| T1049 AD_discovery Sysmon | 2.989 | 23: 1.296; 10: 1.173; 1: 110 | 1 | 0 | 3 sự kiện command-line khớp `netstat`/`Get-NetTCPConnection`; metadata ghi mô phỏng PoschC2/PowerShell implant, dễ rò rỉ danh tính công cụ. |
| T1018 AD_discovery Sysmon | 3.115 | 23: 1.287; 10: 1.226; 1: 121 | 1 | 0 | 5 lệnh dạng `nltest`/`dsquery computer`/`Get-ADComputer` là ứng viên cần rà; không gán nhãn toàn tệp. |
| T1087.002 ADSI, 3 XML PowerShell | 4 bản ghi, 3 quan sát duy nhất | 4104: 4 | 1 | 0 | Nội dung tìm organizational unit/GPO, không phải domain account. Một quan sát lặp giữa tệp gốc và `xml1`; có dấu ký tự thay thế trong hai bản ghi. **Loại khỏi dương T1087.002.** |
| T1654 eventlog_enumeration Sysmon | 9 | 1: 9 | 1 | 0 | Có `wevtutil`, `Get-WinEvent`, WMIC log query và công cụ log khác. Mục đích từng sự kiện vẫn cần bằng chứng kịch bản; metadata `eventlog_enumeration_old.yml` chứa đường dẫn T1621 không khớp thư mục. |

Tổng 13.808 bản ghi đọc được, 0 lỗi parser; `ingest_time_utc` thiếu ở toàn bộ
XML. Trong T1049/T1018, nhiều sự kiện là hoạt động nền của Splunk forwarder.
Cả hai có cùng host/lối mô phỏng AD discovery nhưng khác ngày; không khẳng
định là hai run độc lập dùng để chia train/test. Chia ngẫu nhiên theo sự kiện
sẽ rò rỉ nguồn và thời gian. Chưa có tập benign-admin độc lập.

## Quyết định nhãn và phiên

- Giữ `activity=unknown` cho tất cả bản ghi đã tải. Kỹ thuật trong đường dẫn
  và `mitre_technique` của YAML là **ngữ cảnh kịch bản**, không phải nhãn từng
  event. Dò lệnh chỉ tạo danh sách cần người rà soát.
- Không ghép các tệp T1016, T1049, T1018, T1087.002, T1654 thành chuỗi tấn
  công. Khoảng cách thời gian, host và metadata không chứng minh quan hệ phiên.
- T1016 có hai cụm nguồn cách nhau hơn bốn năm; cần tìm nguồn gốc 11 dòng 2025
  trước khi dùng. T1087.002 không đáp ứng đúng sub-technique nên phải thay
  bằng nguồn khác hoặc run lab có truy vấn tài khoản miền thật.
- Baseline huấn luyện thật cần annotation theo từng event, run ID do quá trình
  thu thập xác nhận, scenario family, benign-admin độc lập và chia theo family.
  Không dùng kết quả của Wazuh/Splunk làm ground truth tự động.

`scripts/fetch_public.py` xác thực tệp bằng kích thước và SHA-256;
`scripts/audit_public.py` tái tạo `artifacts/public_audit.json` (không commit
raw dữ liệu); `scripts/review_public.py` in ví dụ để rà bằng chứng, không gán
nhãn. Dữ liệu Windows-APT 2025 chỉ được xem ở mức bài báo/trang tác giả;
API tệp công khai trả 401 trong phiên này, nên chưa kiểm toán CSV hay dùng làm
tập huấn luyện. Bài báo cho biết `scenario_manifest.csv` có metadata kịch bản
và dữ liệu có cả benign/malicious, nhưng ánh xạ đúng năm TTP và nguồn nhãn
vẫn phải xác minh trên tệp thực tế.
