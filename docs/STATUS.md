# Trạng thái VT-Guard — cập nhật 2026-10-07 (Asia/Bangkok)

## Mốc 1: package, config và schema

- Đã xây `pyproject.toml`, CLI, hai cấu hình JSON, schema v1.0 với provenance,
  nhãn riêng và mask thiếu trường. `model_input` loại nguồn, host/user, nhãn và
  metadata Wazuh khỏi phép chiếu trường sự kiện.
- Đã khởi tạo Git repository local; chưa tạo remote, chưa push hay xuất bản.
- Đã kiểm thử schema qua kiểm thử pipeline và smoke CLI trên fixture tổng hợp.
- Còn thiếu manifest run và nhãn độc lập; chưa có vector hóa, mô hình, luật,
  fusion hay bundle. Bước tiếp: thiết kế manifest/split sau kiểm toán nguồn.

## Mốc 2: adapter và normalizer dùng chung

- Đã xây adapter Wazuh archive JSONL, Windows Event JSONL và XML một Event mỗi
  dòng hoặc một tài liệu Event. Cùng hàm `normalize` dùng cho mọi nguồn.
- Đã kiểm thử 5 trường hợp bằng fixture tổng hợp: thời gian Sysmon/Wazuh,
  fragment PowerShell, XML, dòng JSON lỗi, đầu ra CLI và ranh giới leakage.
- Sau khi xem tệp Splunk T1654 thật, bổ sung XML mỗi dòng và xử lý
  `EventData.UtcTime` UTC không có hậu tố múi giờ. Đây là điều chỉnh theo bằng
  chứng định dạng; không đổi mục tiêu kiến trúc.
- Còn thiếu kiểm chứng adapter trên bốn nguồn public còn lại và xuất thật từ
  VM Wazuh/Indexer. Chưa ghép fragment, liên kết 4688 với Sysmon 1 hay xử lý
  XML chứa nhiều Event đa dòng.

## Mốc 3: báo cáo chất lượng và smoke CPU

- CLI xuất `normalized.jsonl`, `model_inputs.jsonl`, `quality.json` với
  checksum đầu vào, số lỗi, trường thiếu, loại sự kiện, nhãn, nguồn, host/run,
  trùng quan sát cùng kênh và dấu thời gian bất thường. Smoke được đánh dấu
  `detector_status=not_trained`.
- Lệnh đã chạy: `python -m unittest discover -s tests -v` bằng Python 3.11.15
  tải vào `.uv-python/` trong workspace: **5/5 đạt**. Lệnh
  `python -m vtguard.cli configs/smoke.json`: **2 sự kiện tổng hợp, 0 lỗi**.
- Tệp công khai được kiểm tra riêng: [Splunk attack_data T1654](https://github.com/splunk/attack_data/blob/4389fa7a4e74a7c083c0fbe448fa2c7c32378981/datasets/attack_techniques/T1654/eventlog_enumeration/eventlog_enumeration.log),
  commit `4389fa7a4e74a7c083c0fbe448fa2c7c32378981`, LFS SHA-256
  `b7d86de9df27311dfc987ce78cb0fc1ea1a70a479d758fad350c438065f72131`,
  18.657 byte. Lệnh `python -m vtguard.cli configs/audit_t1654.json`:
  **9/9 sự kiện XML Sysmon ID 1, 0 lỗi parse, 1 host, 0 run, 9 nhãn unknown**.
  Tất cả 9 thiếu ingest time và script block; dữ liệu này chưa đủ để huấn luyện
  chuỗi hoặc gán toàn bộ là malicious. Đây mới là kiểm toán một tệp, chưa phải
  kiểm toán đủ năm TTP. Giấy phép áp dụng và ranh giới kịch bản cần đối chiếu.
- Còn thiếu giới hạn bộ nhớ khi chạy file rất lớn (hàm `assess` hiện giữ toàn bộ
  event để xuất), đối chiếu trùng xuyên nguồn, phân phối benign, session và
  bằng chứng nhãn. Bước tiếp: kiểm toán có chọn lọc các tệp còn lại, manifest
  nguồn/nhãn, rồi chia split theo run trước tạo cửa sổ.

## Chưa xác minh trên nền tảng đích

Không chạy trên Windows Agent, Colab hay VT-SIEM01 trong mốc này. Chưa xem
Wazuh Compose, chứng chỉ, cổng hay API Indexer. Không chạy training lớn, không
triển khai SIEM, không có kết quả phát hiện hoặc đánh giá mô hình.

## Mốc 4: kiểm toán đủ các nguồn Splunk đã chọn

- Đã tải 7 tệp theo một commit cố định, xác minh kích thước/SHA-256 và đọc
  13.808 bản ghi, 0 lỗi parser. Đã đối chiếu 5 YAML metadata và giấy phép
  Apache-2.0. Chi tiết số liệu, quyết định nhãn và ranh giới phiên ở
  [public_data_audit.md](public_data_audit.md).
- Phát hiện T1016 trộn hai cụm thời gian/host; T1087.002 thực tế đọc OU/GPO,
  không phải domain account, lại có một sự kiện lặp; không tệp nào có run ID
  hoặc nhãn từng event. Đã ghim Enterprise ATT&CK v19.2 cho ánh xạ mới.
- Đã kiểm tra Windows-APT 2025 ở mức tài liệu. API liệt kê tệp trả 401; chưa
  có CSV để kiểm toán trực tiếp. Không dùng nguồn này làm nhãn huấn luyện.
- Bước tiếp: hoàn thiện baseline CPU với annotation/run manifest bắt buộc,
  kiểm thử bằng fixture tổng hợp; chỉ train dữ liệu thật sau khi có nhãn và
  phiên được xác nhận.

## Mốc 5: baseline CPU có cổng dữ liệu được duyệt

- Đã xây feature extractor dùng chung offline/online, logistic regression
  một-vs-còn-lại cho attack + đúng năm TTP, loader reviewed manifest, split
  theo scenario family, từ vựng fit train, ngưỡng chọn trên validation, test
  metrics, bundle JSON có SHA-256 và kiểm tra inference tham chiếu.
- Đã chạy `python scripts/smoke_baseline.py`: 21 sự kiện **tổng hợp** trên 21
  run/family (7 mỗi split), tạo và nạp lại bundle `synthetic_smoke`. Đã chạy
  `python -m unittest discover -s tests -v`: **8/8 đạt**. Notebook Colab JSON
  hợp lệ; chưa chạy notebook trên Colab. Xem [protocol](experiment_protocol.md).
- Bundle baseline `deployable=false`: chưa có luật sinh, fusion, GRU, đánh giá
  phiên, hoặc xác minh lab. Không báo điểm synthetic là hiệu quả phát hiện.
- Người dùng xác nhận chưa có run lab được gán nhãn. Vì vậy **chưa huấn luyện
  baseline trên dữ liệu thật**. Mẫu manifest và hướng dẫn thu/rà nhãn ở
  [lab_collection.md](lab_collection.md). Windows-APT v3 chưa kiểm toán được
  tệp CSV: API công khai trả 401 và endpoint giao diện trả 502 trong phiên này.
- Bước tiếp: nhận raw lab và annotation độc lập; kiểm tra manifest, chia split
  cố định rồi train baseline thật. Sau đó bổ sung luật, GRU attention và fusion.
- Đã tạo commit Git local cho mã/tài liệu; chưa tạo remote hoặc push. Mã Colab
  hiện truyền commit đã ghim vào metadata của bundle khi chạy thực tế.
- Loader hiện bắt buộc UTC bắt đầu/kết thúc run và kiểm tra event được chọn nằm
  trong khoảng này; kiểm thử và smoke tổng hợp đã chạy lại, vẫn 8/8 đạt.

## Mốc 6: chuẩn bị rà nhãn lab

- Đã xây `review_runs.py prepare/compile`: tạo CSV nhãn trống từ raw và run
  spec, rồi chỉ biên dịch những dòng đã được rà. Kiểm lại raw SHA-256, UID
  dòng và toàn bộ cổng dữ liệu của baseline trước khi xuất manifest.
- Đã kiểm thử vòng chuẩn bị → điền nhãn fixture → compile → loader, UID bị sửa
  và dòng CSV bị xóa: `python -m unittest discover -s tests -v` **9/9 đạt**.
- Đã chạy `python scripts/smoke_baseline.py` và CLI `review_runs.py prepare`
  trên fixture tổng hợp. Smoke tạo/nạp bundle `synthetic_smoke`; đây không phải
  dữ liệu hay đánh giá từ lab thật.
- Chưa chạy công cụ trên export lab thật vì chưa có run được gán nhãn. Hướng
  dẫn thao tác và mẫu run spec ở [lab_collection.md](lab_collection.md).

## Mốc 7: cửa sổ chuỗi nhân quả (local)

- Đã xây `features.sequence` với giới hạn số sự kiện/thời gian, tách theo run,
  host và logon/user, cùng một builder cho replay offline và luồng online.
  Sự kiện đến trễ sai thứ tự bị từ chối để collector xử lý riêng. Builder live
  cho phép thiếu run ID và giới hạn tối đa 1024 nhóm trong bộ nhớ.
- Đã kiểm thử thứ tự, ranh giới run/identity, horizon và offline/online parity:
  `python -m unittest discover -s tests -v` **11/11 đạt**.
- Chưa dùng chuỗi để train: corpus hiện chỉ có fixture một event/run và chưa có
  run thật được gán nhãn. Bước tiếp: mã hóa cửa sổ, GRU cơ bản và attention;
  kiểm tra trên run nhiều event trước khi đánh giá.

## Mốc 8: luật Decision Tree có thể thực thi local

- Đã xây CART nhị phân nhỏ trên token hành vi cho sáu đầu attack/TTP, lấy các
  nhánh dương thành điều kiện `required/forbidden`. Chỉ dùng train để học và
  validation để lọc support/precision; `match_vector` chạy cùng token extractor.
- Đã kiểm thử luật khớp/không khớp, serialize và cổng validation:
  `python -m unittest discover -s tests -v` **12/12 đạt**.
- Chưa có luật nào được xác nhận trên dữ liệu thật; chưa có fusion hay triển khai.
  Bước tiếp: tích hợp rule-only/AI-only/hybrid và đóng gói versioned bundle.

## Mốc 9: baseline hybrid CPU thử nghiệm

- Đã tích hợp logistic AI và vector luật sinh vào fusion điểm số sáu đầu.
  Trọng số/ngưỡng chọn trên validation; test chỉ dùng để báo cáo riêng
  rule-only, AI-only và hybrid. Bundle có luật, cấu hình fusion, checksum và
  suy luận tham chiếu; `deployable=false`.
- Đã kiểm thử serialize/nạp bundle, suy luận sáu đầu và đầu vào fusion sai:
  `python -m unittest discover -s tests -v` **14/14 đạt**.
- Chỉ chạy trên fixture tổng hợp; chưa chứng minh luật hoặc hybrid hiệu quả thật.
  Còn thiếu mô hình chuỗi, tập public có nhãn/phiên, Colab thực tế và SIEM.
  Bước tiếp: triển khai GRU hai đầu trên cửa sổ nhân quả và smoke CPU nhỏ.

## Mốc 10: GRU và GRU attention đa nhãn

- Đã xây encoder chung token + delta thời gian, GRU cơ bản và GRU attention
  sáu đầu (attack + năm TTP), mask padding, huấn luyện mini-batch, dừng sớm
  trên validation và checkpoint/resume tách khỏi bundle. Bundle GRU có trọng
  số SHA-256, schema, vocab, cấu hình, provenance và reference inference CPU.
- Đã chạy thật trên local Python 3.11.15, PyTorch 2.7.1+cpu, NumPy 2.2.6.
  Kiểm thử hai mô hình, mask và resume đạt. Fixture mở rộng có hai event lặp/run
  để chạy cửa sổ nhiều event; smoke **không** xác nhận khả năng học ngữ cảnh
  hay hiệu quả phát hiện trên telemetry thật.
- Bước tiếp: chạy trên manifest có run nhiều event được rà, kiểm tra trực tiếp
  Colab GPU/Drive và so sánh với baseline.

## Mốc 11: hybrid GRU và luồng Colab thử nghiệm

- Đã ghép GRU attention + luật sinh + fusion thành bundle tự chứa; chọn luật,
  trọng số và ngưỡng chỉ trên train/validation, báo cáo test rule-only/AI-only/
  hybrid. Đã thêm stage raw được kiểm checksum, báo cáo readiness theo split/
  nguồn/lớp/cửa sổ, notebook điều phối các module và báo cáo so sánh sáu phương án.
- Đã chạy `python scripts/smoke_training.py` trên fixture 42 event/21 run và
  `python -m unittest discover -s tests -v` trên virtualenv local: **19/19 đạt**.
  Notebook JSON hợp lệ; **chưa chạy notebook trên Colab**. Hướng dẫn ở
  [colab_training.md](colab_training.md).
- Sau khi giới hạn cache live và kiểm ranh giới run/host/identity ở encoder,
  đã chạy lại toàn bộ suite: **20/20 đạt**; smoke tổng hợp vẫn nạp đủ bundle.
- Chưa có GitHub remote, reviewed corpus public/lab đủ nhãn/run, Colab test,
  đánh giá thật hoặc triển khai SIEM. Tất cả bundle hiện `deployable=false`.
  Bước tiếp: tìm/duyệt corpus public phù hợp, thu run lab độc lập, kiểm Colab
  với manifest thật rồi mới diễn giải metrics; sau đó xây collector/API/dashboard.
- Đã thử lại endpoint danh sách tệp Mendeley v3 được tài liệu hóa
  (`/datasets/publics/b8fmtzvpy8/files?version=3`): HTTP 401. Trang so sánh
  công khai liệt kê file nhưng chưa lấy được CSV để kiểm nhãn/phiên.
