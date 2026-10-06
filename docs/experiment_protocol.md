# Protocol baseline v1

Baseline là logistic regression một-vs-còn-lại trên sự kiện đơn, chạy CPU bằng
thư viện chuẩn Python. Sáu đầu dự đoán gồm attack và năm TTP. Đặc trưng dùng
chung qua `vtguard.features.event`: channel/event ID, basename từ danh sách
công cụ hệ thống cho phép và từ vựng cú pháp hành vi giới hạn. Không dùng host,
user, tên nguồn, nhãn Wazuh, run/scenario ID hay tên công cụ mô phỏng. Cần
rà thêm nội dung lệnh trước khi mở rộng từ vựng.

## Reviewed manifest

Manifest JSON có `schema_version=1.0`, `attack_version=19.2` và danh sách
`runs`. Mỗi run cần ID, scenario family, split (`train`, `validation`, `test`),
đường dẫn và SHA-256 raw, định dạng, nguồn/phiên, cùng annotation từng dòng.
Mỗi annotation cần nhãn `attack` hoặc `benign-admin`, danh sách năm TTP đã
rà, TTP hiện diện, độ tin cậy, người rà và chứng cứ. Sự kiện không annotation
không dùng huấn luyện. Không tự gán toàn bộ run tấn công là event tấn công.
Một ví dụ manifest tổng hợp được tạo bởi `scripts/smoke_baseline.py` trong
`artifacts/baseline_smoke_input/reviewed_manifest.json`.

Kiểm tra trước train: checksum nguồn, đầy đủ annotation, thời điểm UTC, family
không qua split, cùng raw content không qua split, không trùng quan sát, cả
hai lớp ở train/validation cho mọi đầu. Không cho dữ liệu tổng hợp vào lệnh
train thật nếu không bật cờ smoke. Từ vựng chỉ fit trên train. Chọn ngưỡng F1
trên validation; test chỉ đọc một lần. Average precision là diện tích PR bậc
thang theo các mức score khác nhau. Chỉ số hiện ở mức event, chưa có session,
alerts/giờ hoặc độ trễ end-to-end.

Bundle `cpu_event_baseline` chứa trọng số, từ vựng, ngưỡng, cấu hình, phiên
schema/ATT&CK, provenance/checksum nguồn, metrics và inference tham chiếu.
Loader kiểm SHA-256 và suy luận tham chiếu. Bundle này `deployable=false`:
chưa có luật, fusion, sequence builder hay xác minh lab/SIEM. Artifact từ
fixture luôn ghi `detector_status=synthetic_smoke`.

## Lệnh

```powershell
python scripts/smoke_baseline.py
python scripts/train_baseline.py --manifest PATH_TO_REVIEWED_MANIFEST --output PATH_TO_BUNDLE
```

Notebook `notebooks/train_colab.ipynb` chỉ clone commit đã ghim, cài package,
gọi smoke rồi gọi script train với manifest trên Drive. GitHub URL, commit và
manifest thật chưa được cung cấp; notebook chưa được chạy trên Colab.
