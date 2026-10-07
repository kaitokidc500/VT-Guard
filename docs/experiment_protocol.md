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
UTC bắt đầu/kết thúc run là bắt buộc; event được chọn phải nằm trong khoảng
này (dung sai mặc định một giây, tối đa mười giây cho sai lệch đồng hồ đã ghi).
Mỗi annotation cần nhãn `attack` hoặc `benign-admin`, danh sách năm TTP đã
rà, TTP hiện diện, độ tin cậy, người rà và chứng cứ. Sự kiện không annotation
không dùng huấn luyện. Không tự gán toàn bộ run tấn công là event tấn công.
Một ví dụ manifest tổng hợp được tạo bởi `scripts/smoke_baseline.py` trong
`artifacts/baseline_smoke_input/reviewed_manifest.json`.
`scripts/review_runs.py prepare/compile` tạo bảng rà nhãn trống từ raw export
và chuyển các dòng đã rà thành manifest sau khi xác thực lại checksum/UID.

Kiểm tra trước train: checksum nguồn, đầy đủ annotation, thời điểm UTC, family
không qua split, cùng raw content không qua split, không trùng quan sát, cả
hai lớp ở train/validation cho mọi đầu. Không cho dữ liệu tổng hợp vào lệnh
train thật nếu không bật cờ smoke. Từ vựng chỉ fit trên train. Chọn ngưỡng F1
trên validation; test chỉ đọc một lần. Average precision là diện tích PR bậc
thang theo các mức score khác nhau. Chỉ số hiện ở mức event, chưa có session,
alerts/giờ hoặc độ trễ end-to-end.

Bundle `cpu_event_baseline` chứa trọng số, từ vựng, ngưỡng, cấu hình, phiên
schema/ATT&CK, provenance/checksum nguồn, metrics và inference tham chiếu.
Loader kiểm SHA-256 và suy luận tham chiếu. Artifact từ fixture luôn ghi
`detector_status=synthetic_smoke`.

## Mô hình chuỗi, luật và fusion

Builder nhân quả nhóm theo run (nếu có), host và logon/user, tối đa 64 event
trong 300 giây và 1024 nhóm hoạt động trong bộ nhớ. Luồng live không có run ID
được giới hạn bằng host/identity và horizon; collector sau này phải xử lý đến
trễ. Đây là giả thuyết cấu hình, cần điều chỉnh trên dữ liệu thật. GRU cơ bản
và GRU attention dùng cùng token vocabulary train-only cùng delta thời gian.
Sáu đầu sigmoid dự đoán attack và năm TTP đa nhãn. Mô hình attention dùng
trọng số trên các trạng thái GRU hợp lệ; padding bị mask. Baseline chuỗi là GRU
không attention. Train dùng checkpoint có thể resume trên Drive và dừng sớm
theo validation; test chỉ tính sau khi chọn checkpoint/ngưỡng.

Decision Tree nhị phân học trên token sự kiện từ train. Nhánh dương thành luật
`required/forbidden`; chỉ giữ khi đạt support/precision trên validation. Luật
chạy trong VT-Guard. Fusion trộn điểm AI với vector luật; trọng số và ngưỡng
được chọn trên validation theo từng đầu. Phiên này dùng validation để chọn
fusion cố định, chưa dùng mô hình fusion học bằng dự đoán ngoài fold. Báo cáo
so sánh rule-only, logistic, GRU, GRU attention và hai tổ hợp hybrid, không
giả định hybrid tốt hơn.

Bundle `gru_rule_hybrid` tự chứa bundle GRU, luật, tham số fusion, checksum và
reference inference. Tất cả bundle hiện `deployable=false`: chưa có kết quả
thật, kiểm tra Colab/SIEM hoặc đánh giá theo phiên/độ trễ.

## Lệnh

```powershell
python scripts/smoke_baseline.py
python scripts/smoke_training.py
python scripts/train_baseline.py --manifest PATH_TO_REVIEWED_MANIFEST --output PATH_TO_BUNDLE
```

Notebook `notebooks/train_colab.ipynb` clone commit ghim, smoke CPU, stage dữ
liệu có checksum, kiểm readiness, gọi toàn bộ module train/fit/compare và lưu
checkpoint/bundle trên Drive. Xem [hướng dẫn Colab](colab_training.md).
GitHub URL, manifest thật và kiểm chứng Colab hiện chưa có.
