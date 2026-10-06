# Chuẩn bị run lab cho baseline thật

Chưa có export và nhãn lab trong workspace. Khi thu thập, giữ raw bất biến và
lưu một tệp JSONL Wazuh cho mỗi run cùng ghi chú ngoài log: run ID, host, vai
trò, UTC bắt đầu/kết thúc, người thao tác, mục tiêu benign-admin hoặc kỹ thuật,
script/lệnh thực hiện và lỗi/gián đoạn. Ghi SHA-256 ngay sau khi xuất. Không
đổi chính sách logging hoặc xóa log để giảm nhiễu controller.

Thu các hoạt động quản trị benign có thể dùng cùng lệnh với TTP để đo false
positive; thu riêng các run cho năm kỹ thuật. T1087.002 phải truy vấn **tài
khoản miền**, không phải OU/GPO, group hoặc local account. T1654 phải đọc/liệt
kê log, không xóa log. Đánh dấu telemetry của automation controller, giữ sự
kiện child process và raw. Run lỗi/partial được giữ để debug, không giả làm
phiên hoàn chỉnh.

Rà từng sự kiện **được chọn** bằng raw_ref/dòng và bằng chứng của kịch bản;
những sự kiện chưa rà giữ unknown và không đưa vào train. Một người thực hiện
có thể ghi lại bằng chứng và sau đó tự rà trên bản raw; không lấy Wazuh rule ID
hoặc mô hình làm ground truth. Dùng
[`configs/reviewed_manifest.template.json`](../configs/reviewed_manifest.template.json)
cho cấu trúc. Một tệp có thể chứa nhiều sự kiện nhưng mỗi dòng annotation phải
có hoạt động attack/benign-admin, năm kỹ thuật đã rà, kỹ thuật hiện diện, độ
tin cậy, người rà và chứng cứ. `line` là số dòng của JSONL gốc.

Chỉ định split ở cấp `scenario_family` **trước** khi tạo cửa sổ hoặc fit từ
vựng. Các lần lặp/biến thể cùng kịch bản và raw trùng nguồn phải cùng split.
Nên có hoạt động và TTP cần đánh giá ở train, validation và test bằng các run
độc lập; protocol không áp một tỷ lệ hoặc số mẫu tối thiểu chưa được xác lập.
Giữ test cố định, không chỉnh nhãn/ngưỡng sau khi xem test mà không khai báo
protocol mới. Baseline hiện là sự kiện đơn; session model và latency SIEM sẽ
được đánh giá sau.
