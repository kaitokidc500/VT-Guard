# Kiến trúc và các phần triển khai

1. **Dữ liệu và smoke CPU (đã dựng local):** package, cấu hình, schema, adapter tệp,
   normalizer dùng chung, báo cáo chất lượng, kiểm thử parser và CLI xuất ba tệp.
2. **Kiểm toán dữ liệu thật:** tải có chọn lọc, ghim commit/giấy phép/checksum,
   kiểm định ID, run, nhãn, mức thiếu, trùng và thiên lệch nguồn. Chỉ sau đó
   xác lập manifest và split độc lập.
3. **Baseline và artifact (đã smoke tổng hợp):** event/sequence builder nhân quả,
   logistic CPU, GRU/GRU attention sáu đầu, luật Decision Tree, fusion và bundle
   có checksum/reference inference. Chưa xác nhận hiệu quả trên dữ liệu thật.
4. **Colab (chưa chạy trên Colab):** notebook chỉ gọi module, lưu checkpoint bền
   trong Drive, so sánh logistic, GRU, GRU attention, rule-only và hybrid.
5. **SIEM và đánh giá:** collector Indexer có cursor, chạy song song Wazuh,
   dashboard và đánh giá v1/v2 trên lab test giữ cố định.

Hướng dữ liệu dự kiến: Wazuh Indexer → collector → normalizer dùng chung →
sequence builder → luật + mô hình → fusion → kết quả/API/dashboard. Phần local
đến bundle hybrid đã chạy với fixture tổng hợp. Chưa có collector, kết nối SIEM,
API/dashboard, đánh giá trên dữ liệu thật hay detector vận hành.
