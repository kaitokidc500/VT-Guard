# Kiến trúc và các phần triển khai

1. **Dữ liệu và smoke CPU (hiện tại):** package, cấu hình, schema, adapter tệp,
   normalizer dùng chung, báo cáo chất lượng, kiểm thử parser và CLI xuất ba tệp.
2. **Kiểm toán dữ liệu thật:** tải có chọn lọc, ghim commit/giấy phép/checksum,
   kiểm định ID, run, nhãn, mức thiếu, trùng và thiên lệch nguồn. Chỉ sau đó
   xác lập manifest và split độc lập.
3. **Baseline và artifact:** feature/sequence builder nhân quả dùng cả offline
   và online; baseline CPU, luật Decision Tree và bundle phiên bản có loader
   kiểm tra schema/checksum. Chạy suy luận tham chiếu trên mẫu cố định.
4. **Colab:** notebook chỉ gọi module, lưu checkpoint bền trong Drive, so sánh
   baseline với GRU attention hai đầu, học fusion bằng dự đoán phù hợp split.
5. **SIEM và đánh giá:** collector Indexer có cursor, chạy song song Wazuh,
   dashboard và đánh giá v1/v2 trên lab test giữ cố định.

Hướng dữ liệu dự kiến: Wazuh Indexer → collector → normalizer dùng chung →
sequence builder → luật + mô hình → fusion → kết quả/API/dashboard. Chỉ phần
normalizer từ tệp và báo cáo ở bước 1 đã được dựng. Không có kết nối SIEM,
đánh giá mô hình hay detector vận hành trong mốc này.
