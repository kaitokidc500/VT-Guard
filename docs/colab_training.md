# Chạy pipeline huấn luyện trên Colab

## Điều kiện dữ liệu

Notebook [`train_colab.ipynb`](../notebooks/train_colab.ipynb) nhận một reviewed
manifest trên Google Drive, với raw files ở đường dẫn tương đối với manifest
hoặc đường dẫn hiện hữu trong Colab. Mỗi run phải có UTC bắt đầu/kết thúc độc
lập, `scenario_family`, split cố định, checksum raw và annotation từng event có
chứng cứ. Tập train và validation phải có cả hai lớp cho attack và năm TTP.
Train chuỗi thật cần cửa sổ ít nhất hai sự kiện đã rà trong cùng run/host/ngữ
cảnh logon. Các event chưa rà bị loại khỏi ngữ cảnh chuỗi và được đếm trong
`readiness.json`.

**Các tệp Splunk đã kiểm toán hiện chưa đáp ứng điều kiện này.** Không gán toàn
bộ tệp theo tên thư mục. Nguồn T1087.002 đã tải mô tả OU/GPO, không phải truy
vấn tài khoản miền. Cần một corpus công khai phù hợp cho v1; lab runs được thu
và chia riêng cho đánh giá/adaptation v2 theo protocol.

## Chuyển mã và chạy

1. Repository đích đã được chỉ định:
   `https://github.com/kaitokidc500/VT-Guard.git`. Đưa source Git lên đó với
   quyền hiển thị phù hợp; raw, credentials, checkpoints và weights không đưa
   vào Git. Sao chép full 40 ký tự commit SHA sau khi push. Remote local đã
   cấu hình, nhưng chưa push.
2. Đưa reviewed manifest cùng raw có quyền sử dụng vào Drive, giữ nguyên cấu
   trúc đường dẫn tương đối. Rà báo cáo nguồn/nhãn/phiên trước khi tính điểm.
3. Mở notebook, điền `REPO_URL`, `CODE_COMMIT`, `MANIFEST`, `OUTPUT_ROOT` rồi
   chạy từ đầu. Notebook clone commit ghim, cài package (không cài lại CUDA
   PyTorch), kiểm tra runtime và smoke tổng hợp, mount Drive, xác minh/stage
   raw vào `/content`, rồi chạy các module Python.
4. Kiểm tra `readiness.json` trước khi diễn giải kết quả. Notebook dừng nếu
   train không có cửa sổ nhiều sự kiện. Các script huấn luyện còn kiểm tra
   checksum, split và lớp sau khi stage.

Các lệnh chính tương đương trên local (thay đường dẫn theo môi trường):

```powershell
python scripts/stage_reviewed.py --manifest PATH_TO_MANIFEST --output-dir PATH_TO_SCRATCH
python scripts/inspect_reviewed.py --manifest PATH_TO_SCRATCH/reviewed_manifest.json --output PATH_TO_REPORT
python scripts/train_baseline.py --manifest PATH_TO_SCRATCH/reviewed_manifest.json --output PATH_TO_OUTPUT/logistic
python scripts/train_hybrid.py --manifest PATH_TO_SCRATCH/reviewed_manifest.json --output PATH_TO_OUTPUT/hybrid_logistic
python scripts/train_sequence.py --manifest PATH_TO_SCRATCH/reviewed_manifest.json --output PATH_TO_OUTPUT/gru --checkpoint-dir PATH_TO_CHECKPOINTS/gru --model-kind gru
python scripts/train_sequence.py --manifest PATH_TO_SCRATCH/reviewed_manifest.json --output PATH_TO_OUTPUT/gru_attention --checkpoint-dir PATH_TO_CHECKPOINTS/gru_attention --model-kind gru_attention
python scripts/fit_sequence_hybrid.py --manifest PATH_TO_SCRATCH/reviewed_manifest.json --sequence-bundle PATH_TO_OUTPUT/gru_attention --output PATH_TO_OUTPUT/hybrid_gru_attention
python scripts/compare_experiments.py --root PATH_TO_OUTPUT --output PATH_TO_OUTPUT/experiment_report.json
```

Nếu Colab ngắt, chạy lại notebook; `train_sequence.py --resume` đọc checkpoint
trên Drive và từ chối nếu manifest hoặc cấu hình mô hình khác. Checkpoint
huấn luyện nằm ngoài bundle triển khai. Bundle GRU có checksum cho metadata
và trọng số, phiên bản schema, nhãn, vocab, cấu hình chuỗi, provenance và
reference inference. Bundle hybrid GRU chứa thêm luật và tham số fusion.

## Môi trường và giới hạn kiểm chứng

Đã chạy local trên Windows, Python 3.11.15, PyTorch 2.7.1+cpu và NumPy 2.2.6.
Notebook kiểm tra PyTorch 2.x từ 2.7 trở lên rồi chạy smoke ngay trên runtime
Colab trước dữ liệu thật. Chưa xác minh GPU/Drive trên Colab; version thực tế
được ghi vào bundle. Không tự cài lại gói CUDA của runtime.

Smoke tổng hợp chạy qua `python scripts/smoke_training.py` và xuất
`detector_status=synthetic_smoke`, `deployable=false`. Fixture smoke dùng hai
event lặp mỗi run để kiểm thử cửa sổ và gradient, không chứng minh học ngữ cảnh
chuỗi trên telemetry thật. Chưa có dữ liệu thật được gán nhãn, kết quả phát hiện thật, đánh giá
theo phiên, độ trễ SIEM hoặc bundle được phép triển khai.
