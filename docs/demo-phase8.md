# Graduation project demonstration runbook

Mục tiêu: demo 8–10 phút, dùng số đo thật và không gửi Telegram ngoài ý muốn.

## Chuẩn bị

1. Xác nhận hardware/run ID và dùng `.env` cục bộ không chia sẻ.
2. `docker compose config --quiet`.
3. Start `rsyslog`; chỉ start PostgreSQL/Loki/Grafana/Dashboard nếu cần phần UI.
4. Không bật profile notifications trong benchmark demo.
5. Chạy warm-up 100/s trong 1 giây và bỏ kết quả warm-up khỏi báo cáo.

## Kịch bản

```bash
python -m app.benchmark \
  --mode compose \
  --rates 100 500 1000 \
  --duration 10 \
  --repetitions 3 \
  --run-id demo-YYYYMMDD
```

Trình bày theo thứ tự:

1. `manifest.json`: môi trường và tham số tái lập.
2. `results.csv`: generated → received → processed, không chỉ throughput đẹp nhất.
3. `throughput.svg`: target so với receive và processing.
4. `latency.svg`: nhấn mạnh basis là batch upper bound.
5. `quality.svg`: loss và parse failure.
6. `cpu.svg`/`memory.svg`: giới hạn VM 2 vCPU, khoảng 5,3 GiB RAM.
7. `aggregation.svg`: một alert nhưng toàn bộ raw trace còn giữ.

## Điều phải nói rõ trước hội đồng

- Windows local preflight không phải kết quả Ubuntu/GNS3.
- Ingress nhanh không có nghĩa processor theo kịp; drain/backlog phải được báo.
- Raw spool là evidence; benchmark không xóa volume để làm số liệu “sạch”.
- Loki/PostgreSQL/Grafana contention chỉ được kết luận khi Compose mode đã chạy thật.
- Nếu run fail hoặc Docker/GNS3 không có, trình bày `NOT_RUN` và nguyên nhân.

## Kết thúc

```bash
docker compose stop rsyslog
```

Chỉ stop service cần thiết. Không dùng `down -v`, prune, xóa CSV thất bại hoặc gửi artifact
có raw payload/credential.
