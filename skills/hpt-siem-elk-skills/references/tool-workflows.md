# Dùng tool HPT SIEM

Gọi các tool của MCP server `hpt_siem` trực tiếp với đối tượng JSON. Ví dụ dưới đây dùng SIEM mẫu `demo`, space mẫu `soc` và namespace mẫu `prod`. Thay các giá trị này bằng phạm vi đã xác nhận của yêu cầu hiện tại.

## Chọn tool

| Việc cần làm | Tool và tham số chính |
| --- | --- |
| Tìm SIEM đã đăng ký | `HPT_list_siems` với `{}`. Dùng ID trả về làm `siem`. |
| Đăng ký URL người dùng cung cấp | `HPT_register_siem` với `siem` và `url`. Dùng `allow_http: true` nếu người dùng chấp nhận HTTP. |
| Kiểm tra Kibana có phản hồi | `HPT_health` với `siem`. |
| Kiểm tra phiên đã lưu | `HPT_status` với `siem` và `space` cần dùng. |
| Đăng nhập khi phiên chưa dùng được | `HPT_login` với `siem` và `space`. Gọi khi người dùng sẵn sàng nhập thông tin trong browser. |
| Xóa phiên cục bộ theo yêu cầu | `HPT_logout` với `siem`. Kiểm tra `localSessionRemoved` trong kết quả. |
| Xác định space ID | `HPT_list_spaces` với `siem`. Dùng `limit` và `offset` khi cần thêm trang. |
| Tìm data view và index pattern | `HPT_list_data_views` với `siem`, `space` và tùy chọn `limit`, `offset`. |
| Tìm data stream | `HPT_list_data_streams` với cùng phạm vi. Nếu trả `403`, dùng data view đã xác minh để tìm nguồn. |
| Kiểm tra đường REST và quyền đọc | `HPT_check_query` với `siem`, `space` và `index` hoặc `data_view_id`. Kết quả chưa xác nhận Discover. |
| Tìm hoặc thống kê log | `HPT_query` với `siem`, `space`, nguồn và biểu thức `query`. |
| Đọc alert | `HPT_check_alerts` với `siem`, `space`, khoảng thời gian và `limit`. Có thể thêm `severity`, `workflow_status` hoặc `alert_id`. |
| Liệt kê rule | `HPT_list_rules` với `siem`, `space`, `page` và `limit`. |
| Đọc một rule | `HPT_get_rule` với `siem`, `space` và đúng một trong `id` hoặc `rule_id`. Thêm `include_query: true` nếu cần biểu thức rule. |

## Query log theo đúng nguồn

1. Chọn `space` bằng ID. Nếu người dùng chỉ nêu tên data view, tra `HPT_list_data_views` và dùng `data_view_id` hoặc index pattern thực tế.
2. Với nguồn dùng chung, xác minh field và giá trị namespace rồi đưa điều kiện vào `query`. Ví dụ, chọn đúng data view nhưng thiếu điều kiện namespace vẫn có thể trả thêm log từ nguồn khác.
3. Chọn thời gian, `limit` và các `fields` cần đọc. Mặc định `HPT_query` dùng 5 phút và tối đa 5 kết quả. Dùng `start` và `end` theo ISO 8601 có múi giờ để tái lập truy vấn.

**KQL để lọc nhanh.** Truyền trực tiếp biểu thức vào `query`.

```json
{
  "siem": "demo",
  "space": "soc",
  "index": "logs-nginx.access-prod",
  "query": "data_stream.namespace: \"prod\" AND destination.port: 443",
  "last_minutes": 5,
  "limit": 3,
  "fields": ["@timestamp", "data_stream.namespace", "source.ip", "destination.port"]
}
```

**ES|QL để đếm hoặc nhóm.** Với `intent: "stats"`, tool thêm nguồn `FROM` và khoảng thời gian. Truyền các bước xử lý sau `FROM` và chọn cột đầu ra. Đặt bộ lọc namespace trước `STATS`.

```json
{
  "siem": "demo",
  "space": "soc",
  "index": "logs-nginx.access-prod",
  "intent": "stats",
  "query": "WHERE data_stream.namespace == \"prod\" | STATS events = COUNT(*) BY destination.port | SORT events DESC",
  "fields": ["destination.port", "events"],
  "last_minutes": 15,
  "limit": 5
}
```

**Search DSL hoặc Lucene theo yêu cầu.** Với Search DSL, gửi đối tượng như `{"query":{"term":{"data_stream.namespace":"prod"}}}` làm giá trị của tham số `query`, có thể thêm các điều kiện khác bằng `bool.filter`. Với Lucene, đặt `language: "lucene"` và gửi biểu thức dạng chuỗi.

## Đọc alert và truy vết log gốc

Ví dụ gọi `HPT_check_alerts` để lấy 5 alert gần nhất trong 30 phút.

```json
{
  "siem": "demo",
  "space": "soc",
  "last_minutes": 30,
  "limit": 5,
  "fields": [
    "@timestamp", "kibana.space_ids", "kibana.alert.rule.name",
    "kibana.alert.severity", "kibana.alert.workflow_status",
    "kibana.alert.original_time", "kibana.alert.ancestors.id",
    "kibana.alert.ancestors.index", "kibana.alert.original_data_stream.namespace",
    "source.ip", "destination.ip", "host.name"
  ]
}
```

1. Đối chiếu `kibana.space_ids` với yêu cầu. Nếu trường vắng, kiểm tra index alert. Khi cần đọc lại đúng alert, truyền `alert_id` và khoảng thời gian chứa alert đó.
2. Truy vết bằng `HPT_query` trên nguồn log đã xác minh. Ưu tiên ID/index gốc trong `kibana.alert.ancestors.*` và `kibana.alert.original_time` nếu phù hợp với loại rule. Khi thiếu ID nguồn, lọc theo host, IP hoặc định danh tiến trình trong cửa sổ hẹp. Giữ điều kiện namespace khi nguồn dùng chung.
3. Nêu rõ bằng chứng nối trực tiếp với sự kiện gốc và các log chỉ trùng ngữ cảnh. Nếu alert thiếu namespace gốc, đối chiếu log nguồn trước khi gán. Tổng từ `HPT_check_alerts` là tổng theo space và các bộ lọc mà tool hỗ trợ. Muốn đếm riêng namespace, chỉ dùng `HPT_query` trên alias alert riêng của space khi đã xác minh quyền đọc, field và độ phủ.

## Đọc kết quả và xử lý lỗi

- Dùng `data.adapter` để biết đường thực tế. `auto` ưu tiên REST và có thể dùng Discover cho truy vấn tương thích. Dùng `backend: "api"` nếu yêu cầu chỉ dùng REST. Với Discover, ưu tiên `fields` để chọn đầu ra. Search DSL, `source` và `offset` dùng REST.
- `total.relation: "eq"` cho tổng chính xác trong phạm vi đã tìm nếu kết quả đầy đủ. `gte` cho cận dưới. Kiểm tra `isPartial`, shard lỗi, giới hạn kết quả và phạm vi đã tìm trước khi kết luận.
- Khi gặp `login_required`, hướng người dùng đăng nhập qua `HPT_login`. Với `permission_denied`, báo space, nguồn và đường bị từ chối. Với `timeout` hoặc `network_unreachable`, kiểm tra kết nối. Kết luận không tìm thấy dữ liệu cần một truy vấn thành công ở đúng nguồn.
- Nếu MCP chưa nạp, dùng CLI `hpt-siem`. Các lệnh thường dùng là `list-siems`, `list-spaces`, `list-data-views`, `query` và `list-alerts`. Dùng `hpt-siem <lệnh> --help` để xem tham số. Dùng `--backend auto` nếu cần REST ưu tiên và Discover dự phòng.
