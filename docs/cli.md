# CLI dự phòng

Dùng CLI `hpt-siem` khi host chưa kết nối MCP hoặc khi người dùng làm việc trực tiếp trong terminal. Các lệnh dưới đây gọi cùng chức năng và dùng cùng phiên với tool MCP.

Môi trường đã cài `.[mcp,login]` có sẵn CLI. Nếu chỉ cần CLI và đăng nhập, cài `python -m pip install '.[login]'`. Có thể dùng `./.venv/Scripts/hpt-siem.exe` trong Windows PowerShell khi venv chưa được kích hoạt. Xem tham số bằng `hpt-siem <lệnh> --help`.

| MCP tool | Lệnh CLI |
| --- | --- |
| `HPT_list_siems` | `hpt-siem list-siems` |
| `HPT_status` | `hpt-siem status --siem demo` |
| `HPT_health` | `hpt-siem health --siem demo` |
| `HPT_register_siem` | `hpt-siem register --id demo --url 'https://kibana.example.org/s/security/app/home'` |
| `HPT_login` | `hpt-siem login --siem demo` |
| `HPT_logout` | `hpt-siem logout --siem demo` |
| `HPT_list_spaces` | `hpt-siem list-spaces --siem demo` |
| `HPT_list_data_views` | `hpt-siem list-data-views --siem demo` |
| `HPT_list_data_streams` | `hpt-siem list-data-streams --siem demo` |
| `HPT_check_query` | `hpt-siem check-query --siem demo --index 'edge-events-*'` |
| `HPT_check_alerts` | `hpt-siem list-alerts --siem demo --last-minutes 1440 --limit 5` |
| `HPT_list_rules` | `hpt-siem list-rules --siem demo --page 1 --limit 5` |
| `HPT_get_rule` | `hpt-siem get-rule --siem demo --rule-id example-rule` |
| `HPT_query` | `hpt-siem query --siem demo --index 'edge-events-*' --last-minutes 5 --limit 3 --backend auto --expression 'http.response.status_code >= 500'` |

CLI mặc định ở chế độ REST. Dùng `--backend auto` để ưu tiên REST rồi mới thử Discover, giống mặc định của MCP. `--backend discover` dùng Discover trực tiếp. Với alert, `--api auto` ưu tiên Detection Engine và hỗ trợ fallback sang Console. Chọn `--api detection-engine` hoặc `--api console` để ghim đường đọc. Dùng `--fields` lặp lại cho trường cần lấy, `--data-view-id` để lấy index pattern và time field, hoặc `--space` để chọn space khác.

KQL và Lucene nhận biểu thức qua `--expression`. Với ES|QL, đặt `--intent stats` hoặc `--language esql`. Pipeline tùy chỉnh nhận các bước xử lý sau `FROM` và cột đầu ra qua `--fields`. Search DSL nhận JSON qua `--dsl-file`, ví dụ [server-errors.json](../examples/server-errors.json). Nếu đã có đầu vào JSON qua stdin, dùng `--dsl-file -`.

CLI trả JSON trên stdout. Các mã `partial_results` và `no_shards` vẫn trả mã thoát 0 để giữ thông tin độ phủ. Kiểm tra `ok`, `code` và dữ liệu trả về. Thông báo chờ đăng nhập nằm trên stderr. Nếu server MCP chưa hiện trong danh sách tool, câu lệnh CLI có sẵn đủ để kiểm tra phiên và chạy các thao tác được hỗ trợ.
