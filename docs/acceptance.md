# Kiểm thử MCP trước vận hành

Chạy kiểm thử tự động trong môi trường có extra `.[mcp,login]`. Sau đó thử trực tiếp từng tool trên một SIEM được người dùng cung cấp. Kiểm thử trực tiếp cần VPN hoặc mạng nội bộ, trình duyệt tương tác và tài khoản với các quyền dự kiến khi vận hành.

```sh
python -m pip check
python -m unittest discover -s tests -v
```

## Ma trận nghiệm thu

| Bước | Tiêu chí đạt |
| --- | --- |
| Skill discovery | Cài theo [hướng dẫn](mcp.md#cài-skill), mở phiên mới và tìm `HPT_SIEM_ELK_Skills` trong bộ chọn Codex hoặc `/hpt-siem-elk-skills` trong Claude Code. Khi mở skill, liên kết tới `references/tool-workflows.md` dùng được từ thư mục đã cài. |
| MCP discovery | Host nhận đủ 14 tool qua stdio. |
| `HPT_register_siem`, `HPT_list_siems` | Một ID thử mới được đăng ký và xuất hiện trong danh sách. |
| `HPT_status`, `HPT_login` | Trước đăng nhập trả `login_required`. Người dùng tự đăng nhập trong browser. `HPT_status` thành công từ tiến trình MCP mới. |
| `HPT_health` | Đọc `/api/status` không dùng cookie và báo Kibana khả dụng. |
| `HPT_list_spaces`, `HPT_list_data_views`, `HPT_list_data_streams` | Trả dữ liệu xác thực trong phạm vi quyền. Ghi `coverage` của stream inventory khi có. |
| `HPT_check_query` | Trả kết quả theo API cho từng ngôn ngữ. Phân biệt quyền đọc đã xác minh và backend bị chặn. |
| `HPT_query` | Chạy KQL và ES\|QL trên cùng nguồn hẹp, tối đa một hit hoặc hàng. Lặp lại KQL trong cùng cửa sổ 5 phút. Xem backend thực tế, shard và độ phủ. |
| `HPT_check_alerts` | Đọc tối đa một alert trong 24 giờ. Nếu có alert, đọc lại theo ID và so khớp. Tổng bằng 0 là hợp lệ nếu phạm vi tìm kiếm được xác minh. |
| `HPT_list_rules`, `HPT_get_rule` | Lấy một bản tóm tắt rule rồi đọc chi tiết bằng `rule_id`. Đối chiếu UUID giữa hai phản hồi. |
| `HPT_logout` | Xóa đúng phiên thử cục bộ, trả `serverRevoked:false`. `HPT_status` sau đó trả `login_required`. |

## Chạy trên một SIEM được phép

Khi MCP đã kết nối trong agent, có thể gọi từng tool theo ma trận. Để lặp cả bài test bằng một lệnh, dùng runner nghiệm thu có sẵn. Runner điều phối các tool qua MCP stdio, khởi động lại tiến trình giữa các giai đoạn và chỉ in mã trạng thái, số lượng và thông tin độ phủ. Mỗi lần chạy cần một ID thử chưa tồn tại.

```sh
python tests/acceptance_mcp.py --url 'https://kibana.example.org/login' --siem preflight-demo
```

Chỉ dùng `--allow-http` khi người dùng chấp nhận HTTP. Runner tự gọi `HPT_logout` cho phiên nó tạo. Đăng ký thử vẫn nằm trong registry cục bộ. Không truyền mật khẩu hoặc OTP qua đối số.

Nếu trả `permission_denied`, ghi rõ tool nào bị chặn và lớp báo lỗi. Nếu trả `timeout`, `partial_results` hoặc `no_shards`, thao tác đó chưa được nghiệm thu. Kết quả một lần chạy là kiểm tra chức năng tại thời điểm đó. Kiểm tra lại sau khi đổi quyền, VPN, phiên bản Kibana hoặc cấu hình MCP.
