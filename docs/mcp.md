# Dùng HPT_SIEM_ELK_Skills qua MCP

MCP server `hpt_siem` chạy trên máy của bạn. Khi Codex hoặc Claude Code kết nối, bạn có thể yêu cầu agent bằng ngôn ngữ tự nhiên, chẳng hạn “Tìm 3 log mới nhất trong space SOC của SIEM demo”. Agent gọi tool `HPT_query` với các tham số phù hợp. CLI `hpt-siem` dùng cùng danh sách SIEM và phiên đăng nhập.

## Cài đặt

### Python và thư viện

Trên máy truy cập được Kibana, mở terminal ở thư mục repository. Dùng Python 3.10 trở lên. Nếu đã có `.venv`, bắt đầu từ lệnh `pip install`. Pip sẽ cài các thư viện còn thiếu theo `pyproject.toml`.

**Windows PowerShell**

```powershell
python -m venv .venv
./.venv/Scripts/python.exe -m pip install '.[mcp,login]'
./.venv/Scripts/python.exe -m pip check
./.venv/Scripts/python.exe -c "import hpt_siem, mcp, playwright; print('OK')"
```

**macOS hoặc Linux**

```sh
python3 -m venv .venv
./.venv/bin/python -m pip install '.[mcp,login]'
./.venv/bin/python -m pip check
./.venv/bin/python -c "import hpt_siem, mcp, playwright; print('OK')"
```

Extra `mcp` cài thư viện để Codex hoặc Claude Code gọi tool. Extra `login` cài Playwright cho đăng nhập và Discover. Có thể dùng Edge hoặc Chrome đã cài. Nếu dùng `browser: "chromium"` và chưa có trình duyệt Playwright, chạy Python trong venv với `-m playwright install chromium`. [Playwright browser channels](https://playwright.dev/python/docs/browsers).

### Cài skill

Sau khi tải repository, sao chép nguyên thư mục `skills/hpt-siem-elk-skills/`. Bên trong thư mục đã cài phải có `SKILL.md`, `references/` và `agents/`.

| Agent | Cài cho project | Cài cho người dùng | Tên để gọi tường minh |
| --- | --- | --- | --- |
| Codex | `.agents/skills/hpt-siem-elk-skills/` | `~/.agents/skills/hpt-siem-elk-skills/` | `$hpt-siem-elk-skills` |
| Claude Code | `.claude/skills/hpt-siem-elk-skills/` | `~/.claude/skills/hpt-siem-elk-skills/` | `/hpt-siem-elk-skills` |

Ví dụ cài cho project từ thư mục repository bằng Windows PowerShell.

```powershell
$skillDir = '.agents/skills'
# Với Claude Code, dùng $skillDir = '.claude/skills'
New-Item -ItemType Directory -Path $skillDir -Force | Out-Null
Copy-Item -LiteralPath 'skills/hpt-siem-elk-skills' -Destination $skillDir -Recurse -Force
```

Trên macOS hoặc Linux, dùng `mkdir -p .agents/skills` và `cp -R skills/hpt-siem-elk-skills .agents/skills/`. Với Claude Code, thay `.agents/skills` bằng `.claude/skills`. Nếu cài vào project khác, dùng đường dẫn tuyệt đối tới thư mục đích.

**Tên hiển thị** trong Codex là `HPT_SIEM_ELK_Skills`, lấy từ `agents/openai.yaml`. **Định danh kỹ thuật** là `hpt-siem-elk-skills`, trùng tên thư mục và trường `name` của Agent Skills. Claude Code dùng định danh này trong menu lệnh. Tên hiển thị của project có trong tiêu đề `SKILL.md`. [Chuẩn Agent Skills](https://agentskills.io/specification) · [Skill trong Codex](https://developers.openai.com/codex/skills) · [Skill trong Claude Code](https://code.claude.com/docs/en/skills).

Nếu đã có GitHub CLI hỗ trợ `gh skill install`, có thể cài từ bản phát hành sau khi repository được công bố. Chọn `--agent codex` hoặc `--agent claude-code` và phạm vi `--scope project` hoặc `--scope user`. Sau khi cài skill, cấu hình MCP server ở bước tiếp theo để agent có thể gọi tool. [GitHub CLI](https://cli.github.com/manual/gh_skill_install).

### Codex

Thêm cấu hình bên dưới vào file phù hợp. Dùng đường dẫn tuyệt đối tới Python trong venv và thư mục repository.

- **Dùng trong mọi project trên cùng máy**. Thêm vào `~/.codex/config.toml` hoặc `config.toml` dưới `CODEX_HOME` nếu đã đặt biến này.
- **Dùng trong một project**. Thêm vào `.codex/config.toml` của project được Codex tin cậy. Mở chat từ đúng project để Codex đọc cấu hình này. File có đường dẫn theo máy và được Git bỏ qua.

```toml
[mcp_servers.hpt_siem]
command = 'C:\path\to\HPT_SIEM_ELK_Skills\.venv\Scripts\python.exe'
args = ["-m", "hpt_siem.mcp_server"]
cwd = 'C:\path\to\HPT_SIEM_ELK_Skills'
startup_timeout_sec = 20
tool_timeout_sec = 300
```

Trên macOS/Linux, đổi `command` và `cwd` sang đường dẫn tương ứng. Sau khi lưu, dùng **Settings → MCP servers → Restart** trên Desktop rồi mở hoặc quay lại project và kiểm tra `/mcp`. Khi cần gọi skill tường minh, dùng `$hpt-siem-elk-skills`. [Cấu hình MCP trong Codex](https://developers.openai.com/codex/mcp).

### Claude Code

Chạy lệnh sau trong project và đổi đường dẫn Python theo máy.

```powershell
claude mcp add --transport stdio --scope local hpt_siem -- "C:\path\to\HPT_SIEM_ELK_Skills\.venv\Scripts\python.exe" -m hpt_siem.mcp_server
```

Dùng `/mcp` để kiểm tra server và `/hpt-siem-elk-skills` để gọi skill tường minh. Host MCP và browser đăng nhập cần chạy trong phiên OS của người dùng có VPN hoặc mạng nội bộ. [Cấu hình MCP trong Claude Code](https://code.claude.com/docs/en/mcp).

### Xác nhận kết nối

1. Mở phiên mới trong project đã cài. Trong Codex, gõ `$` hoặc mở bộ chọn skill và tìm `HPT_SIEM_ELK_Skills`. Trong Claude Code, gõ `/` và tìm `hpt-siem-elk-skills`. Nếu chưa thấy, kiểm tra đường dẫn thư mục, rồi khởi động lại agent. [Chọn skill trong Codex](https://developers.openai.com/codex/skills) · [Lệnh skill trong Claude Code](https://code.claude.com/docs/en/skills).
2. Gõ `/mcp` và kiểm tra server `hpt_siem` đã kết nối. Server cung cấp 14 tool có tiền tố `HPT_`. Một số host hiển thị thêm tên server trước tên tool.
3. Yêu cầu agent gọi `HPT_list_siems` với `{}`. Danh sách có thể rỗng nếu bạn chưa đăng ký SIEM. Tiếp theo gọi `HPT_status` với ID SIEM đã đăng ký để xác minh kết nối và phiên.

Nếu `hpt_siem` chưa xuất hiện, chạy `codex mcp get hpt_siem` từ thư mục của chat để kiểm tra phạm vi cấu hình. Lệnh này xác nhận CLI đọc được cấu hình. `/mcp` và lời gọi `HPT_list_siems` xác nhận chat đã nạp server và gọi được tool. Nếu cấu hình đúng nhưng chat chưa có tool, kiểm tra đường dẫn Python, chạy lại hai lệnh kiểm tra thư viện ở trên, rồi nạp lại MCP trong Desktop. Khi cần, thử trong một chat mới từ đúng project.

### Nâng cấp từ bản dùng tên cũ

Cài lại project bằng lệnh cài đặt ở trên, cập nhật thư mục skill đã sao chép rồi mở phiên agent mới. Cập nhật automation hoặc lời gọi MCP đã lưu theo mẫu `query` thành `HPT_query`. Tiền tố phân biệt chữ hoa và chữ thường. Tên server trong cấu hình vẫn là `hpt_siem`. Cú pháp CLI và các tham số như `siem`, `space`, `query` giữ nguyên.

## Tool

Xem [danh sách 14 tool và ví dụ tham số](../skills/hpt-siem-elk-skills/references/tool-workflows.md). Tài liệu này đi cùng thư mục skill, nên agent có thể đọc sau khi cài riêng skill.

## Phạm vi space và namespace

`space` chọn ngữ cảnh Kibana, nơi có data view, rule và alert của space. Một data view trong space vẫn có thể trỏ đến nhiều data stream. Namespace là nhãn của dữ liệu nguồn, ví dụ `prod` hoặc `qa`. Tài khoản có quyền đọc nhiều nguồn có thể thấy log từ nhiều namespace trong cùng một data view. [Kibana spaces và Elastic Security](https://www.elastic.co/docs/solutions/security/get-started/spaces-elastic-security) · [Data streams và namespace](https://www.elastic.co/docs/reference/fleet/data-streams).

1. **Xác nhận phạm vi trước khi search.** Truyền đúng `siem` và `space`, rồi tra `HPT_list_data_views` để lấy index pattern thực tế. Xác nhận cặp field–giá trị với cấu hình nguồn, người vận hành hoặc mẫu lấy từ stream đã biết thuộc phạm vi cần điều tra. Với Elastic Agent, kiểm tra `data_stream.namespace` và đối chiếu `data_stream.dataset` cùng `_index`. Một mẫu có thể xác nhận field tồn tại. Cần thêm căn cứ nếu muốn coi namespace đó là duy nhất của space. Một số dataset cũ dùng field riêng hoặc chỉ có index/alias đã tách nguồn.
2. **Lọc log gốc ngay trong truy vấn.** Chọn data view hoặc index hẹp nhất phù hợp, kết hợp điều kiện namespace với IP, host, ID sự kiện hoặc thời gian. Với ES|QL, đặt `WHERE data_stream.namespace == "prod"` trước `STATS`. Với Search DSL, thêm `{"term":{"data_stream.namespace":"prod"}}` vào `bool.filter`. Giữ điều kiện này khi đổi backend hoặc dùng log gốc để trace alert. Nếu field chưa xác định, dùng nguồn đã xác minh chỉ chứa đúng dữ liệu cần điều tra hoặc hỏi người vận hành về mapping trước khi báo kết quả theo namespace.
3. **Xác minh space của alert.** `HPT_check_alerts` truy vấn alert của space đã chọn. Thêm `kibana.space_ids` vào `fields` và kiểm tra danh sách có chứa ID space đó. Khi field vắng mặt, đối chiếu alias hoặc backing index alert của space. Nếu giá trị mâu thuẫn với space đã chọn, ghi rõ và kiểm tra lại. Khi dùng `HPT_query` với alias alert cụ thể, có thể lọc phía server bằng KQL `kibana.space_ids: "soc"` nếu đã xác minh field có mặt trên các alert cần xét.
4. **Xác minh namespace nguồn của alert.** Yêu cầu `kibana.alert.original_data_stream.namespace`, `data_stream.namespace` và `kibana.alert.ancestors.index` trong `fields`. Trường namespace gốc có thể vắng mặt tùy loại rule hoặc dữ liệu đầu vào. Nếu các trường vắng mặt hay mâu thuẫn, dùng ID/index sự kiện gốc nếu có để truy vết với `HPT_query` đã lọc namespace. Ghi rõ các alert chưa xác định được nguồn. [Schema alert của Elastic Security](https://www.elastic.co/docs/reference/security/fields-and-object-schemas/alert-schema).

`HPT_check_alerts` hiện chưa có tham số lọc namespace phía server. `fields` chỉ chọn trường trả về. Lọc các hit đã đọc chỉ xác nhận các mẫu khớp. `total` của lượt gọi vẫn là tổng theo space và các bộ lọc tool hỗ trợ. Để lấy tổng hoặc alert mới nhất riêng một namespace, dùng `HPT_query` với điều kiện namespace nguồn đã xác minh trên **alias alert cụ thể của space** nếu tài khoản có quyền, đường query đã được xác minh và field đó có trên các alert cần xét. Chỉ báo tổng chính xác khi kết quả xác nhận độ phủ đầy đủ, chẳng hạn `total.relation: "eq"` với truy vấn trả hit và `isPartial: false`. Nếu chưa đủ điều kiện, ghi rõ phạm vi đã xem và số alert chưa xác định được namespace trong mẫu. Tránh dùng wildcard bao trùm alias alert của nhiều space.

## Đường truy vấn và đầu ra

Tool kết nối tới URL Kibana đã đăng ký. `backend: "auto"` là mặc định của MCP. Tool ưu tiên REST và dùng Discover trong trình duyệt riêng khi thao tác đủ điều kiện. Chọn `backend: "api"` để giới hạn ở REST hoặc `backend: "discover"` để dùng trực tiếp Discover.

| Thao tác | API Kibana |
| --- | --- |
| Sức khỏe | `GET /api/status`. Mã HTTP 200 có thể trả cho yêu cầu ẩn danh. Dùng `HPT_status` với probe có xác thực để kiểm tra phiên. |
| Space và data view | `GET /api/spaces/space`, `GET /api/data_views`, `GET /api/data_views/data_view/<id>`. |
| Detection rule | `GET /api/detection_engine/rules/_find` để liệt kê và `GET /api/detection_engine/rules?id=...` hoặc `?rule_id=...` để đọc chi tiết. |
| Security Alert | `POST /api/detection_engine/signals/search` trước. Nếu route hoặc offset không khả dụng, `auto` dùng `POST /api/console/proxy` để gọi `_search` trên alias alert của space. Chỉ định index tùy chỉnh hoặc schema legacy dùng Console. |
| Log và ES\|QL | `POST /api/console/proxy` cho `_search` hoặc `_query`. ES\|QL có thể dùng thêm `POST /api/agent_builder/tools/_execute` với tool cố định `platform.core.execute_esql`. |
| Data stream | `POST /api/console/proxy` cho `GET /_data_stream`. Khi cần, thử `GET /api/fleet/data_streams` để đọc stream Fleet quản lý. |

Lỗi xác thực, thiếu quyền, payload sai hoặc timeout của Detection Engine được trả về cho người gọi. Rule là cấu hình phát hiện và alert là kết quả đã phát sinh. Một deployment có thể đọc được alert và rule dù chưa có quyền truy vấn log qua Console hoặc Agent Builder. [Kibana Status](https://www.elastic.co/docs/api/doc/kibana/operation/operation-get-status) · [Detection Rules](https://www.elastic.co/docs/api/doc/kibana/v8/operation/operation-findrules) · [Elastic Security alert indices](https://www.elastic.co/docs/solutions/security/detect-and-alert/query-alert-indices).

Discover dự phòng cho KQL, Lucene và ES|QL khi đường API của Kibana bị chặn hoặc không hỗ trợ cú pháp tương ứng. KQL và Lucene cần data view phù hợp với time field. Dùng `fields` để chọn trường trả về. Discover sử dụng cơ chế lấy mẫu của giao diện, nên `total.relation` có thể là `gte`. Search DSL, `source` và phân trang bằng `offset` dùng REST. Một lỗi từ chối quyền ở index Elasticsearch được trả về trực tiếp. Với alert, fallback sang Discover chỉ được cân nhắc sau khi Detection Engine và Console cùng không khả dụng. [ES|QL trong Discover](https://www.elastic.co/docs/explore-analyze/query-filter/languages/esql-kibana).

Chọn một nguồn bằng `index` hoặc `data_view_id`. Data view cung cấp index pattern và time field. Với `HPT_check_query`, chọn nguồn cụ thể để kiểm tra quyền đọc qua REST. Khi bỏ nguồn, tool chỉ thử ES|QL bằng `ROW` và để quyền index là `not_checked`. Nếu REST không khả dụng, gọi `HPT_query` với `backend: "auto"`, giới hạn thời gian và `limit: 1` để kiểm tra đường Discover.

Khoảng tìm kiếm tối đa là 31 ngày. Dùng `start` và `end` có múi giờ khi cần cửa sổ tuyệt đối. Một lần gọi trả tối đa 100 hit hoặc hàng. Tool chấp nhận tối đa 20 tên trường đầu ra. Với ES|QL tùy chỉnh, dùng các bước `WHERE`, `STATS`, `SORT`, `EVAL`, `KEEP`, `DROP` hoặc `RENAME` và chọn cột trả về với `fields`. Với Search DSL, dùng khóa cấp cao `query`.

Đọc `data.adapter` để biết đường chạy và `data.apiFallback` khi tool chuyển sang Console hoặc Discover. Xem `total.relation`, `isPartial`, `shards` và `shardFailures` nếu có trước khi kết luận kết quả đầy đủ. Khi `isPartial` là `null`, phản hồi không cung cấp cờ partial.

| Kết quả | Hành động |
| --- | --- |
| `login_required` | Dùng `HPT_login` khi người dùng có thể tương tác. |
| `timeout` / `network_unreachable` | Kiểm tra VPN hoặc định tuyến. Trạng thái phiên chưa được xác minh. |
| `permission_denied` | Xem lớp báo lỗi trong `details` và quyền theo space, API hoặc index. |
| `unsupported_language` / `unsupported_capability` | Dùng `HPT_check_query` để kiểm tra API và ngôn ngữ khả dụng. |
| `partial_results` / `no_shards` | Nêu rõ giới hạn độ phủ khi trả kết quả. |

## Khi nào dùng CLI hoặc script

1. **MCP đã kết nối:** gọi tool trực tiếp. Bộ lọc, khoảng thời gian, cột trả về và thống kê là tham số của tool. Với yêu cầu nhiều bước như trace alert, gọi `HPT_check_alerts` rồi `HPT_query` trên log nguồn.
2. **MCP chưa kết nối:** dùng [lệnh CLI tương ứng](cli.md). Ví dụ, kiểm tra phiên bằng `hpt-siem status --siem demo`. Chỉ cần lệnh đã cài để kiểm tra thao tác.
3. **Tool và CLI chưa đáp ứng yêu cầu:** cân nhắc script riêng khi người dùng cần xử lý tùy biến cao, như ghép dữ liệu SIEM với nguồn ngoài đã được phép hoặc tạo định dạng xuất riêng. Giữ quyền và phạm vi dữ liệu đã được cấp. Tận dụng kết quả tool hoặc CLI làm đầu vào khi có thể.
