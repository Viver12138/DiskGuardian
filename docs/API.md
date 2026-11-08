# DiskGuardian — Engine API (v0.3.0)

传输：stdin 一行一个 JSON 请求，stdout 一行一个 JSON 响应（JSONL）。日志只走 stderr。

```json
{"request_id": "req_1", "operation": "scan_disk", "params": {}}
{"request_id": "req_1", "success": true, "data": {...}, "error": null}
{"request_id": "req_1", "success": false, "data": null,
 "error": {"code": "E_PATH_NOT_ALLOWED", "message": "..."}}
```

限制：请求 ≤ 1 MiB；响应 ≤ 8 MiB（超限替换为 `E_TOO_LARGE`）；每个请求必须带 `request_id`；每次调用一个短生命周期进程，不做自动重试。

## 操作

| operation | 工具 | 参数（全部有边界） | 读/写 |
|---|---|---|---|
| `scan_disk` | `scan_disk` | — | 只读 |
| `scan_directories` | `scan_directories` | `paths?`(≤16)、`max_depth`(0–6)、`max_entries`、`max_seconds` | 只读 |
| `find_large_files` | `find_large_files` | `roots?`(≤16)、`min_bytes`、`limit`(≤500)、预算 | 只读 |
| `list_installed_software` | 同名 | `include_signature`、`limit`(≤2000) | 只读 |
| `inspect_startup_entries` | 同名 | `include_signature`、`include_tasks` | 只读 |
| `inspect_services` | 同名 | `include_signature`、`running_only` | 只读 |
| `inspect_browser_extensions` | 同名 | — | 只读 |
| `inspect_browser_settings` | 同名 | — | 只读 |
| `inspect_security_status` | 同名 | — | 只读 |
| `list_cleanup_candidates` | 同名 | `roots?`、`min_age_hours`、`limit`、`max_seconds` | 只读 |
| `purge_quarantine` | 同名 | `quarantine_ids?`、`older_than_days?`、`all?`、`dry_run?` | 永久删除隔离副本 |
| `classify_files` | 同名 | `paths`(≤64) | 只读 |
| `analyze_software` | 同名 | `include_signature`、`limit` | 只读 |
| `analyze_startup` | 同名 | `include_signature`、`include_tasks` | 只读 |
| `analyze_browser` | 同名 | — | 只读 |
| `analyze_security_status` | 同名 | — | 只读 |
| `create_cleanup_plan` | 同名 | `paths`(≤200 条)、`max_items`(≤500) | 只读（写计划） |
| `create_removal_plan` | 同名 | `software`(≤16) | 只读（写计划） |
| `create_startup_plan` | 内部（`manage_startup_entry`） | `name`、`action`、`scope?` | 只读（写计划） |
| `preview_action_plan` | 同名 | `plan_id` | 只读 |
| `issue_approval` | 内部（工具在用户确认后调用） | `plan_id`、`source` | 写授权记录 |
| `execute_cleanup_plan` | 同名 | `plan_id`、`approval_id` | 副作用（隔离） |
| `execute_removal_plan` | 同名 | `plan_id`、`approval_id` | 副作用（卸载） |
| `execute_startup_plan` | 内部（`manage_startup_entry`） | `plan_id`、`approval_id` | 副作用（注册表） |
| `restore_quarantined_item` | 同名 | `quarantine_id` | 副作用（恢复） |
| `list_quarantine` | 同名 | `limit` | 只读 |
| `list_startup_changes` | 同名 | `limit` | 只读 |
| `get_audit_log` | 同名 | `limit` | 只读 |
| `self_check` | `engine_status` | — | 只读 |

写入类操作（计划、授权、隔离、恢复）在 Phase D/E 加入，且必须携带 plan/approval 标识，不接受 `approved: true`。

## 错误码

| code | 含义 |
|---|---|
| `E_BAD_REQUEST` / `E_INVALID_PARAMS` | 请求格式或参数越界 |
| `E_UNKNOWN_OPERATION` | 未注册的 operation |
| `E_PATH_NOT_ALLOWED` | UNC、非固定磁盘、越界路径 |
| `E_NOT_FOUND` | 目标不存在 |
| `E_TOO_LARGE` | 请求或响应超过上限 |
| `E_TIMEOUT` | 引擎未在期限内应答（客户端终止进程） |
| `E_ACCESS_DENIED` / `E_ELEVATION_REQUIRED` | 权限不足（Phase D/E 使用） |
| `E_QUARANTINE_FULL` | 隔离区容量不足以容纳本次计划（未消费批准，可释放后重试） |
| `E_ENGINE` | 未预期的引擎内部错误 |
| `E_ENGINE_UNAVAILABLE` / `E_PYTHON_NOT_FOUND` / `E_ENGINE_SPAWN` / `E_ENGINE_CRASH` / `E_ENGINE_PROTOCOL` | 客户端侧传输错误 |

## 结果约定

- 每个扫描结果带 `scan_id`；存储写入失败时带 `storage_error`，扫描数据仍然返回。
- 覆盖率信息放在 `coverage`：查询是否可用、检查了多少条、哪些被过滤或不可读。
- 预算截断用 `truncated` + `truncated_reason`（`entries` / `time`）。
- 签名结果是 `valid`、具体失败原因（如 `unsigned`、`untrusted-root`）或 `unavailable`；它只是证据，不是判决。
