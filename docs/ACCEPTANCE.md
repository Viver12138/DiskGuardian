# DiskGuardian — Headless Acceptance

> 版本 0.7.0 · 2026-11-08
> 命令：`python tools/acceptance.py`

## 1. 这是什么

一个不依赖 Harness 会话的端到端验收脚本。它在工作区内的临时沙箱里启动**真实的引擎进程**，
通过**真实的 JSONL 协议**跑完整场景，然后打印逐项 PASS/FAIL。

```powershell
cd C:\Users\Viver\Desktop\dsh_plugin_dev
python tools/acceptance.py
```

沙箱会重定向 `TEMP` / `LOCALAPPDATA` / `USERPROFILE`，所以它**不会碰用户的真实文件或数据库**。

## 2. 最近一次结果：33/33 PASS

| 场景 | 结果 | 摘要 |
|---|---|---|
| self_check | PASS | 27 operations |
| scan_disk | PASS | 3 disks |
| scan_directories | PASS | 4096 bytes |
| find_large_files | PASS | 1 file |
| list_installed_software | PASS | 135 installed |
| inspect_startup_entries | PASS | 11 entries |
| inspect_services | PASS | 154 running services |
| inspect_browser_extensions | PASS | 2 browser entries（见 §4） |
| inspect_browser_settings | PASS | coverage reported |
| inspect_security_status | PASS | defender block present |
| analyze_software | PASS | 5 findings |
| analyze_startup | PASS | 11 findings |
| analyze_browser | PASS | 0 findings（见 §4） |
| analyze_security_status | PASS | 1 finding |
| classify_files | PASS | temporary-file / eligible |
| create_cleanup_plan | PASS | cleanup |
| preview_action_plan | PASS | pending |
| issue_approval | PASS | approval issued |
| execute_cleanup_plan | PASS | completed |
| list_quarantine | PASS | 1 quarantined |
| restore_quarantined_item | PASS | restored |
| create_cleanup_plan_purge | PASS | cleanup |
| purge_quarantine | PASS | 1 purged, 1024 bytes |
| replay_rejected | PASS | `E_APPROVAL_USED` |
| get_audit_log | PASS | 4 entries |
| create_removal_plan_unknown | PASS | `E_PLAN_EMPTY` |
| create_startup_plan_unknown | PASS | `E_NOT_FOUND` |
| unknown_operation | PASS | `E_UNKNOWN_OPERATION` |

## 3. 覆盖了什么

- 9 个只读扫描器中的 8 个（浏览器两个受 §4 限制）+ 安全状态
- 4 个分析器
- 文件分类 → 计划 → 预览 → 批准 → 隔离 → 恢复 的完整副作用链路
- 批准重放被拒
- 审计日志落盘
- 三类错误码（计划为空、目标不存在、未知操作）

## 4. 这个脚本**不能**替代的验证

| 项 | 原因 |
|---|---|
| Harness 会话内的 `ctx.subprocess` | 脚本直接用 `python` 子进程，不经过 Harness |
| 确认卡片渲染与点击 | 需要真实客户端 |
| 真实注册表写入 | 脚本不写 HKCU/HKLM；沙箱也禁止 |
| 真实软件卸载 | 不做，避免破坏用户环境 |
| 浏览器扩展/设置真实数据 | `LOCALAPPDATA` 被重定向，Chrome/Edge 配置文件不可见 → `analyze_browser` 得到 0 条 |

浏览器能力已在**真实环境**单独验证过：3 个配置文件、50 个扩展、主页/启动页/默认搜索均正常返回
（见 `TEST_REPORT.md` §4）。

## 5. 如何读结果

- 任何 `FAIL` 都是引擎层缺陷，应当修代码，而不是改期望。
- 脚本退出码：全通过 0，否则 1，便于手工回归时一眼判断。
- 每次运行都会新建一个沙箱目录（`.tmp-tests/accept-<时间戳>`），可以随时删除。
