# Phase C — 只读引擎与扫描器

> 状态：**代码完成**，全部只读能力已在本机真实数据上跑通；Harness 会话内的实时验证待重启后执行（见 §4）
> 日期：2026-11-08
> 版本：`0.3.0`

## 1. 交付内容

### 引擎（Python，stdlib 优先）

| 模块 | 作用 |
|---|---|
| `engine/run.py` + `diskguardian/main.py` | JSONL 循环：一行一请求、一行一响应、stderr 日志、`--self-check` |
| `diskguardian/protocol.py` | 请求 1 MiB / 响应 8 MiB 上限、错误码、参数边界（int/bool/str-list） |
| `diskguardian/storage/` | SQLite 10 张表 + 迁移 + 事务；扫描会话落库，写库失败降级为 `storage_error` |
| `diskguardian/permissions/paths.py` | 只允许绝对本地路径、拒绝 UNC、只允许固定磁盘、重解析点判定 |
| `diskguardian/util.py` | 命令解析（只用于证据提取，从不执行）、时间格式化 |

### 扫描器（全部只读）

| 扫描器 | 机制 | 不依赖 |
|---|---|---|
| `scanner/volumes.py` | `GetLogicalDrives` / `GetDiskFreeSpaceExW` / `GetVolumeInformationW` | 无 WMI、无 shell |
| `scanner/filesystem.py` | `os.scandir` 递归 + 条目/时间预算 + 跳过重解析点 | 无 |
| `scanner/software.py` | 卸载注册表键（HKLM 64/32、HKCU）+ Authenticode | 无 WMI |
| `scanner/startup.py` | Run/RunOnce 注册表键、Startup 目录、`System32\Tasks` XML（回退 ScheduledTasks cmdlet） | 无 COM |
| `scanner/services.py` | `HKLM\SYSTEM\CurrentControlSet\Services` + `sc.exe query state= all` | 无 WMI |
| `scanner/browser.py` | Chrome/Edge `Local State`、`Preferences`、扩展 `manifest.json` | 无浏览器 API |
| `scanner/security.py` | Defender cmdlet、防火墙策略注册表、SCM 服务状态、OS 注册表 | 尽量少的 cmdlet |
| `scanner/signature.py` | `WinVerifyTrust`（ctypes） | 无 PowerShell |

### Harness 侧

| 文件 | 作用 |
|---|---|
| `src/engine/client.js` | 一次请求一个进程、`-I` 隔离、超时终止、信封校验、错误码映射 |
| `src/tools/disk.js` | `scan_disk`、`scan_directories`、`find_large_files` |
| `src/tools/scanners.js` | 6 个清单/态势工具 |
| `index.js` | 系统提示段 + `engine_status` + 全部工具注册（预设作用域） |

## 2. 实测证据（本机真实数据）

```
scan_disk                → 3 块固定磁盘：C:\ 87.6% 已用，D:\ 58.4%，E:\ 55.8%
scan_directories         → 目录体积 + 前 10 大子目录 + 预算截断标记
find_large_files         → 大小/修改时间/系统属性，按大小排序
list_installed_software  → 135 条；签名：Photoshop=valid、AMD Software=valid
inspect_startup_entries  → 11 条（Run 8 + RunOnce-32 3）；计划任务 XML 在命令沙箱内不可读（见 §3）
inspect_services         → 152 个运行中的 Win32 服务，含启动类型/路径/账户；签名 147 valid / 5 non-valid
inspect_browser_extensions → Chrome + Edge，3 个配置文件，50 个扩展
inspect_browser_settings   → 主页/启动页/默认搜索/机器策略
inspect_security_status  → 防火墙 domain/private/public 全部启用；
                            build 22631 → lifecycle=windows-11；
                            Defender 查询被沙箱拒绝，降级为 service-state-only
self_check               → 10 个 operation，admin=False
```

测试：`python -m unittest` 25 项通过；`node tests/plugin.test.mjs` 4 项通过；`node tests/engine-client.test.mjs` 7 项通过。

## 3. 已知限制（本轮实测，全部如实上报）

1. **命令沙箱阻止部分 Windows 查询**：`Get-MpComputerStatus`、`Get-ScheduledTask`、`System32\Tasks` 目录读取在沙箱内被拒。引擎把失败写进 `coverage`/`errors`（Defender 降级为 `service-state-only`，计划任务回退到 cmdlet），不伪造结果。运行时由 Host 进程拉起引擎，不受该沙箱限制——**待实时会话确认**。
2. **引擎写库在沙箱内失败**（`LOCALAPPDATA\DiskGuardian` 被拒），结果带 `storage_error`；同样待实时会话确认。
3. **无管理员权限**：`admin=False`。卸载、系统服务/启动项修改将在 Phase D/E 返回 `E_ELEVATION_REQUIRED`，不自动提权。
4. **Windows 10 未验证**：本机 Win11 22631。代码用能力检测（注册表/SCM/服务状态）而非版本字符串，但 10 与 11 的实测差异仍需另一台机器。
5. 浏览器检查只读白名单字段；`History`/`Cookies`/`Login Data`/`Web Data` 在代码里根本不出现（测试可审计文件名集合）。

## 4. 待验证（需要用户执行一次）

重启 DSH 后在新建任务里选择 **DiskGuardian**，依次运行：

1. `engine_status` — 确认 `ok: true`、`admin: false`、`database` 路径；
2. `scan_disk` — 确认数值与本报告一致；
3. `inspect_services` — 确认 `sc.exe` 路径在预设会话内可用。

若 `engine_status` 返回 `E_ENGINE_UNAVAILABLE`，说明 `ctx.subprocess` 未注入该预设作用域，需改 Host 级注入。

## 5. 下一步：Phase D

- 风险分级（L0–L4）与文件分类规则
- `create_cleanup_plan` / `preview_action_plan`（计划 + 哈希 + 目标清单）
- `issue_approval`（绑定 `plan_hash` + manifest 哈希 + TTL + 一次性）
- 隔离区（move + 记录 + 恢复前校验）
- 审计与结果验证
- 权限测试：伪造批准、过期、重放、计划/目标变更、L4 拒绝
