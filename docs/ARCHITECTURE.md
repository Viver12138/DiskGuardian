# DiskGuardian — Architecture

> 版本 0.7.0 · 2026-11-08

## 1. 分层

```
用户
  ↕  自然语言
Harness 会话（diskguardian preset）
  ↕  结构化工具调用
Host 插件（index.js + src/tools/*.js）      ← 只做契约、参数形状、结果投影、确认 UI
  ↕  JSONL over stdio（一行一请求，一进程一调用）
Python 执行引擎（engine/diskguardian）      ← 权限、分类、计划、授权、隔离、验证、审计
  ↕
SQLite（%LOCALAPPDATA%\DiskGuardian\diskguardian.db）+ Windows API / 注册表 / 文件系统
```

**边界原则**：上层永远不决定"能不能做"。插件没有权限判断代码；模型没有授权入口；引擎不接受模型给的风险等级与批准标志。

## 2. 目录

| 路径 | 职责 |
|---|---|
| `index.js` | 预设系统提示段、`engine_status`、注册所有工具 |
| `src/tools/*.js` | 21+ 个工具定义（参数 schema、`output.render`、超时、确认流程） |
| `src/engine/client.js` | 子进程传输：解析 Python、单次 spawn、超时终止、信封校验、错误码映射 |
| `engine/run.py` | 启动器（`python -I run.py`） |
| `engine/diskguardian/protocol.py` | 请求/响应信封、大小上限、参数边界 |
| `engine/diskguardian/main.py` | operation 分发表 |
| `engine/diskguardian/permissions/` | 路径校验、L0–L4 分类规则 |
| `engine/diskguardian/scanner/` | 9 个只读采集器 |
| `engine/diskguardian/analyzers/` | 4 个证据型分析器 |
| `engine/diskguardian/actions/` | 计划、授权、清理/隔离、卸载、启动项变更 |
| `engine/diskguardian/storage/` | SQLite schema（10 张表 + 变更记录）、迁移、审计写入 |

## 3. 数据流（一次清理）

1. `scan_directories` / `find_large_files` → 候选路径。
2. `classify_files` → 类别、L 级、eligibility、逐条原因。
3. `create_cleanup_plan` → 计划落库（items + `target_hash` + `plan_hash`）。
4. `preview_action_plan` → 目标、过期时间、可逆说明。
5. `execute_cleanup_plan`（工具内）→ 用户确认 → `issue_approval` → `execute_cleanup_plan`（引擎）。
6. 引擎：重算目标身份 → 比对 manifest → 消费批准 → 逐项分类复核/锁定检查/哈希/移动 → 验证 → 审计。

## 4. 关键决策

| 决策 | 理由 |
|---|---|
| SQLite 由引擎持有 | 授权消费与执行可落在同一事务域；模型侧拿不到数据库句柄 |
| 一次调用一个 Python 进程 | 无跨调用状态、无泄漏；启动成本 ~60–100 ms 可接受 |
| 扫描不依赖 WMI | WMI/DCOM 在沙箱与加固主机常被拒绝；注册表 + SCM + 官方 XML 更可靠 |
| 签名用 WinVerifyTrust | 避免逐文件 PowerShell；结果只有可信/不可信标签 |
| 隔离优先于删除 | 可恢复、可审计；回收站不代清 |
| 分析器不碰磁盘 | 输入是扫描结果，可做确定性测试 |
| 浏览器扩展不做变更 | 改写 `Preferences` 风险高、可能损坏用户配置 |

## 5. 失败与降级

- 扫描预算（条目/时间）触发 → `truncated` + 原因，结果照常返回。
- SQLite 写入失败 → 结果带 `storage_error`，采集数据仍返回。
- PowerShell/CIM 不可用 → `coverage` 标注 + `errors`，分析器输出 `unknown`。
- 子进程崩溃/超时 → 客户端 `E_ENGINE_*` / `E_TIMEOUT`，不重试有副作用的操作。
- 部分项失败 → `status: partial` + `failed_items`，不虚报成功。

## 6. 扩展点

- 新扫描器：加 `scanner/<name>.py` + `main.OPERATIONS` + 工具定义 + 测试。
- 新分析器：输入扫描结果，输出统一 finding。
- 新动作类型：复用 `planner` + `approval`，在 `actions/` 内实现执行与验证。
