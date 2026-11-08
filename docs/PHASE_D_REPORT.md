# Phase D — 权限、计划、授权、隔离与审计

> 状态：**代码完成**，引擎级端到端闭环已实测（见 §3）；Harness 会话内的确认 UI 待重启后验证
> 日期：2026-11-08
> 版本：`0.4.0`

## 1. 权限模型落地

| 层 | 机制 | 位置 |
|---|---|---|
| L0 只读 | 9 个扫描器 + `classify_files`，无写入路径 | `engine/diskguardian/scanner/*` |
| L1 可清理 | 严格规则全部满足才 eligible：允许根内、非目录、非重解析点、路径链无重解析、单硬链接、非个人目录、mtime 超过 24h | `permissions/rules.py` |
| L2 中风险 | 回收站内容识别为 L2，**本版不进入计划**，提示用户用 Windows 自行清空 | `rules.classify` |
| L3 高风险 | 软件卸载/扩展移除/系统启动项：Phase E 实现，逐项确认 | — |
| L4 禁止 | 个人文档、Windows/Program Files、未知路径、网络路径、重解析点：不可加入计划，明确拒绝 | `rules.classify` |

关键点：**模型不提供风险等级**。执行请求只带 `plan_id`，引擎从文件系统重新推导分类、资格与哈希。

## 2. 授权链路

```
create_cleanup_plan  →  plan_hash + 每项 target_hash（不含副作用）
execute_cleanup_plan →  工具内部 ctx.userQuestions.ask(approval 意图)
                     →  用户点「确认执行」
                     →  issue_approval(plan_id, source=harness-user-question)
                     →  引擎写 approval_record（plan_hash + manifest_hash + TTL 15min + used=0）
                     →  execute_cleanup_plan(plan_id, approval_id)
                     →  校验 → 消费 → 逐项隔离 → 验证 → 审计
```

拒绝路径（全部有单测）：

| 场景 | 结果 |
|---|---|
| 伪造 `approval_id` | `E_APPROVAL_NOT_FOUND`，文件不动 |
| 重复使用同一批准 | `E_APPROVAL_USED` |
| 批准过期 | `E_APPROVAL_EXPIRED` |
| 计划条目被改动 | `E_APPROVAL_STALE` |
| 文件在批准后被修改 | `E_TARGET_CHANGED`（整批拒绝，不只是该项） |
| L4 路径进入计划 | `E_PLAN_EMPTY` + 每条排除原因 |

`issue_approval` **没有对应的模型工具**：只有工具内部在用户确认后才调用它。

## 3. 端到端实测（真实引擎进程 + 真实文件）

```
classify_files      → temporary-file / L1 / eligible
create_cleanup_plan → plan_b7dce… items=1
issue_approval      → approval_e8dea…
execute_cleanup_plan→ success=true verified=true，源文件已消失
再次 execute        → E_APPROVAL_USED
list_quarantine     → 1 条，status=quarantined
restore             → verified=true，文件回到原位
get_audit_log       → approval.issue, cleanup.quarantine, cleanup.execute, quarantine.restore
```

测试：Python **35 项通过**（新增 10 项权限/授权/隔离/审计测试），Node 插件契约 4 项、客户端 7 项通过。

## 4. 设计取舍

1. **隔离优先于删除**：本版没有永久删除路径。移动后记录 SHA-256、大小、计划 ID，恢复时再次校验。
2. **一次性授权 + 整批失效**：任何一个目标漂移，整份批准作废，避免「部分旧、部分新」的混合状态。
3. **先消费再执行**：批准在执行开始时原子消费，宁可浪费一次授权，也不给重放窗口。
4. **回收站不纳入计划**：`$Recycle.Bin` 的语义与其他目录不同（按 SID、系统行为），V1 只识别与提示，不代为清空。
5. **L1 仍需确认**：规格允许 L1 自动执行，但本版选择「所有清理都要一次明确确认」。更严格，方向与规格一致；将来可在严格规则下放开自动 L1。
6. **目录不清理**：只有文件进入计划，目录只做统计。避免误删目录树。

## 5. 已知限制

- 确认 UI 的真实渲染（approval intent 卡片）只在 Harness 客户端可用；引擎侧已用单元测试覆盖确认结果的两条分支，但**尚未在真实会话点过一次**。
- 被其他进程以独占方式打开的文件会在 `E_TARGET_LOCKED` 失败并保留原样；测试环境难以稳定构造独占锁，该项为代码路径覆盖而非实测。
- Windows 10 与提权场景仍未验证。

## 6. 下一步：Phase E

- 5 个 analyzer：`analyze_software`、`analyze_startup`、`analyze_browser`、`analyze_security_status`（含证据/置信度/建议）
- 软件卸载计划与执行（官方卸载程序，逐项确认）
- `manage_startup_entry`、`manage_browser_extension`（默认只读 + 确认后执行）
- 6 条自然语言工作流与 21 工具对齐
