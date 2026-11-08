# Phase E（第一部分）— 分析器

> 状态：4 个 analyzer 完成并实测；剩余 4 个执行类工具与 6 条工作流在下一轮
> 日期：2026-11-08
> 版本：`0.5.0`

## 1. 分析模型

所有 analyzer 共享同一套输出结构，符合规格 §5.2 的要求：

```json
{
  "target": "…", "category": "software | startup | browser-extension | browser-setting | security",
  "risk_level": "trusted | unknown | suspicious（安全态势用 high/medium/low/unknown）",
  "confidence": 0.0,
  "evidence": ["可复核的观察"],
  "reasons": ["为什么这值得注意"],
  "recommended_action": "no-action | review | verify-publisher | investigate",
  "details": {}
}
```

每个结果的顶层还带 `summary`（按风险分组的计数 + 可疑项摘要）和 `note`（本版能力边界说明）。

### 关于"不能只凭单一弱证据判定恶意"

规格 §2.1-C 要求区分广告软件、可疑软件、已知恶意软件。本版**没有威胁情报源**，因此：

- 输出上限是 `suspicious`，永远不会出现 `confirmed-threat`；
- `suspicious` 的语义是"值得核实"，`recommended_action` 会给出核实方向；
- 每个结论都附带证据列表与置信度，模型必须原样转述，不得自行升级措辞。

## 2. 四个分析器

| 分析器 | 证据信号 | 实测（本机） |
|---|---|---|
| `analyze_software` | 签名结果、发布者、安装位置（用户可写目录）、卸载信息、版本 | 40 条：19 trusted / 12 unknown / 9 suspicious |
| `analyze_startup` | 可执行文件缺失、未签名、用户可写路径、解释器启动（含 `-enc` 等隐藏参数）、已禁用 | 11 条：8 trusted / 1 unknown / 2 suspicious |
| `analyze_browser` | 非商店安装、`<all_urls>`、高影响权限（proxy/management/nativeMessaging/debugger…）、未知默认搜索引擎（有企业策略时标注而非判定劫持） | 50 个扩展：4 trusted / 39 unknown / 7 suspicious |
| `analyze_security_status` | Defender 实时保护、杀毒、篡改保护、病毒库时效、防火墙三档、安全服务状态、Windows 生命周期 | Defender 查询被沙箱拒绝 → 1 条 `unknown`（如实降级） |

## 3. 测试

- Python **49 项通过**（新增 14 项 analyzer 测试，覆盖：签名良好→trusted、未签名+用户目录→suspicious、解释器+编码参数→suspicious、商店扩展→trusted、侧载+全站权限→suspicious、未知搜索引擎→unknown、关闭保护→high、Defender 不可用→unknown 而非 high）。
- 插件契约测试：工具数 21，全部带 `output.render`、参数 schema 拒绝未知字段。

## 4. 设计取舍

1. **分析器不碰磁盘**：输入是扫描器输出，因此可以用固定数据集做确定性测试，也避免"分析阶段偷偷写入"。
2. **安全态势用另一套等级**（high/medium/low/unknown），因为"系统防护关闭"与"某软件可疑"不是同一种风险，混用会误导。
3. **企业策略单独报告**：浏览器有机器策略时，未知搜索引擎只记为 unknown，并提示先与组织确认。
4. **Defender 不可用不视为高风险**：本机沙箱拒绝 `Get-MpComputerStatus`，输出 `unknown` + 原因，而不是编造"已关闭"。

## 5. 卸载（Phase E 第二部分）

新增 `create_removal_plan` 与 `execute_removal_plan`，复用同一套计划/批准机制：

| 检查 | 规则 |
|---|---|
| 卸载命令来源 | 只取注册表 `UninstallString` / `QuietUninstallString`，不接受模型提供的命令行 |
| 可执行文件 | 必须是本地存在的 `.exe`，且不在 `Temp` / `Downloads` / `Public` |
| 解释器 | 拒绝 `cmd`/`powershell`/`wscript`/`mshta`/`rundll32`/`regsvr32` 等 |
| MSI | `msiexec.exe` 必须带 `/X` 或 `/uninstall` |
| 提权 | 不做任何提权；`WinError 740` 映射为 `E_ELEVATION_REQUIRED` |
| 授权 | 一次性 approval，绑定计划哈希与软件清单哈希 |
| 验证 | 卸载后重新读注册表：条目消失才算 verified |

实测（测试替身，非真实卸载）：成功路径、卸载器无效果→`E_VERIFY_FAILED`、需要提权→`E_ELEVATION_REQUIRED`、重复执行→`E_APPROVAL_USED`、无批准→`E_APPROVAL_NOT_FOUND` 全部通过。

**真实卸载未在本机执行**：不能拿用户的软件做实验。需要你指定一个可弃用软件后再单独验证。

## 6. 实施进度（截至 0.7.0）

已完成：
`manage_startup_entry` + `list_startup_changes`（注册表 Run 值可逆禁用/恢复，原值入库，逐项确认）；
`inspect_removal_residue`（卸载后只读残留检查：是否仍注册、按目录统计残留体积；不删除）。

仍未实现（明确记录）：
- `manage_browser_extension`：V1 **不做**。改写浏览器 `Preferences` 需要关闭浏览器、失败会损坏用户配置，
  且等于绕过浏览器自身的扩展管理。引导用户自行移除更安全。
- 回收站清理：识别（L2）但不代清。
- 残留**清理**：只做检查。残留通常位于 Program Files/ProgramData（L4），本引擎不删除这些位置；
  如需处理，应作为独立计划并人工确认。

## 7. 与规格 21 工具的对照

| 规格类别 | 规格数 | 已实现 | 差异 |
|---|---|---|---|
| Scanner | 8 | 9 | 多一个 `inspect_security_status`（采集层与判断层分开） |
| Analyzer | 5 | 5 | 一致 |
| Planner | 3 | 3 | 一致 |
| Executor | 5 | 4 | 缺 `manage_browser_extension`（刻意不做） |
| **合计** | **21** | **21** | 覆盖 20/21，另有 7 个附加工具（`engine_status`、`list_quarantine`、`get_audit_log`、`list_startup_changes`、`inspect_removal_residue`、`list_cleanup_candidates`、`purge_quarantine`），共 28 个 |


