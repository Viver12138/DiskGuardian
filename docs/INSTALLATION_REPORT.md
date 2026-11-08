# DiskGuardian — Installation Report

> 版本 0.7.0 · 2026-11-08 · 目标 profile：`desktop`

## 1. 当前安装状态

| 项 | 值 |
|---|---|
| Bundle | `@local/dsh-diskguardian` 0.7.0 |
| 安装方式 | 工作区目录链接（junction） |
| 包路径 | `C:\Users\Viver\Desktop\dsh_plugin_dev` |
| Profile 依赖 | `"@local/dsh-diskguardian": "link:C:/Users/Viver/Desktop/dsh_plugin_dev"` |
| Profile bundles | `@local/dsh-diskguardian` 已加入 |
| 安装结果 | `application: applied`，无 warning，无 build script |
| Preset 行 | `preset-diskguardian`（运行时可见，`status: schema`） |
| 工具可见性 | 仅 `diskguardian` 预设会话；不污染标准/创造模式 |

原始安装命令（记录）：

```
plugin_manager install_bundle target=C:\Users\Viver\Desktop\dsh_plugin_dev
```

## 2. 这个安装改变了什么

- profile 的 `package.json` 增加一条 link 依赖，并把 bundle 加入 `dsh.profile.bundles`；
- `node_modules/@local/dsh-diskguardian` 是指向工作区的 junction（改文件即生效，无需重装）；
- 新增预设 `diskguardian`，会出现在「设置 → Agent 预设」与新建任务选择器；
- **没有**修改 `cordis.patch.yml`、没有在 profile 内运行 pnpm、没有全局注册工具。

## 3. 验证步骤

1. 退出并重启 DSH（Host 进程需要加载新的插件代码代际）。
2. 新建任务 → 选择 **DiskGuardian** → 运行 `engine_status`。
   预期：`ok: true`、`admin: false`、`database` 指向 `%LOCALAPPDATA%\DiskGuardian\diskguardian.db`。
3. 运行 `scan_disk` 与 `inspect_services`，确认返回真实数据。
4. 运行 `create_cleanup_plan` + `execute_cleanup_plan`，确认弹出确认卡片、点确认后返回隔离结果。

引擎层可以先跑一次无需会话的端到端验收：`python tools/acceptance.py`（26 个场景，见 `ACCEPTANCE.md`）。

## 4. 卸载

```
plugin_manager remove_bundle target=@local/dsh-diskguardian
```

卸载后：bundle 行移除、预设消失、工具不可见。
本地数据（数据库、隔离区）不会被删除；如需清理：

```
%LOCALAPPDATA%\DiskGuardian\diskguardian.db
%LOCALAPPDATA%\DiskGuardian\quarantine\
```

删除前请先确认隔离区里没有需要恢复的文件。

## 5. 验收清单（对照规格 §16）

| 项 | 状态 | 证据 |
|---|---|---|
| Harness 识别 Bundle | ✅ | `application: applied` |
| Plugin 加载 | ✅ | 预设行存在；工具契约测试通过 |
| `diskguardian` Preset 可启动 | ✅ 实测 | 0.8.2：会话内 `engine_status` 返回 `ok: true` |
| 自然语言维护请求 | ✅ 实测 | 同上，一次真实工具调用完成 |
| 引擎传输（JSONL over `ctx.subprocess`） | ✅ 实测 | `engine_status` 返回完整诊断，无超时/截断 |
| 28 个结构化工具 | ✅ | 含 7 个附加工具（状态/隔离/审计/启动项变更/残留检查/清理候选/隔离区清理） |
| Python Engine 稳定 | ✅ | 28 个 operation，82 项测试 + 27 个端到端场景 |
| Win10/Win11 兼容验证 | ⚠️ 仅 Win11 | 见 COMPATIBILITY.md |
| 磁盘/垃圾/软件/启动项/浏览器/安全 检查 | ✅ | 真机实测 |
| 软件风险分析 | ✅ | 4 个分析器 |
| 操作计划与预览 | ✅ | 计划/预览/过期 |
| L0–L4 权限控制 | ✅ | 分类测试 + 拒绝路径测试 |
| 用户授权机制 | ✅ 实测 | 确认卡片 → 一次性批准 → 隔离 → 审计，两批共 128 项 |
| 隔离与恢复 | ✅ | 端到端实测 |
| 隔离区清空（purge） | ✅ 实测 | 64 项 / 398,487,092 B，SHA-256 校验后删除，0 失败 |
| 磁盘空间实际释放 | ✅ 实测 | C: 可用空间净增 3,873,837,056 B（约 3.61 GiB） |
| 操作审计 | ✅ | `action_logs` 实测 |
| 执行结果验证 | ✅ | 尺寸/哈希/注册表复核 |
| 安全测试全部通过 | ✅ | TEST_REPORT.md |
| 最终安装经用户明确批准 | ✅ | 用户在 Phase B 明确批准安装 |

## 6. 安装后可回滚性

- Bundle 移除即恢复原状；不写系统级配置。
- 唯一的系统级副作用来自用户自己确认的操作（清理/卸载/启动项），每一条都有审计记录与恢复途径（卸载除外）。
