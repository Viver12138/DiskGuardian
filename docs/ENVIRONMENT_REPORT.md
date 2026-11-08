# ENVIRONMENT_REPORT — DiskGuardian Phase A

> 项目：DiskGuardian
> 阶段：A — Environment and API Discovery
> 生成时间：2026-11-08
> 发现方式：只读检查（`cordis_inspect_query` 的 Service / Config provider）+ 本机 shell 探测
> 结论摘要：**架构可行**，有 6 处必须调整的实现约束（见 §5），无阻塞性缺口；两项目标本机无法验证（Windows 10、UAC 提权），已单独标注。

---

## 1. Runtime Facts

| 项目 | 实测值 | 备注 |
|---|---|---|
| DSH 版本 | `0.2.2-rc.1` | 来自 app.asar 内 package.json |
| 运行形态 | Desktop（Electron 44.7.0，打包 asar） | 源码不在本机可读路径；API 以运行时检查为准 |
| Profile | `desktop`（`DSH_PROFILE=desktop`） | `DSH_PROFILE_DIR=C:\Users\Viver\.dsh\profiles\desktop` |
| 当前会话 Preset | `cordis`（创造模式） | 用于开发；**不作为** DiskGuardian 运行模式 |
| 操作系统 | Windows 11 23H2，Build 22631.4169，`CoreCountrySpecific`（家庭中文版） | 注册表 `ProductName` 仍写 “Windows 10”，以 Build ≥ 22000 判定为 Win11 |
| 当前权限 | **非管理员**（`IsInRole(Administrator)=False`） | 影响卸载、系统服务/启动项修改 |
| Node.js | v24.19.0 | ESM、`node --test` 可用 |
| pnpm | 12.14.0 | 仅用于开发目录，**不在 profile 内运行** |
| Python | 3.13.2（`C:\python\python3.13.2\python.exe`） | stdlib `sqlite3` 3.45.3、`winreg` 可用 |
| 第三方 Python 包 | `psutil 7.0.0` 已存在 | 不作为硬依赖（见 §5.6） |
| PowerShell | 7.6.9（`pwsh`）与 5.1（`powershell.exe`）均在 | 引擎内部固定脚本可择一，模型不可指定 |
| Windows 工具 | `sc.exe`、`schtasks.exe` 均在 `System32` | 引擎可用固定参数调用 |

工作区：`C:\Users\Viver\Desktop\dsh_plugin_dev`（空目录，可写，file policy = `workspace-write`）。
会话权限：`workspace-write` + `approval: ask`（每次 `plugin_manager` 调用都会请求批准）。

---

## 2. Verified Harness APIs

以下签名均来自当前进程的运行时检查，不是文档推断。

### 2.1 Tool registration — `ctx.tools`（hard dependency 可用 `inject: ['tools']`）

```ts
register(definition: ToolDefinition, options?: ToolRegistrationOptions): () => void

interface ToolDefinition extends ToolSchema {
  name: string; description: string; parameters: Record<string, unknown>;
  output: { schema: JsonSchemaNode; render(args, value): ContentBlock[];
            presentationMeta?(args, value): JsonValue };
  execute(args: unknown, exec: ToolRunContext): Promise<unknown>;
  timeoutMs?: number;
  isConcurrencySafe?(args): boolean;
  presentCall?(args): ToolCallView | undefined;
  presentResult?(args, result: ToolResult): ToolResultView | undefined;
}
interface ToolRegistrationOptions { when?(context: ToolActivationContext): boolean | Promise<boolean> }
```

要点：
- 注册返回精确的 disposer，必须在 `apply` 内用 `ctx.effect` 收集。
- 名字冲突、保留名 `run_code` 会失败；scoped 注册会遮蔽 global。
- **没有 `output.render` 的工具无法把结构化结果交给模型** —— DiskGuardian 的每个工具都必须提供 `output.schema` + `render`，返回 JSON 文本块（`ContentBlock[]`）。
- `timeoutMs` 是工具级超时；与引擎内部超时是两层，必须都设。

### 2.2 Subprocess — `ctx.subprocess`（provider：`@deepseek-ai/dsh-subprocess-local`，默认组合已挂载）

```ts
spawn(spec: SubprocessSpawnSpec): SubprocessHandle     // 同步返回，无默认值
resolveExecutable(command, env?, signal?): Promise<string>

interface SubprocessSpawnSpec {
  argv: readonly string[]; cwd: string;
  stdio: { stdin: 'ignore'|'pipe'|{data:string};
           stdout: 'pipe'|'inherit'|{maxBytes:number; spill?:{maxBytes:number}};
           stderr: /* 同上 */; control?: 'pipe' };
  graceMs: number; signal?: AbortSignal; env?: NodeJS.ProcessEnv;
}
interface SubprocessHandle {
  readonly stdin: Writable|undefined; readonly stdout: Readable|undefined;
  readonly stderr: Readable|undefined; readonly control: Duplex|undefined;
  readonly collected: { stdout?: SubprocessOutputReader; stderr?: SubprocessOutputReader };
  readonly done: Promise<{ exitCode: number|null; signal: NodeJS.Signals|null }>;
  terminate(): void; waitForExit(signal?: AbortSignal): Promise<boolean>;
}
interface SubprocessOutputReader {
  readFrom(fromByte: number): { text: string; nextOffset: number; lossy: boolean; spillPath?: string };
}
```

要点：
- `stdio.stdout: 'pipe'` 直接拿到 `Readable`，适合 JSONL 行协议；`collected` 是**按字节偏移、非消费式**读取，多读者互不吞数据，适合日志。
- `spawn` 会同步抛错：argv/cwd/env/grace 非法、或 signal 已 abort。
- `graceMs` 是终止宽限期，必须显式给值。
- **未在本次会话中实测 spawn 行为**（只读检查无法执行代码）；Phase B 的最小工具负责验证 `ctx.get('subprocess')` 是否可用、JSONL 往返是否正常。

### 2.3 Approval — `ctx.approval`

```ts
request(req: { agent, toolName, callId?, reason?, displayReason?, signal? }): Promise<ApprovalOutcome>
type ApprovalOutcome = 'allowed-once' | 'rejected' | 'cancelled' | 'unavailable'
setPolicy(agent, policy: 'ask'|'never'): void
```

要点：
- `'allowed-once'` 是唯一授权值；`'unavailable'` 必须按**拒绝**处理（fail closed）。
- 只要求存在打开的 turn，且每次 ask/outcome 成对写入会话日志。
- 这是 **Harness 工具执行权限**，与 DiskGuardian 的**业务授权**是两套机制（规格 §4.3 已明确），不能互相替代。

### 2.4 用户确认 — `ctx.userQuestions`

```ts
ask(request): Promise<AskUserQuestionAnswer>
askTimed(request & {agent}, callId, timeoutMs): Promise<TimedUserQuestionResult>
```

要点：这是“真实用户交互”的可用来源（`ask_user_question` 工具同一服务）。DiskGuardian 的批准流程以它为**唯一**的用户确认来源，引擎侧只认它产生的 ApprovalRecord。

### 2.5 Plugin Manager — `ctx.pluginManager` / `plugin_manager` 工具

```ts
installBundle(spec: string, options?): Promise<ChangeResult>
removeBundle(name): Promise<ChangeResult>
setPluginEnabled(id, enabled) / setBundleEnabled(name, enabled): Promise<ChangeResult>
listPlugins() / listBundles() / readBundleDetail(name, language, options?)
inspect(spec, options?, signal?) / updateBundle(name, version, options?)
```

要点：安装/托管由它完成，**不得手写 profile 的 `package.json` / `cordis.patch.yml`，不得在 profile 目录跑 pnpm**。`ChangeResult.application`（`applied` / `restart-required` / `failed` / `overridden`）才是“是否生效”的判据。

### 2.6 Agent Preset — `@deepseek-ai/dsh-agent-preset` 声明行

运行时 Config schema（`include:preset-cordis` 的投影）：

```
{ id: string(必填), plugins: array(必填), name?: string|null, description?: string|null, order?: number|null }
```

现状：内置 `standard` / `ptc` / `minimal` / `cordis` 均为 **bundle patch 中的 insert 行**（`id: preset-<name>`），用户自建 preset 同样是 insert 行，安装后出现在设置页与新建任务选择器。`preset id` 与行 id 分离：`config.id` 是会话保存的标识符，行 `id` 是 Loader 编辑地址。

**规划**：DiskGuardian 用 `id: diskguardian`，`name: DiskGuardian`，`order` 取 20，不覆盖任何内置行。

### 2.7 Storage — 无可直接使用的 SQLite 服务

`ctx.storage` 是 hub：`mount(form, facility)` / `form(form)`，`storageDomain.open(spec)` 打开领域表。当前 profile **没有**暴露 SQLite 存储表单（`StorageForms` 未包含 sqlite 后端），若走 Harness 存储需要自建 backend，收益低。

`ctx.fs` 提供文件读写/编辑/删除/移动 + `watch`，全部经过沙箱策略（`sandboxPolicy`），是“模型侧文件操作”的通道，不是数据库。

---

## 3. Sandbox and Permission Boundary

- 本会话：`workspace-write`，可写根 = 会话工作区；`sandboxPolicy.workspaceRoot` 由启动时 `process.cwd()` 决定。
- 插件内 `ctx.fs` 的写操作受 sandbox policy 约束；**`ctx.subprocess.spawn` 启动的引擎进程不受该文件沙箱约束**（provider 层不做路径裁决）。
- 因此 DiskGuardian 的“引擎能碰哪些路径”**只能由引擎自己裁决**（路径允许清单 + 重解析点/符号链接检查 + 目标再验证）。这一点必须在安装前向用户明示：安装 DiskGuardian 等于授予一个“以当前用户身份访问全盘”的本地进程。

---

## 4. Capability Gaps (relative to the spec)

| # | 规格依赖 | 实测情况 | 处理 |
|---|---|---|---|
| G1 | Harness SQLite 存储 | 无 SQLite storage form | Python 引擎自带 `sqlite3`，DB 放 `%LOCALAPPDATA%\DiskGuardian\diskguardian.db` |
| G2 | 提权执行 | 当前非管理员；无内建提权 API | 引擎返回 `ELEVATION_REQUIRED`，由用户自行以管理员身份重启；**不自动 UAC** |
| G3 | Windows 10 兼容验证 | 本机 Win11 23H2 | 代码用能力检测而非版本号；Win10 列为“未验证”，需另一台/VM |
| G4 | 任意 shell | 无该能力，且规格禁止 | 21 个工具全部是固定 operation + 结构化参数；引擎内部只用固定 PowerShell/CIM 片段 |
| G5 | 浏览器 Cookie/密码 | 规格禁止读取 | 只读扩展 manifest/Local State/Preferences 的白名单字段 |
| G6 | 会话级长期进程 | `spawn` 生命周期属于 provider，服务 dispose 会终止子进程 | 引擎按“每次调用短生命周期进程”运行；可用 `control` 管道预留常驻模式，但 V1 不启用 |

---

## 5. Architecture Adjustments (decisions)

1. **引擎拥有 SQLite**（替代 §3.2-D 的 Harness 存储）：连接只在引擎内，事务、一次性授权消费、重复执行保护都在同一事务域里完成，模型侧看不到 DB 句柄。
2. **TS 插件是薄适配层**：21 个工具 = 21 个固定 `operation`，只做参数形状校验、超时、请求 ID、结果投影；不做任何权限判断，也不做 `approved` 透传。
3. **两阶段授权落地方式**：
   - 用户确认：插件调用 `ctx.userQuestions.ask()`（与 `ask_user_question` 同一服务），问题里给出 plan 摘要 + 目标清单哈希。
   - 授权记录：确认后插件调用引擎 `issue_approval(plan_id, plan_hash, manifest_hash)`，引擎写入 `approval_records`（TTL、一次性、绑定哈希），**不把授权值返回给模型**；执行工具只传 `approval_id`。
   - 引擎在执行时重算 plan_hash/manifest_hash、比对目标元数据、检查 TTL 与 `used`，任一不符即 `APPROVAL_INVALID`。模型伪造 `approved=true` 无任何代码路径可达。
4. **工具级与业务级权限分离**：Harness 侧的 approval/sandbox 只保证“这个调用被允许执行”，业务侧仍由引擎独立裁决 L0–L4。
5. **非管理员优先**：只读扫描（L0）覆盖磁盘、软件清单、启动项、服务、浏览器、安全状态；需要提权的卸载/系统服务修改一律 `ELEVATION_REQUIRED`，V1 不自动提权。
6. **Python 依赖策略**：以 stdlib 为准（`sqlite3`、`winreg`、`ctypes`、`subprocess`、`json`、`hashlib`）；`psutil`、PowerShell CIM 作为**可选加速**，缺失时降级并如实标注 `coverage: partial`。不引入需要编译的第三方包。
7. **Windows 版本判定用能力检测**：`Get-MpComputerStatus` 是否存在、注册表键是否可读、`sc.exe` 是否可用，而不是字符串比较；Win10 与 Win11 走同一路径。

---

## 6. Feasibility Verdict

| 模块 | 可行性 | 依据 |
|---|---|---|
| 21 个工具注册 | ✅ | `tools.register` + `output.render` 契约完整 |
| Python 引擎 + JSONL | ✅ | `subprocess.spawn` 提供 stdin/stdout 管道、`done`、`terminate`、`graceMs` |
| 独立权限与审计 | ✅ | 引擎内 SQLite + 哈希绑定；授权来自 `userQuestions` |
| 隔离与恢复 | ✅ | 引擎内 move + 记录表，无需 Harness 参与 |
| 浏览器检查（Chrome/Edge） | ✅ | 读 `Local State` / `Preferences` / manifest，白名单字段 |
| 软件卸载 | ⚠️ | 非管理员下多数卸载程序会自行提权；引擎需检测并如实报告 |
| Defender 状态 | ✅ | 固定 PowerShell `Get-MpComputerStatus` 或 `Get-CimInstance` |
| Windows 10 验证 | ❌ 本机不可行 | 需外部环境 |
| 提权操作 | ⚠️ 默认拒绝 | 与规格 §4.1 L4 / §10 一致 |

**给规格的两条修正建议**（不改变产品定位）：
- §3.2-D 的 “Local Storage 使用 SQLite” 明确为“由 Python 引擎持有”，TS 侧不引入数据库依赖。
- §4.3 的 “Harness 提供的真实交互机制” 明确落地为 `ctx.userQuestions.ask()`；`ctx.approval` 只用于工具执行许可，不产生业务授权。

---

## 7. Phase Plan and Gates

| Phase | 交付 | Gate（不通过不进入下一阶段） |
|---|---|---|
| A | 本报告 | 架构确认（当前） |
| B | bundle 骨架 + `diskguardian` preset + `dg_ping` 最小工具 | bundle 被识别、工具可调用、错误可返回、preset 不覆盖内置 |
| C | 引擎只读能力（磁盘/软件/启动项/浏览器/安全） | 8 个 scanner 工具全部返回真实本机数据 |
| D | 计划/预览/授权/隔离/审计 | 伪造批准、过期、重放、计划变更、目标变更、L4 全部被拒 |
| E | 执行类工具接入 + 6 条工作流 | 自然语言端到端可用 |
| F | 全量测试 + 安装 | 源码审查、测试通过、用户明确批准后才 `install_bundle` |

---

## 8. Open Items（需在 B/C 阶段实测确认）

1. `ctx.subprocess` 在 preset 子插件上下文里是否可直接 `inject`（计划用 `dg_ping` 验证）。
2. `spawn` 在 `workspace-write` 会话下的实际路径可见范围（是否被 provider 额外限制）。
3. 大输出场景：`collected` 的 `spillPath` 行为与 `maxBytes` 上限，用于给引擎响应设上限。
4. `plugin_manager` 安装本地目录 bundle 时是否有 pending build script（本 bundle 不写 install 脚本，预期没有）。
5. Home 版策略键（`CoreCountrySpecific`）下 Defender/浏览器策略键的可读性。
