# DiskGuardian — Test Report

> 版本 0.7.0 · 2026-11-08
> 运行方式：`python -m unittest discover -s engine/tests -t engine`、`node tests/plugin.test.mjs`、`node tests/engine-client.test.mjs`
>
> P0 实机结果（0.9.1，2026-11-09）见 [P0_REAL_MACHINE_REPORT.md](P0_REAL_MACHINE_REPORT.md)。
> 本文的"未验证"清单写于 0.7.0，其中真实卸载、启动项写回、锁文件、恢复冲突等已被 P0 覆盖；
> 仍待验证的是第三方卸载器、MSI `/I`、确认卡片 UI、HKLM 启动项与重启行为。

## 1. 结果

| 套件 | 数量 | 结果 |
|---|---|---|
| Python：协议 / 存储 / 扫描 / 权限 / 动作 / 分析 / 卸载 / 启动项 / 残留 / 源码卫生 | 96 | 全部通过 |
| Node：插件契约（工具、schema、render、无进程调用、JSON Schema 子集） | 6 | 通过 |
| Node：工具确认链路（确认/拒绝/异常/计划类型/过期/无批准入口） | 8 | 通过 |
| Node：引擎客户端（超时、错误映射、大小上限） | 7 | 通过 |

## 2. 覆盖范围

| 领域 | 测试要点 |
|---|---|
| 协议 | 非法 JSON、缺 request_id、超大请求、响应超限替换、单行输出、参数边界 |
| 存储 | 建表、迁移幂等、扫描记录、审计写入 |
| 文件系统 | 目录汇总、预算截断、大文件排序、相对路径/UNC 拒绝 |
| 权限 | L4 个人文档、未知路径、新鲜临时文件、重解析点判定 |
| 清理动作 | 计划→批准→隔离→验证→恢复；伪造批准、重复使用、过期、计划变更、目标变更；隔离区容量上限（拒绝时不消费批准、可重试）、保留期与用量输出 |
| 分析器 | 签名/发布者/安装位置/解释器/扩展权限/搜索提供者/防护状态；`unknown` 与 `high` 的区分 |
| 卸载 | 解释器/临时目录/无 `/X` 的 MSI 被拒；成功、未生效、需提权、重放 |
| 启动项 | 禁用后原值入库、恢复精确写回、值漂移拒绝、无记录不能恢复、必须批准 |
| 残留检查 | 仍注册判定、按目录统计残留体积、缺失路径不抛错、空名称拒绝 |
| 清理候选 | 只列超过安全期的文件、递归子目录、按大小取前 N、拒绝越界根、拒绝相对路径 |
| 清空隔离区 | dry-run 不删除、删除后记录置为 purged、恢复被拒、哈希不符拒删、按天数过滤、必须给过滤条件 |
| 源码卫生 | 无 `shell=True`、无 `os.system`、无 `eval/exec`、无网络库；`browser.py` 不含敏感文件名；`cleaner.py` 只 `shutil.move` 不 `os.remove`；插件 JS 不直接 spawn 进程 |
| 工具确认链路 | 确认后才签发批准并执行；拒绝时只调用 preview；确认服务抛错按"未确认"处理；计划类型不符/已过期拒绝；执行类工具的 schema 无 `approval_id`/`approved` 字段 |
| Host schema 子集 | 每个工具的参数与输出 schema 只允许 type/oneOf/properties/required/additionalProperties/items/enum/const 与 description/title/default/examples；`type` 必须是单个字符串；object 专属关键字只在 object 上；oneOf 不得带兄弟关键字 |

> 这一行来自一次真实的激活失败：预设卡片报 `unsupported JSON schema: ...type must be a single type string`。
> 根因是 `engine_status` 的输出 schema 用了 `type: ['object','null']`，而 Host 的 schema 子集不接受类型数组；
> 同类问题也存在于 `minItems`/`maximum` 等关键字。修复后新增本测试，按 Host 校验器的规则逐条断言。
>
> 另一次真实故障是 `E_ENGINE_PROTOCOL: the engine returned no JSON response (exit 0)`：
> 客户端用 **collect 模式**启动引擎（`stdout: { maxBytes }`），而 provider 在 collect 模式下
> 不暴露 `handle.stdout`，只提供 `handle.collected.stdout` 读取器；客户端当时只监听流、从未读取 collector，
> 于是引擎明明输出了 JSON 却被丢弃。修复：同时读取流与 collector；stdin 改为 `{ data }` 一次性写入，
> 不再依赖写入与进程启动的时序。`tests/engine-client.test.mjs` 增加了 collect 模式与"零输出"两条回归测试。

## 3. 使用替身（未触碰真实系统）的部分

1. **卸载执行**：`runner` 与注册表 `lookup` 注入替身。真实卸载未执行——不能拿用户软件做实验。
2. **启动项写操作**：`FakeRegistry` 注入。命令沙箱禁止写 HKCU，真实注册表写入未在本环境执行。
3. **确认 UI**：`askForConfirmation` 的确认/拒绝分支由代码路径覆盖；真实渲染待 Harness 会话验证。

## 4. 真机执行过的部分

- 磁盘扫描（3 块固定盘，真实容量）
- 软件清单（135 条）+ 签名（WinVerifyTrust 实测）
- 启动项（11 条注册表项）
- 服务（152 个运行中，SCM 状态 + 注册表启动类型）
- 浏览器（Chrome/Edge 3 个配置文件、50 个扩展）
- 安全态势（防火墙注册表、build 22631、生命周期）
- 清理闭环（真实文件：分类→计划→批准→隔离→重放拒绝→恢复→审计）
- 真实注册表计划（不执行）：`create_removal_plan` 解析出 Adobe Photoshop 的真实卸载器与参数；
  `create_startup_plan` 定位到 HKCU Run 下的 OneDrive；`enable` 在无记录时正确拒绝。
- 计划类型隔离：把 startup 计划交给 cleanup 执行路径 → `E_INVALID_PARAMS`，注册表值不变。
- **实时会话（0.8.2）**：`engine_status` → ok:true、CPython 3.13.2、SQLite 3.45.3、admin:false、28 operations。
- **实时会话（0.9.0）完整清理闭环**：两批共 128 个文件、3,880,043,101 B 移入隔离区，均 `verification.verified: true`；
  `purge_quarantine` 删除 64 项 / 398,487,092 B，0 失败；C: 可用空间净增 3,873,837,056 B（约 3.61 GiB）。
- **缓存根覆盖（0.9.1）**：实测 24 个根（Chrome/Edge 各 profile 的 Cache / Code Cache / GPUCache / Service Worker、
  CrashDumps、Explorer 缩略图），≥1 MB 候选 1,248 个 / 2,914 MB，扫描 64,875 项耗时 1.88 s。

## 5. 未验证（诚实清单）

| 项 | 原因 |
|---|---|
| Windows 10 行为 | 本机为 Win11 22631 |
| 真实软件卸载 | 需要用户指定可弃用软件 |
| 真实注册表启动项写入 | 命令沙箱拒绝写注册表；运行时由 Host 进程执行 |
| 确认卡片渲染 | 需要在真实 Harness 会话中点击 |
| 独占锁文件（E_TARGET_LOCKED） | 难以稳定构造 |
| Defender 状态查询 | 沙箱拒绝 CIM 查询；运行时再确认 |
| 回收站清理 | 未实现（刻意） |
| 浏览器扩展变更 | 未实现（刻意） |

## 6. 如何复跑

```powershell
cd C:\Users\Viver\Desktop\dsh_plugin_dev
python -m unittest discover -s engine/tests -t engine -v
python tools/acceptance.py
node tests/plugin.test.mjs
node tests/engine-client.test.mjs
```

`python tools/acceptance.py` 是端到端验收：真实引擎进程 + 真实 JSONL，26 个场景（见 `ACCEPTANCE.md`）。

Node 测试必须直接用 node 执行文件；`node --test tests/` 会用管道 spawn 子进程，在命令沙箱下报 `EPERM`。
