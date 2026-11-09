# DiskGuardian — P0 实机测试报告

> 版本 0.9.1 · 2026-11-09 · Windows 11 23H2（build 22631.4169）· 非管理员会话
> 命令：`python tools/p0_real_machine.py --yes --keep`

## 1. 结论

- **11/11 自动化场景通过**：真实卸载进程、提权拒绝、启动项写回、锁文件部分失败、只读文件、恢复冲突、隔离区清空异常。
- **2 项未闭环**：
  1. **MSI 卸载被引擎拒绝**：测试 MSI 的 ARP `UninstallString` 是 `MsiExec.exe /I{GUID}`，引擎只接受 `/X` 或 `/uninstall`，计划阶段直接 `E_PLAN_EMPTY`。手动 `msiexec /X /qn` 可以正常卸载，说明是兼容性缺口，不是 MSI 本身的问题。
  2. **确认卡片真实 UI 未点**：当前会话没有加载 DiskGuardian 预设，且策略禁止弹确认；已验证"无确认服务时绝不执行"的 fail-closed 路径，但卡片渲染/点击仍需在预设会话里手工走一次。
- **HKLM 启动项未测**：当前会话非管理员（`IsUserAnAdmin()=False`），无法创建 HKLM Run 测试值；HKCU 已完整验证。

## 2. 环境

| 项 | 值 |
|---|---|
| OS | Windows 11 23H2，build 22631.4169（注册表 `ProductName` 仍写 "Windows 10 Home China"） |
| 权限 | 标准用户令牌，Medium integrity，`IsUserAnAdmin()=False` |
| Python | 3.13.2 |
| Node.js | 24.19.0 |
| 引擎 | 0.9.1，30 个 operation |
| 数据库/隔离区/TEMP | 测试沙箱 `.tmp-tests/p0-20261109-113043/`，不污染真实 `%LOCALAPPDATA%\DiskGuardian` |
| 测试程序 | 本机用 .NET Framework `csc.exe` 编译的静默卸载器，注册在 HKCU 卸载项下，测试后删除 |

## 3. 结果

| 场景 | 检查项 | 结果 | 关键证据 |
|---|---:|---|---|
| `removal-exe-success` | 13/13 | ✅ | 真实 `uninstall.exe` 退出码 0；HKCU 卸载项消失；`verification.verified=true`；残留目录被 `inspect_removal_residue` 报告 |
| `removal-elevation` | 6/6 | ✅ | `requireAdministrator` 卸载器在非提权进程下返回 WinError 740 → `E_ELEVATION_REQUIRED`；软件仍注册；审计记录失败 |
| `removal-msi-i-string` | 2/2 | ⚠️ | MSI 的 `/I{GUID}` UninstallString 被拒绝：`E_PLAN_EMPTY`，原因 "msiexec removal must carry /x or /uninstall" |
| `startup-hkcu-disable-enable` | 9/9 | ✅ | HKCU Run 值被删除；原值入库；`enable` 精确写回；状态从 `disabled` 变 `restored` |
| `startup-value-drift` | 2/2 | ✅ | 批准后把值改成 `calc.exe`，执行前 `E_TARGET_CHANGED`，新值保持不动 |
| `cleanup-locked-partial` | 9/9 | ✅ | 独占锁文件 `E_TARGET_LOCKED`；同批另一个文件成功隔离；`status=partial`；隔离项可恢复且内容一致 |
| `cleanup-readonly-file` | 3/3 | ✅ | `attrib +R` 的临时文件被报 `E_TARGET_LOCKED`，未被静默删除，计划 `failed` |
| `restore-conflict` | 6/6 | ✅ | 原路径被重建后恢复 → `E_TARGET_EXISTS`；重建文件不动；记录仍 `quarantined`；删除冲突后可恢复 |
| `restore-missing-copy` | 2/2 | ✅ | 隔离副本被删后恢复 → `E_NOT_FOUND`；原路径保持不存在 |
| `purge-locked-copy` | 6/6 | ✅ | 锁住隔离副本 → `E_IO`，`purged=0`，记录仍 `quarantined`；解锁后清空成功 |
| `purge-hash-mismatch` | 4/4 | ✅ | 篡改隔离副本 → `E_VERIFY_FAILED`，拒绝删除，记录保留 |

> `removal-msi-i-string` 标 ⚠️ 是**产品能力缺口**，不是测试失败：场景本身通过（引擎按当前规则正确拒绝了 `/I`）。

Node 确认链路：`node tests/tools.test.mjs` **13/13 通过**，新增 2 项"无确认服务时不得执行"的 fail-closed 测试。

## 4. 关键发现

### 4.1 真实卸载（EXE）通过

测试用 HKCU 卸载项指向自编译的 `uninstall.exe`。引擎按注册表命令启动真实进程，退出码 0，随后重新读取注册表确认 `DisplayName` 消失，才标记 `verified=true`。进程输出、失败原因和审计都落在 `removal.run` / `removal.execute`。

这说明：**执行 + 验证链路是真实的**，不是替身。但它验证的是"厂商卸载器会删除自己的注册项"这一契约；第三方卸载器的 GUI、UAC、延迟退出等行为仍未覆盖（见 §5）。

### 4.2 提权拒绝正确，不重试

带 `requireAdministrator` manifest 的卸载器从非提权进程启动时，Python `subprocess` 返回 WinError 740，引擎映射为 `E_ELEVATION_REQUIRED`，记 `failed_items`，不重试、不弹 UAC。软件注册项保持原样。这正是文档承诺的行为。

### 4.3 启动项写回（HKCU）通过

- `disable`：删除 Run 值 → 写入 `startup_changes`（含原始数据）→ 重新读取确认值为空。
- `enable`：从 `startup_changes` 取回原始数据 → 写回 → 重新读取确认完全一致。
- 值漂移：批准后把值改成 `calc.exe`，执行前被 `E_TARGET_CHANGED` 拦截，新值未被动过。

HKLM 路径未测：当前非管理员，无法创建 HKLM Run 测试值；也不应拿用户已有的启动项做实验。

### 4.4 锁文件与部分失败符合预期

用 `CreateFileW(..., dwShareMode=0)` 独占锁住 `p0-locked.tmp`，同一计划里的 `p0-good.tmp` 正常隔离：

- 整批 `status=partial`，不是全成功也不是全失败；
- 锁文件 `E_TARGET_LOCKED`，源文件保留；
- 成功项可 `restore`，内容哈希校验通过；
- `verification.verified=false`，如实反映部分失败。

### 4.5 只读文件被当作"锁定"处理

`attrib +R` 的文件在 `_assert_unlocked()` 里 `os.open(O_RDWR)` 失败，返回 `E_TARGET_LOCKED`，文件保留。行为是安全的（不删），但错误码语义略粗：用户看到的是"locked"，实际是只读属性。是否要区分 `E_TARGET_READONLY` 可以后续决定。

### 4.6 恢复与清空隔离区的异常路径全部 fail-closed

- 原路径被重建：`E_TARGET_EXISTS`，不覆盖用户新文件；
- 隔离副本丢失：`E_NOT_FOUND`；
- 隔离副本被锁：purge 返回 `E_IO`，不删除、记录不变；
- 副本被篡改：`E_VERIFY_FAILED`，拒绝删除；
- 解锁/移除冲突后，恢复和清空都能成功。

### 4.7 MSI `/I` 兼容性缺口（需要修）

测试 MSI 用 WiX 5 构建，安装后 ARP 项是：

```
UninstallString = MsiExec.exe /I{1660C740-0EAD-4E2D-B202-01B33B6BC659}
```

引擎的 `validate_uninstaller()` 对 `msiexec.exe` 只接受 `/X`、`-X` 或 `/uninstall`（[removal.py:143](engine/diskguardian/actions/removal.py#L143-L145)），因此 `create_removal_plan` 把该软件排除，最终 `E_PLAN_EMPTY`。

手动执行 `msiexec /X{GUID} /qn` 可以正常卸载（退出码 0，ARP 项和安装目录都消失）。所以这是**引擎的可卸载范围缺口**，不是 MSI 损坏。

建议二选一：

1. **修**：对 `msiexec` 的 `/I{GUID}` 形式，识别 GUID 并重写为 `/X{GUID}`，同时补 `/qn`，然后走现有验证；加一条单元测试和一条实机用例。
2. **不修**：在 `create_removal_plan` 的排除原因里明确写"该 MSI 使用 /I 维护模式，请用 Windows 应用设置卸载"，并在文档中列为已知限制。

当前报告按"不修"记录，未改产品行为。

### 4.8 确认卡片：真实 UI 未验，fail-closed 已验

当前会话没有 DiskGuardian 预设，`execute_cleanup_plan` 等工具不可用；即使可用，策略也禁止弹确认。因此**卡片渲染、批准、拒绝、超时没有在真实 GUI 里点过**。

已补的自动化保证：

- `userQuestions` 服务不存在时，工具抛 `E_CONFIRMATION_UNAVAILABLE`，只调用 `preview_action_plan`，**不签发批准、不执行**；
- 服务抛错时按"未确认"处理，返回 `declined:true`，不执行；
- 执行类工具 schema 仍不接受 `approval_id` / `approved`。

真实 UI 的手工步骤（需要 DiskGuardian 预设会话、允许确认）：

1. 在临时目录造一个超过 24h 的 `.tmp` 文件；
2. 让模型 `create_cleanup_plan`；
3. 调 `execute_cleanup_plan`，确认卡片出现，检查计划 ID、文件数、目标路径；
4. 点"取消"：文件不动、计划仍 `pending`；
5. 再调一次，点"确认执行"：文件进隔离区、审计有记录；
6. 等 5 分钟超时：工具应返回未确认，不执行。

## 5. 未完成 / 阻塞

| 项 | 原因 | 后续 |
|---|---|---|
| HKLM 启动项写回 | 非管理员，不能创建测试值 | 在管理员会话/VM 用 HKCU 同款流程补测；不要动用户已有项 |
| 真实第三方软件卸载 | 不能拿用户软件做实验 | 在 VM 装一个可弃用软件（MSI/EXE 各一），走完整卡片确认 |
| MSI 成功卸载（引擎驱动） | `/I` 被拒；fixture 没有可写的 QuietUninstallString | 先决定 §4.7 的修/不修，再补一条引擎驱动的 MSI 用例 |
| 确认卡片真实渲染 | 当前会话无预设、确认被禁用 | 按 §4.8 手工走一遍 |
| 重启后启动项是否真的不启动 | 不做重启 | 在 VM 里禁用测试项 → 重启 → 确认未启动 → 恢复 |
| 第三方卸载器的 UAC/GUI/延迟退出 | 测试 fixture 是静默的 | 用真实软件在 VM 验证 |

## 6. 复现

```powershell
# 需要非管理员或管理员均可；脚本只写 HKCU 测试项
python tools/p0_real_machine.py --yes --keep
```

脚本会：

1. 在 `%LOCALAPPDATA%\DiskGuardianP0` 编译两个测试卸载器（普通/requireAdministrator）；
2. 写 HKCU Uninstall / Run 测试项，执行 11 个场景；
3. 无论成功失败，`finally` 删除测试项、测试程序和启动项；
4. 数据库、TEMP、隔离区都在 `.tmp-tests/p0-*`，不动真实 `%LOCALAPPDATA%\DiskGuardian`；
5. 不加 `--keep` 时连沙箱一起删除；加 `--keep` 保留 `report.json`。

安全边界：不卸载用户软件、不改 HKLM、不重启、不写用户文档目录。

## 7. 建议

1. **先决定 MSI `/I` 策略**（§4.7）。这是 P0 里唯一一个会让真实用户"点不了卸载"的功能缺口。
2. 在 VM 里补：真实第三方 EXE/MSI 卸载、重启后的启动项验证、管理员会话的 HKLM。
3. 在 DiskGuardian 预设会话里补确认卡片的拒绝/超时分支。
4. 可选：区分 `E_TARGET_READONLY` 与 `E_TARGET_LOCKED`，避免只读文件被描述成"被占用"。
5. 可选：跨卷隔离（TEMP 在 D:）仍未测；`%LOCALAPPDATA%` 固定放 C:，跨卷会走 copy+delete，文档里"同卷"的表述需要修正。
