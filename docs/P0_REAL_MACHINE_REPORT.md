# DiskGuardian — P0 实机测试报告

> 版本 0.9.1 · 2026-11-09 · Windows 11 23H2（build 22631.4169）· 非管理员会话
> 命令：`python tools/p0_real_machine.py --yes --keep --msi-fixture .tmp-tests/p0/msi/p0.msi`

## 1. 结论

- **12/12 自动化场景通过**，包括：真实 EXE 卸载、提权拒绝、**真实 MSI `/I` 卸载**、启动项写回、锁文件部分失败、只读文件、恢复冲突、隔离区清空异常。
- **MSI `/I` 兼容性缺口已修复并实测**：`MsiExec.exe /I{GUID}` 现在会先解析到 `%SystemRoot%\System32\msiexec.exe`，再重写为 `/X{GUID} /qn`；真机安装的 MSI 由引擎成功卸载，ARP 项与安装目录都消失。
- **1 项未闭环**：确认卡片的真实 UI 未点。当前会话没有加载 DiskGuardian 预设，且策略禁止弹确认；已用测试证明"无确认服务时绝不执行"的 fail-closed 行为，但卡片渲染/批准/拒绝/超时仍需在预设会话里手工走一次。
- **HKLM 启动项未测**：当前会话非管理员（`IsUserAnAdmin()=False`），无法创建 HKLM Run 测试值；HKCU 已完整验证。

## 2. 环境

| 项 | 值 |
|---|---|
| OS | Windows 11 23H2，build 22631.4169（注册表 `ProductName` 仍写 "Windows 10 Home China"） |
| 权限 | 标准用户令牌，Medium integrity，`IsUserAnAdmin()=False` |
| Python | 3.13.2 |
| Node.js | 24.19.0 |
| 引擎 | 0.9.1，30 个 operation |
| 数据库/隔离区/TEMP | 测试沙箱 `.tmp-tests/p0-20261109-114313/`，不污染真实 `%LOCALAPPDATA%\DiskGuardian` |
| EXE 测试程序 | 本机用 .NET Framework `csc.exe` 编译的静默卸载器，注册在 HKCU 卸载项下，测试后删除 |
| MSI 测试程序 | WiX 5 构建的可弃用 MSI，安装到 `%LOCALAPPDATA%\DiskGuardianP0Msi`，测试后卸载 |

## 3. 结果

| 场景 | 检查项 | 结果 | 关键证据 |
|---|---:|---|---|
| `removal-exe-success` | 13/13 | ✅ | 真实 `uninstall.exe` 退出码 0；HKCU 卸载项消失；`verification.verified=true`；残留目录被 `inspect_removal_residue` 报告 |
| `removal-elevation` | 6/6 | ✅ | `requireAdministrator` 卸载器在非提权进程下返回 WinError 740 → `E_ELEVATION_REQUIRED`；软件仍注册；审计记录失败 |
| `removal-msi-i-string` | 4/4 | ✅ | 裸 `MsiExec.exe /I{GUID}` 被解析到 `C:\Windows\System32\msiexec.exe`，计划参数变为 `['/X{GUID}', '/qn']` |
| `removal-msi-real` | 7/7 | ✅ | 真实 MSI 安装成功；ARP 为 `MsiExec.exe /I{GUID}`；引擎重写并执行 `/X{GUID} /qn`，退出码 0，`verified=true`，ARP 与安装目录均消失 |
| `startup-hkcu-disable-enable` | 9/9 | ✅ | HKCU Run 值被删除；原值入库；`enable` 精确写回；状态从 `disabled` 变 `restored` |
| `startup-value-drift` | 2/2 | ✅ | 批准后把值改成 `calc.exe`，执行前 `E_TARGET_CHANGED`，新值保持不动 |
| `cleanup-locked-partial` | 9/9 | ✅ | 独占锁文件 `E_TARGET_LOCKED`；同批另一个文件成功隔离；`status=partial`；隔离项可恢复且内容一致 |
| `cleanup-readonly-file` | 3/3 | ✅ | `attrib +R` 的临时文件被报 `E_TARGET_LOCKED`，未被静默删除，计划 `failed` |
| `restore-conflict` | 6/6 | ✅ | 原路径被重建后恢复 → `E_TARGET_EXISTS`；重建文件不动；记录仍 `quarantined`；删除冲突后可恢复 |
| `restore-missing-copy` | 2/2 | ✅ | 隔离副本被删后恢复 → `E_NOT_FOUND`；原路径保持不存在 |
| `purge-locked-copy` | 6/6 | ✅ | 锁住隔离副本 → `E_IO`，`purged=0`，记录仍 `quarantined`；解锁后清空成功 |
| `purge-hash-mismatch` | 4/4 | ✅ | 篡改隔离副本 → `E_VERIFY_FAILED`，拒绝删除，记录保留 |

Node 确认链路：`node tests/tools.test.mjs` **13/13 通过**，含 2 项"无确认服务时不得执行"的 fail-closed 测试。

## 4. 关键发现

### 4.1 真实卸载（EXE）通过

测试用 HKCU 卸载项指向自编译的 `uninstall.exe`。引擎按注册表命令启动真实进程，退出码 0，随后重新读取注册表确认 `DisplayName` 消失，才标记 `verified=true`。进程输出、失败原因和审计都落在 `removal.run` / `removal.execute`。

这说明：**执行 + 验证链路是真实的**，不是替身。第三方卸载器的 GUI、UAC、延迟退出等行为仍未覆盖（见 §5）。

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

### 4.7 MSI `/I` 已修复并实测

修复前有两个叠加问题：

1. ARP 里的 `UninstallString` 常写成裸 `MsiExec.exe /I{GUID}`，而 `validate_uninstaller()` 要求可执行文件是绝对路径，先报"uninstall executable is missing"；
2. 即使路径可解析，`/I{GUID}` 也不在 `/X`、`-X`、`/uninstall` 的白名单里。

修复（[removal.py](engine/diskguardian/actions/removal.py)）：

- 裸 `MsiExec.exe` 先解析到 `%SystemRoot%\System32\msiexec.exe`，不信 PATH；
- 新增 `_msiexec_product_code()`：只接受带花括号的合法 GUID；
- 新增 `_normalize_msiexec_arguments()`：把 `/I{GUID}`（含 `/I {GUID}`）重写为 `/X{GUID}`，保留其他参数，移除原有 `/q*` 并统一补 `/qn`，确保无维护对话框；
- 其他 `/I<路径>.msi` 形式仍拒绝，不会被误当成卸载。

真机证据：

```
ARP:    MsiExec.exe /I{8B6F3A2C-7D4E-4A1B-9C2D-3E4F5A6B7C8D}
计划:   /X{8B6F3A2C-7D4E-4A1B-9C2D-3E4F5A6B7C8D} /qn
结果:   exit 0, success=true, verification.verified=true
        ARP 项消失，%LOCALAPPDATA%\DiskGuardianP0Msi 被移除
```

单测：新增 5 项（`/I{GUID}` 重写、`/I {GUID}` 重写、`/qb` 被统一为 `/qn`、包路径拒绝、裸 `MsiExec.exe` 解析），Python 共 **101 项**通过。

可复跑的 MSI 夹具源码在 [tools/fixtures/p0_msi/Product.wxs](tools/fixtures/p0_msi/Product.wxs)：

```powershell
Push-Location tools\fixtures\p0_msi
wix build Product.wxs -o ..\..\..\.tmp-tests\p0\msi\p0.msi
Pop-Location
```

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
| 确认卡片真实渲染 | 当前会话无预设、确认被禁用 | 按 §4.8 手工走一遍 |
| 重启后启动项是否真的不启动 | 不做重启 | 在 VM 里禁用测试项 → 重启 → 确认未启动 → 恢复 |
| 第三方卸载器的 UAC/GUI/延迟退出 | 测试 fixture 是静默的 | 用真实软件在 VM 验证 |

## 6. 复现

```powershell
# 基础 11 项（不装 MSI）
python tools/p0_real_machine.py --yes --keep

# 加上真实 MSI 卸载（先按 §4.7 构建 p0.msi）
python tools/p0_real_machine.py --yes --keep `
  --msi-fixture .tmp-tests\p0\msi\p0.msi
```

脚本会：

1. 在 `%LOCALAPPDATA%\DiskGuardianP0` 编译两个测试卸载器（普通/requireAdministrator）；
2. 写 HKCU Uninstall / Run 测试项，执行场景；
3. 提供 `--msi-fixture` 时安装该 MSI，由引擎卸载并验证，失败则用 `msiexec /x /qn` 清理；
4. 无论成功失败，`finally` 删除测试项、测试程序、启动项和 MSI 安装目录；
5. 数据库、TEMP、隔离区都在 `.tmp-tests/p0-*`，不动真实 `%LOCALAPPDATA%\DiskGuardian`；
6. 不加 `--keep` 时连沙箱一起删除；加 `--keep` 保留 `report.json`。

安全边界：不卸载用户软件、不手工写 HKLM、不重启、不写用户文档目录。MSI 的 ARP 注册由 Windows Installer 完成，不是脚本直接写注册表。

## 7. 建议

1. 在 VM 里补：真实第三方 EXE/MSI 卸载、重启后的启动项验证、管理员会话的 HKLM。
2. 在 DiskGuardian 预设会话里补确认卡片的拒绝/超时分支。
3. 可选：区分 `E_TARGET_READONLY` 与 `E_TARGET_LOCKED`，避免只读文件被描述成"被占用"。
4. 可选：跨卷隔离（TEMP 在 D:）仍未测；`%LOCALAPPDATA%` 固定放 C:，跨卷会走 copy+delete，文档里"同卷"的表述需要修正。
