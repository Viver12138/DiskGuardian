# DiskGuardian — Compatibility

> 版本 0.7.0

## 1. 运行环境（实测）

| 项 | 值 | 说明 |
|---|---|---|
| DSH | 0.2.2-rc.1（Desktop / Electron 44.7.0） | API 以运行时 `cordis_inspect_query` 为准 |
| OS | Windows 11 23H2，22631.4169 | 注册表 `ProductName` 仍显示 "Windows 10"，按 build ≥ 22000 判定 |
| 版本类型 | 家庭中文版（CoreCountrySpecific） | 无组策略编辑器；策略键只读检查 |
| 权限 | 非管理员 | 卸载/系统级修改会返回 `E_ELEVATION_REQUIRED` |
| Python | 3.13.2（系统安装） | 只用标准库；`psutil` 等第三方包不是依赖 |
| Node.js | 24.19.0 | 插件与测试 |
| PowerShell | 5.1（`powershell.exe`）+ 7.6.9（`pwsh`） | 引擎固定脚本使用 5.1 |
| 浏览器 | Chrome、Edge（本机均安装，3 个配置文件） | Firefox 不在 V1 范围 |

## 2. 支持矩阵

| 能力 | Windows 11 | Windows 10 | 备注 |
|---|---|---|---|
| 磁盘/目录/大文件扫描 | ✅ 实测 | 代码路径相同，未实测 | 用 Win32 卷 API |
| 软件清单 + 签名 | ✅ 实测 | 未实测 | 注册表 + WinVerifyTrust |
| 启动项检查 | ✅ 实测（注册表/Folder） | 未实测 | 计划任务 XML 在沙箱内不可读 |
| 服务检查 | ✅ 实测 | 未实测 | 注册表 + `sc.exe` |
| 浏览器检查 | ✅ 实测 | 未实测 | Chrome/Edge 配置文件结构稳定 |
| 安全态势 | 部分实测 | 未实测 | 防火墙走注册表；Defender 查询在沙箱被拒 |
| 清理（隔离） | ✅ 实测 | 未实测 | 路径规则与系统无关 |
| 卸载 | 流程用替身验证 | 未实测 | 依赖厂商卸载器 |
| 启动项禁用 | 流程用替身验证 | 未实测 | HKCU/HKLM Run |
| 系统服务修改 | ❌ 不提供 | — | L3，但本版不实现 |
| 浏览器扩展移除 | ❌ 不提供 | — | 设计理由见 SECURITY.md §5 |

## 3. 能力检测优先于版本号

- 卷类型：`GetDriveTypeW`，不是"假设 C 盘是固定盘"。
- 服务：是否存在 `sc.exe` 结果，而不是比较 Windows 版本。
- 注册表路径缺失 → 该字段为 `null` 并在 `coverage` 中体现，不 assuming。
- PowerShell 不可用 → 查询标记 `unavailable`，分析器输出 `unknown`。

## 4. 已知环境限制

1. 家庭版没有 `gpedit`，浏览器策略键通常不存在；这意味着"未受管理"是常态，不能据此判断安全。
2. 非管理员会话无法读取部分服务配置、无法枚举全部计划任务；引擎如实报告覆盖率。
3. Windows 10 已于 2025-10-14 结束主流支持；引擎把"能运行"和"仍受支持"分开报告（`lifecycle`）。
4. 中文/多语言环境：所有输出为 UTF-8；`sc.exe` 输出按 UTF-8 解码并容错。
5. DSH 文件沙箱会拦截 `%TEMP%` 写入与注册表写入，因此部分能力只能在运行时（Host 进程）验证。
