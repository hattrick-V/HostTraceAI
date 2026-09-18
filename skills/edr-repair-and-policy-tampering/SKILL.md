---
name: edr-repair-and-policy-tampering
description: "安全软件装不上/被拉黑/被接管时的排查与修复：识别恶意代码完整性（WDAC/CI）策略、BYOVD 型反杀软驱动、杀软残留过滤驱动与未生效的服务删除，按审批流程恢复安全软件正常工作。当目标主机出现火绒/360/Defender 装不上、装完不启动、被策略阻止加载、残留驱动锁目录时加载本技能。"
metadata:
  tags: ["溯源", "windows", "EDR修复", "WDAC", "驱动"]
  version: "1.0.0"
---

# 安全软件装不上：策略篡改与驱动残留排查修复

入侵者常见手法之一不是"躲过"安全软件，而是**让它装不上、起不来、被系统拉黑**。本技能给出识别与（经审批后）修复的完整路径。

## 适用条件

- 目标主机安装安全软件失败：提示驱动加载失败、安装程序无提示退出、装完服务不启动（Windows 服务启动报 1067/1053）。
- 已装安全软件被"接管"或停用：Defender 显示 `Not running`、被第三方接管后无法恢复，或防护模块被禁用且改不回来。
- 出现无签名的可疑内核驱动、且其文件时间/来源与正常软件不符。
- 排查过程中发现代码完整性/组策略层面的异常项。

前置信息：系统版本与补丁、是否有域/组策略、已装与曾装过的安全软件清单、最近一次成功安装时间、重启是否被允许（多个修复动作需要重启才生效）。

## 证据要求

- 策略类：`C:\Windows\System32\CodeIntegrity\`（`SiPolicy.p7b` / `CiPolicies\Active\*.cip`）的文件列表、大小、时间戳、SHA-256、PolicyID/PolicyName；导出副本后再谈落盘修改。
- 驱动类：驱动文件路径、SHA-256、签名状态（`Get-AuthenticodeSignature`）、服务注册项（`HKLM\SYSTEM\CurrentControlSet\Services\<name>` 的 `ImagePath`/`Start`/`Type`）、文件创建时间（对比恶意活动时间窗）。
- 残留类：`HKLM\SYSTEM\CurrentControlSet\Services` 中已停止但仍在的过滤驱动、`PendingFileRenameOperations`、安装目录 ACL 与锁定进程（用 `handle`/`Get-Process` 关联，或开机安全模式观察）。
- 事件日志：代码完整性事件（`Microsoft-Windows-CodeIntegrity/Operational`，常见 3033/3077/3099）、驱动加载失败（System 日志 219/7026）、服务启动失败（7000/7009/7011/7024）。
- 每一项修复动作都要记录：改前状态、改后状态、是否可回滚（备份文件路径）。

## 工具顺序

1. **确认现象**：
   `Get-MpComputerStatus | Select AMRunningMode,AntivirusEnabled,RealTimeProtectionEnabled`（Defender 被接管时会异常）；
   `Get-Service | Where-Object {$_.Name -match 'sysdiag|hr|360|huorong|defender'} | Select Name,Status,StartType`；
   查看安全软件安装目录是否残留、是否有进程锁定（`Get-Process | Where-Object Path -like '*<厂商目录>*'`）。
2. **查代码完整性策略**：
   `Get-ChildItem C:\Windows\System32\CodeIntegrity -Recurse -Force | Select FullName,Length,LastWriteTime`；
   `Get-ChildItem C:\Windows\System32\CodeIntegrity\CiPolicies\Active -Force`；
   `Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Select CodeIntegrityPolicyEnforcementStatus`；
   对每个策略文件算哈希并**只读复制留档**；用 `CiTool -lp`（若可用）列出当前生效策略与 PolicyID。
   判据：**策略文件落在 CodeIntegrity 目录且时间戳落在入侵时间窗内、PolicyID 与微软默认策略不同** → 高度可疑（这是"用系统自身机制拉黑安全软件"的典型痕迹）。
3. **查内核驱动**：
   `driverquery /v /fo csv`；`Get-CimInstance Win32_SystemDriver | Select Name,DisplayName,PathName,State,StartMode`；
   对路径异常（`C:\Windows\Temp`、`ProgramData`、`Users\Public`、随机英文名）且无有效签名的驱动逐个算哈希、查情报、看是否与安全进程句柄清理/进程终止相关行为对应。
   BYOVD 特征：驱动合法签名但**被滥用**（可能是某厂商真实驱动被拿来清安全软件句柄），需要结合"它由谁加载、加载时间、加载后杀软进程发生了什么"来判断。
4. **查残留与锁定**：
   服务已被删除但驱动仍加载（`sc delete` 只标记删除，**重启后才真正卸载**）→ 说明"装不上"很可能是一次重启就能解决的假象；
   安装目录被过滤驱动占用 → 检查是否有厂商卸载残留、是否需要重启后再清目录。
5. **归类结论**：把"装不上"的原因归到四类之一 —— ①恶意 CI/WDAC 策略拉黑；②BYOVD 驱动对抗安全软件；③安全软件卸载残留（驱动/服务/目录锁定）；④系统组件损坏（WMI/服务栈）。
6. **修复（全部提交审批，逐条执行并复验）**：
   - 隔离并保留恶意策略副本 → 移除策略文件（或按微软流程更新为合规策略）→ 重启 → 用 `CiTool -lp` 与 CodeIntegrity 事件确认不再拦截；
   - 停止并删除恶意驱动服务（`sc stop <name>`、`sc delete <name>`）→ **重启**以完成卸载 → 确认驱动文件可删除后归档；
   - 清理残留：结束锁定进程或重启后删除锁定目录、清理 `PendingFileRenameOperations`；
   - 修复后重装安全软件 → 确认服务能启动、防护生效（`Get-MpComputerStatus` 或厂商状态页）。
7. **复验与闭环**：重采一次策略目录、驱动列表、服务状态、事件日志；确认无新的拦截事件；把"改前/改后"对照写入报告。

## 停止条件

- 四类原因已定位并有证据 → 进入修复（走审批）。
- 需要重启/停机、需要修改系统策略、需要删除驱动服务 → 停止，提交审批并说明必须重启的理由。
- 出现无法判定的合法业务驱动 → 不动它，标注"待厂商或系统管理员确认"。

## 输出格式

```
【主机】<ip/主机名> 系统版本 <…> 是否允许重启 <是/否>
【现象】装不上/起不来/被拉黑 具体表现 + 报错码
【归类】①恶意CI策略 ②BYOVD驱动 ③卸载残留 ④组件损坏（置信度）
【证据】策略文件/驱动/服务/事件日志 → 路径 + SHA-256 + 时间 + 命令输出
【修复方案】动作 → 命令 → 影响面 → 是否需重启 → 回滚方式（标注需审批）
【复验结果】策略状态、驱动状态、安全软件能否启动
【未决】…
```

## 红线与审批

- 只读：列策略/驱动/服务、算哈希、导出策略与驱动副本、读事件日志 → 直接执行。
- 需审批：删除或替换 CI 策略文件、停止/删除驱动与服务、修改注册表、重启主机、卸载残留安全软件组件。
- 禁止：未经归档就删除策略或驱动文件；在未确认恶意的情况下动业务驱动；跳过重启就宣称"已修复"。
