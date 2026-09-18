---
name: windows-host-triage
description: "Windows 主机溯源与应急处置：当目标 Windows 主机疑似被入侵、存在恶意外联、木马反复复活、安全软件被禁用或装不上时，经主机通道完成只读取证（落地时间、投毒载体、持久化七处、外联与 C2）、样本只归档不删除、隔离区移动与持久化清除，并产出时间线、IOC、证据链报告。"
metadata:
  tags: ["溯源", "windows", "应急响应", "持久化", "C2"]
  version: "1.0.0"
---

# Windows 主机溯源与应急处置

## 适用条件

- 触发：主机疑似被入侵、有恶意外联、木马清完又复活、杀软被禁用或装不上、系统时间被改。
- 前置信息：`<target-ip>`、可用 `<user>`、系统版本（Win10/11/Server）、是否中文系统、业务是否在线、用户提供的可疑 IP/域名/文件名/时间点。
- 接入方式：用 `execute` 经平台主机通道逐条下发命令（Windows OpenSSH 服务默认监听 22/tcp）。每条命令必须带墙钟超时，某条卡住要能中断并保留已完成进度，不能整批假死。
- 采集阶段全程只读；处置动作（清持久化、杀进程、搬文件、改注册表/服务/驱动/策略）先出方案走审批。
- 中文系统命令输出按 GBK 解码；输出量大时先在主机侧 `Export-Csv` / 重定向落盘再取回，用 `glob`、`grep`、`read_file` 在 `<case-dir>/` 离线复读，不重复上机。

## 证据要求

- 每条命令留一份：主机标识、采集时间（显式标注 UTC+8）、命令原文、原始输出、退出码，存 `<case-dir>/raw/`；第二轮独立存 `<case-dir>/raw2/`。
- 样本（可执行体、侧载 DLL/dat/伪装文件、C2 配置文件、恶意驱动、投毒载体）只读复制到 `<case-dir>/样本/`，逐文件 `Get-FileHash -Algorithm SHA256` 生成"路径+大小+SHA256"三列清单，打包 zip 后与源目录逐条比对条目数/大小/哈希。
- 时间证据写清来源与时区：文件 `CreationTime`、`C:\Windows\System32\Tasks` 下任务文件时间、事件日志 `TimeCreated`、浏览器下载库时间（UTC，需 +8）。
- 结论分 `事实`（有原文/哈希支撑）、`推断`、`待验证`；主机侧未观测到的历史外联一律写"主机侧无记录，需边界设备日志按时间点比对"，不得推断成结论。

## 工具顺序

1. 定位在连谁（只读）
   - `netstat -ano`；`powershell -NoProfile -Command "Get-NetTCPConnection -State Established,SynSent | Select RemoteAddress,RemotePort,OwningProcess,State"`。长期 `SYN_SENT` 同一目标端口 = 常驻体反复重试上线。
   - PID → 进程：`powershell -NoProfile -Command "Get-CimInstance Win32_Process | Select ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate | ConvertTo-Csv -NoTypeInformation"`。父进程为 `svchost.exe -k netsvcs -s Schedule` 即计划任务拉起。
2. 落地时间与投毒载体
   - 落地时间取文件创建时间：`Get-ChildItem 'C:/Program Files (x86)','C:/Users/Public','C:/ProgramData' -Force | Sort CreationTime -Desc | Select -First 40`；任务文件时间 `dir /a /tc "C:\Windows\System32\Tasks"`。
   - 服务/驱动安装 `Get-WinEvent -FilterHashtable @{LogName='System';Id=7045;StartTime=(Get-Date).AddDays(-60)}` 可把装驱动钉到秒；7040 = 服务启动类型被改（禁用 Windows 更新/Defender）；Application 1000/1001 = 恶意程序崩溃；System 1 = 系统时间被改；`provider=winsrvext` 的 100 属正常组件，勿误报。
   - 浏览器下载库 `C:\Users\<user>\AppData\Local\Microsoft\Edge\User Data\Default\History`（SQLite，`downloads` 表 `target_path/tab_url/start_time`）：时间为 1601 起微秒且是 UTC，+8 后与文件创建时间对齐，通常直接锁定投毒载体。
   - 辅助源：Amcache/ShimCache/Recent；USN 先 `fsutil usn queryjournal C:` 看"最大大小"（默认 32MB，滚动快，多半已覆盖）；Prefetch 每程序一条且会被覆盖。ACL 仍为默认继承的目录不要写成木马落地目录。
3. 持久化七处枚举（一处都不能漏）
   - 计划任务：`schtasks /query /fo csv /v`；按动作路径筛非常规位置 `Get-ScheduledTask | ?{ $_.Actions.Execute -and $_.Actions.Execute -notmatch '(?i)^(%SystemRoot%|%windir%|C:\\Windows|C:\\Program Files|C:\\ProgramData\\Microsoft)' }`。
   - 注册表自启动：`reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"`、同路径 `HKCU`、`HKLM\SOFTWARE\WOW6432Node\...\Run`、`HKU\<SID>\...\Run(Once)`；键名常伪装成 Alibaba/Tencent/Microsoft SecurityHealth。
   - 服务：`Get-CimInstance Win32_Service | ?{ $_.PathName -notmatch '(?i)C:\\Windows|C:\\Program Files' } | Select Name,State,StartMode,PathName`。
   - 内核驱动（`Win32_Service` 不含驱动，漏这步就漏 BYOVD）：`Get-CimInstance Win32_SystemDriver | Select Name,State,StartMode,PathName`，路径不在 `System32\drivers|DriverStore` 的重点看，木马会把驱动伪装成 `C:\Windows\Temp\*.jpg`。
   - WMI 订阅：`Get-CimInstance -Namespace root/subscription -ClassName __EventFilter,CommandLineEventConsumer,__FilterToConsumerBinding`。
   - 启动文件夹、`Winlogon` 的 `Shell`/`Userinit`（`reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell`）。
4. C2 与外联
   - 目的 IP:PORT ↔ PID ↔ 进程完整路径 ↔ 落地目录名交叉比对；侧载宿主目录里所有非 exe 大文件（伪装 `thumbs.db`/`image.png`/`.dat`）取回本地 `grep` 点分四段 IP、域名、端口，C2 配置多为明文。
   - 输出 `netstat -ano` 原文与外联时长，供边界设备按时间点比对。
5. 处置：先断复活链 → 再杀进程 → 最后搬文件
   - 先留证：任务 `schtasks /query /tn "<任务名>" /xml > <case-dir>\raw\任务X.xml`、`reg export "HKLM\...\Run" <case-dir>\raw\Run备份.reg /y`、事件日志按时间窗 `Export-Csv`。导出件必须与样本一起归档，否则主机目录被清时一并消失。
   - 清持久化：`schtasks /delete /tn "<任务名>" /f`、`reg delete "HKLM\...\Run" /v "<值名>" /f`、驱动服务 `sc delete <服务名>`（STOPPED 可直接删）。顺序颠倒会被 1 分钟看门狗任务立刻拉起。
   - 杀进程：`taskkill /F /IM <a.exe>`。
   - 搬文件（木马常写 DENY 删除 ACE + 隐藏/系统属性，直接 move 报"系统找不到指定的文件/拒绝访问"）：`takeown /f "<目录>" /r /d y` → `icacls "<目录>" /remove:d *S-1-5-32-545 /T /C` → `icacls "<目录>" /grant *S-1-5-32-544:(OI)(CI)F /T /C` → `attrib -s -h -r "<目录>\*" /s /d` → `robocopy "<目录>" "C:\Quarantine_<target-ip>_<日期>\<新名>" /E /MOVE /R:1 /W:1 /NFL /NDL /NJH /NJS`。隔离目录同名空壳先 `rd` 掉。**只移动，不 `del`**。
   - 复查（立刻 + 60~210 秒各一次）：`for %p in ("<路径1>" "<路径2>") do @if exist %p (echo EXISTS %p) else (echo GONE %p)`、`tasklist | findstr /i "<进程名>"`、`netstat -ano | findstr "<C2端口>"`、`schtasks /query /fo csv | findstr /i "<任务名>"`、`reg query "HKLM\...\Run"`。
6. 清理后安全软件装不上时的排查顺序
   - 残留过滤驱动锁安装目录：`fltmc filters` 看驱动是否仍在内存；改名探针 `ren "C:\Windows\System32\drivers\<x>.sys" <x>.sys.probe`，报"拒绝访问"即被加载中的驱动占用。`icacls` 显示 Everyone 全权限却仍拒绝写入 = 内核过滤驱动在保护，别继续绕 ACL。
   - 木马投放的代码完整性（WDAC）策略：`CiTool -lp -json`，`IsSignedPolicy:false` 且 `IsEnforced:true` 即恶意；`Microsoft-Windows-CodeIntegrity/Operational` 的 3077/3033/3004 可佐证。处置：先把 `C:\Windows\System32\CodeIntegrity\SiPolicy.p7b` 移到隔离区，再 `CiTool -r` 当场卸下策略（无需重启），探针验证：复制 `cmd.exe` 改名为被杀软黑名单中的进程名后能正常运行。保留 `IsSystemPolicy:true` 的微软自带策略。
   - 驱动文件被占用需重启前搬走：`MoveFileEx(src, dst, 4)`（DELAY_UNTIL_REBOOT）。进安全模式前先 `reg query "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot" /s /f <驱动名>` 确认它不在 SafeBoot 列表；安全模式下主机通道通常不可用，只能让用户本地执行预置脚本。
   - 顺序：先重启再装 → 仍失败则清残留（`sc delete` + 搬 `.sys`/`.trashed` + 清产品目录）→ 或安全模式安装。清残留属改系统配置，须先取得用户同意；正在 RUNNING 的正常杀软不要动。

## 停止条件

- 证据闭环即停：落地时间、投毒载体、持久化清单、外联主体、样本哈希齐备，且处置后两次复查均为 GONE。
- 需审批即停：任何改服务/驱动/注册表/代码完整性策略、清合法软件残留、隔离主机、阻断外联的动作，先出方案等确认。
- 无权限或通道中断：记录已完成部分并交回，不做旁路尝试。
- 影响业务即停：主机在跑关键业务，或动作可能导致停机（重启、安全模式、杀进程）时先报影响面。
- 主机侧无法证实的历史外联不做无限深挖（USN 已覆盖、出站日志关闭即以书面说明收口）。

## 输出格式

- 时间线表（时间/阶段/事件/证据来源），阶段按 落地 → 持久化 → 外联 → 处置 排序。
- 持久化清单表（类型/名称/路径/参数/证据）、外联与 IOC 表（IP、端口、域名、URL、文件哈希）、未闭合问题表。
- 每条结论标注 `事实`/`推断`/`待验证` 与置信度；哈希、路径、时间戳原样给全，供沙箱与边界设备检索。
- 处置记录：动作、执行时间、命令原文、执行前后对比、复查结果。
- 建议动作：凭据按已泄露处理并重置、全盘查杀、同网段排查相同哈希、投毒域名与文件提交沙箱核对。

## 红线与审批

- 只读动作（枚举、查询、导出、哈希、只读复制）直接执行。
- 必须审批：清持久化、杀进程、移动文件、改注册表/服务/驱动、移走 WDAC 策略、重启或进安全模式、清杀软残留。
- 任何情况下：样本只归档不删除，主机上只允许移到隔离目录；不删除非恶意文件与业务数据；不尝试任何口令；不对非目标主机发起连接或扫描；不覆盖业务配置。
- 处置后必须复查；复查不通过时记录并继续上报，不得据此回滚结论。
