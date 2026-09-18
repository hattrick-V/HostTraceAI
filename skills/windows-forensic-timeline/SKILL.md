---
name: windows-forensic-timeline
description: "Windows 主机取证时间线：定位样本落地时刻、落地物、持久化位置与外联痕迹，固化日志清除与勒索加密锚点，全程只读取证、不改主机配置。适用于拿到被入侵 Windows 主机（通常只有远程 shell/SSH 通道）后回答什么时候落地的、放了什么、怎么持久化、外联到哪、是否清过日志，产出时间线表、IOC 清单与证据包。"
metadata:
  tags: ["溯源", "windows", "时间线", "持久化", "应急响应"]
  version: "1.0.0"
---

# Windows 主机取证时间线（远程只读溯源）

回答「什么时候落地 → 放了什么 → 怎么持久化 → 外联到哪 → 是否清过日志」，只读取证、不改主机配置。

## 适用条件

- 线索：随机命名目录/进程、同名 exe 多实例、杀软装不上、防火墙三档关闭、日志被清、勒索信与批量加密文件。
- 前置（缺一项先问）：主机 IP/主机名、Windows 版本、远程通道（SSH / WinRM / 现成 shell）、管理员权限、**主机本地时区**、案例目录 `<case-dir>`、已授权范围。
- 不适用：无授权、非目标主机；需其它主机或边界设备数据时转补证清单。

## 证据要求

1. 主机标识：`hostname`、`systeminfo` 域与序列号、主 IP，绑定案例目录。
2. 采集时刻：本地时间 + UTC + 偏移 + 采集者。
3. 命令原文与原始输出各落一文件 `<case-dir>/raw/<tag>__<name>.txt`，首行 `$ <命令原文>` 与 `[rc=]`；**禁止只贴屏幕摘要**。
4. 长输出先落远端 `C:\Windows\Temp\<out>\` 再取回，不用管道截断（缓冲易卡死）。
5. 样本/驱动/策略/任务 XML/注册表导出：SHA-256 + 大小 + 绝对路径 + 采集时刻 → `<case-dir>/sample-manifest.csv`。
6. 可信度：主机原始日志 > 主机应用日志 > 第三方采集包 > 边界设备与云端。

## 工具顺序

### 1. 建通道（本地侧）

用 `write_file` 落 `scripts/win_remote_collect.py`，`execute` 以环境变量传参（主机、账号、口令、案例目录外部注入，禁止写死）：

```
export TRACE_HOST=<target-ip> TRACE_USER=<user> TRACE_RAW=<case-dir>/raw
python scripts/win_remote_collect.py whoami
```

逐条执行，**每条命令必须有硬性 deadline**（轮询 + 到点关通道返回部分输出），否则 `recv_exit_status()` 会永久阻塞；TCP 通但无 banner（重启/瞬断）时跑间隔 30s 的重试自动补采。

### 2. 一次性初筛（批量落盘）

```
whoami /all & net user & net localgroup administrators
netstat -ano & ipconfig /all & arp -a & ipconfig /displaydns
powershell -NoProfile -Command "Get-Process | Select Id,ProcessName,Path,Company,StartTime | Sort StartTime | Export-Csv C:\Windows\Temp\out\proc.csv -NoTypeInformation -Encoding UTF8"
powershell -NoProfile -Command "Get-NetTCPConnection | Select LocalPort,RemoteAddress,RemotePort,State,OwningProcess | Export-Csv C:\Windows\Temp\out\tcp.csv -NoTypeInformation"
netsh advfirewall show allprofiles
powershell -NoProfile -Command "Get-MpComputerStatus | Select AMRunningMode,AntivirusEnabled,RealTimeProtectionEnabled"
```

判读：恶意目录名伪装大厂（`Company` 与路径不符）、同名多实例为看门狗；Defender `Not running` + 三档关闭 = 出联不受阻且不留历史连接。

### 3. 落地时刻（核心产出）

```
powershell -NoProfile -Command "Get-Item 'C:\path\payload.exe' | Select CreationTime,LastWriteTime,Length"
dir /a /tc C:\Windows\System32\Tasks | findstr /i "<任务名关键字>"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist" /s
dir /a /tw C:\Windows\Prefetch\*.pf
copy /y C:\Windows\AppCompat\Programs\Amcache.hve <case-dir>\Amcache.hve
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
fsutil usn queryjournal C:
```

- 优先级：MACB 的 `CreationTime`（木马一般不改）→ 任务文件创建时间（= 自动化投放）→ System `7045/7040/1000/1` → 浏览器下载记录。
- 浏览器库 `C:\Users\<user>\AppData\Local\Microsoft\Edge\User Data\Default\History`（SQLite），跑 `scripts/browser_history_timeline.py` 取 `downloads/urls/visits`；**Chrome/Edge 时间 = 1601-01-01 起的微秒且为 UTC**，换成主机本地时区；下载完成与文件创建相差几分钟内即可疑。
- USN：先看覆盖范围（默认 32MB，常只留最近几天），覆盖不到就别投入；覆盖时 `fsutil usn readjournal C: csv | findstr /i "<关键字>"`。
- $MFT：线上不跑第三方 raw 解析器；用 `vssadmin list shadows` + `mklink /d` 挂载卷影**只读比对**。
- UserAssist / Prefetch / Amcache / ShimCache / SRUM 的键位与时间换算见 `references/timeline-artifacts-and-event-ids.md`。

### 4. 持久化全枚举

```
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell
powershell -NoProfile -Command "Get-CimInstance Win32_SystemDriver | Where-Object { $_.PathName -and $_.PathName -notmatch '(?i)System32\\drivers|DriverStore' } | Select Name,State,StartMode,PathName"
powershell -NoProfile -Command "Get-ScheduledTask | ForEach-Object { $t=$_; $t.Actions | Where-Object { $_.Execute -and $_.Execute -notmatch '(?i)^(C:\\Windows|C:\\Program Files)' } | ForEach-Object { Write-Output ($t.TaskPath+$t.TaskName+' | '+$_.Execute+' '+$_.Arguments) } }"
powershell -NoProfile -Command "Get-CimInstance -Namespace root\subscription -Class __EventFilter,CommandLineEventConsumer,ActiveScriptEventConsumer,__FilterToConsumerBinding"
dir /a "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
```

- Run 键**整键打印**：值名会仿冒正常项（`SecurityHealth` 旁多出 `Tencent SecurityHealth`），findstr 会漏。
- 计划任务看动作路径不看名字；`Hidden=true` + `Repetition PT1M` + `RunLevel Highest` 为典型组合。
- **内核驱动单独查**（`Win32_Service` 不含驱动），否则漏 BYOVD；另扫 WMI 事件订阅、三处启动文件夹、`Winlogon Shell/Userinit`、`Win32_StartupCommand`。
- “杀软装不上”的成因、判定表与命令见 `references/persistence-and-avkiller-artifacts.md`。

### 5. 外联到哪

```
ipconfig /displaydns
powershell -NoProfile -Command "Get-NetTCPConnection -State Established | Select RemoteAddress,RemotePort,OwningProcess"
get-content "C:\ProgramData\<vendor>\*.log" -Tail 300
```

- 防火墙通道**不含连接级五元组**（只 2002~2011 规则类），不能证明外联。
- 远控明文日志：入站连接请求 + 认证成功 + `LaunchSession`/`start session video` 成组才算有会话；当天无会话不留 session 日志；`*.xlog/*.mmap3` 加密（熵 8.0），别耗时。
- 线索优先级：浏览器 History → DNS 缓存 → 应用日志（IIS `c-ip`、MSSQL ERRORLOG `[CLIENT: x.x.x.x]`）→ 安全软件拦截日志。
- 查不到 IP 时写“主机不保留出站历史”，转边界设备日志比对；口径见 `references/attacker-ip-attribution.md`。

### 6. 日志清除与加密锚点

```
wevtutil qe Security /q:"*[System[(EventID=1102)]]" /f:text /c:20
wevtutil qe Application /q:"*[System[(EventID=104)]]" /f:text /c:50
powershell -NoProfile -Command "Get-WinEvent -FilterHashtable @{LogName='System';Id=6005,6006,6009,1074,1076,6013,7031,7034,7000,7011} -MaxEvents 300 | Select TimeCreated,Id,ProviderName | Sort TimeCreated"
dir /s /b C:\*_readme.txt C:\RECOVERY*.txt
```

- **1102**（审核日志被清）+ **104**（日志文件被清）；同秒反复被清几十到几百次 = 加密器/批处理特征；清空时刻**之前不可回溯**，报告须写明，别把“查不到入口”写成“没有入口”。
- **6013** 给“系统已启动 N 秒”，用采集时刻倒推开机时间；窗口内 6005/6006/6009/1074/1076 全为 0 且关键 PID 跨天未变 = **未重启**（“服务以新实例启动”常只是看门狗拉起被杀进程）。
- 加密前置链：安全软件等待超时/启动失败（7011/7000）→ 杀软组件意外终止（7031/7034 ×N）→ 数据库服务意外停止 → 远控服务意外终止；勒索信与 `*.<扩展名>` 的 mtime = 加密可信下限，勒索信常每目录一份，是最好的样本。
- 代码完整性策略被投放：`CiTool -lp -json`，未签名 + `IsEnforced=true` + `PolicyOptions` 含 `Enabled:UMCI` 即恶意；`winsrvext` 的 `100`（进程延迟关机）正常关机也有，不是恶意项。
- 完整事件 ID 与判读见 `references/timeline-artifacts-and-event-ids.md`。

### 7. 固证（不动配置）

```
wevtutil epl System <case-dir>\evt\System.evtx
reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" <case-dir>\reg\Run.reg /y
powershell -NoProfile -Command "Get-Acl 'C:\path' | Format-List"
certutil -hashfile "C:\path\payload.exe" SHA256
vssadmin list shadows
```

本地侧用 `ls`/`glob` 清点证据、`grep` 过滤、`read_file` 复核，清单用 `write_file`/`edit_file` 维护。

样本只读复制回本机打包，目标机上**只移动不删除**（隔离目录 `C:\Quarantine_<日期>\`）；取时间戳用 `Get-Item | Select CreationTime,LastWriteTime,LastAccessTime`，避免污染 MACB。

## 停止条件

- 「落地时刻 + 落地物 + 持久化 + 外联（或明确否定）」可答即停；不做全盘扫描。
- 处置动作（结束进程、停/删服务与驱动、删任务与 Run 值、改策略、隔离主机、阻断外联）先出方案走审批。
- 通道不可用、无管理员权限、证据被内核态保护 → 停，转人工现场脚本。
- USN 覆盖不到、Amcache/SRUM 成本高 → 先问用户，不长时间占用主机。
- 需边界设备/云端/采集包明文 → 停，产出补证清单交用户。

## 输出格式

- 三分：`事实`（有原始输出支撑）/ `推断`（依据 + 置信度）/ `待验证`（缺什么证据、找谁要）。
- 时间线表：`时间(本地+UTC) | 阶段 | 事件 | 证据来源 | 置信度`；阶段：投毒入口 → 文件释放 → 持久化 → 执行/内核驱动 → 外联 → 日志清除 → 加密 → 处置。
- IOC：绝对路径、SHA-256、服务/驱动名、任务路径与名、Run 键名、域名/IP、签名主体。
- 附件：`raw/`、`evt/`、`reg/`、`sample-manifest.csv`、样本包（SHA-256 写清单首行）。
- 未闭合项单列，写明需用哪台设备/哪类日志补证，不与结论混写。
- **己方机器与操作不进交付物**：自身 IP、登录、装软件、跑采集器只留内部笔记。
- 答“有没有 X”先穷举再断言：导出相关通道按时间窗过滤去重，给命令与结果，用“证据 + 否定结论”写法。

## 红线与审批

- 只读直接做：查时间、导日志、`reg query`、`Get-*`、算哈希、只读复制样本、导出 ACL、列举任务/驱动。
- 需审批后做：任何终止/禁用/删除（进程、服务、驱动、计划任务、Run 值、文件）、隔离主机、阻断外联、改注册表/策略/启动项、重启或进安全模式、上传下载工具与样本。
- **禁止**：删非恶意文件；尝试任何口令（含哈希爆破）；对非目标主机发起连接或扫描；把边界设备/云端日志当本机证据；凭印象下“没有/不可得”的结论。
