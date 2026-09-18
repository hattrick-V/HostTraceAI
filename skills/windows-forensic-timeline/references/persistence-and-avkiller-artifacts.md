# 持久化枚举 · BYOVD · 恶意 WDAC · 杀软残留（命令与判定表）

配合 `windows-forensic-timeline` 主文件使用；全部为 Windows 目标机上的**只读**枚举命令（带处置动作的段落已标注）。所有输出先落 `C:\Windows\Temp\<out>\` 或 `<case-dir>` 再取回本地分析。

## 1. 三分钟拿到“持久化全景”

计划任务（按**动作路径**过滤，能抓出伪装成 Edge 更新的任务）：

```
powershell -NoProfile -Command "Get-ScheduledTask | ForEach-Object { $t=$_; $t.Actions | Where-Object { $_.Execute -and $_.Execute -notmatch '(?i)^(%SystemRoot%|%windir%|C:\\Windows|C:\\Program Files|C:\\ProgramData\\Microsoft)' } | ForEach-Object { Write-Output ($t.TaskPath+$t.TaskName+' | '+$_.Execute+' '+$_.Arguments) } }"
```

驱动/服务（**必须单独查内核驱动**，`Win32_Service` 看不到驱动）：

```
powershell -NoProfile -Command "Get-CimInstance Win32_SystemDriver | Where-Object { $_.PathName -and $_.PathName -notmatch '(?i)System32\\drivers|DriverStore' } | Select Name,State,StartMode,PathName | Format-Table -AutoSize"
driverquery /v /fo csv | findstr /i "<关键字>"        :: 含 Services 注册名与路径
sc query type= driver state= all                     :: 内核驱动全量状态
```

近 60 天所有服务/驱动安装（一眼看完全部持久化驱动，正常项一并列出便于对比）：

```
powershell -NoProfile -Command "Get-WinEvent -FilterHashtable @{LogName='System';Id=7045;StartTime=(Get-Date).AddDays(-60)} -ErrorAction SilentlyContinue | Select-Object TimeCreated,@{n='Svc';e={$_.Properties[0].Value}},@{n='Path';e={$_.Properties[1].Value}},@{n='StartType';e={$_.Properties[3].Value}} | Sort-Object TimeCreated | Format-Table -AutoSize"
```

注册表持久化点（Run 键**整键打印**，不要只 findstr 关键字）：

```
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"   :: 当前登录用户 hive 已加载，可直接查
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v Common Startup
```

WMI 事件订阅（文件型无落地文件也能持久化执行）：

```
powershell -NoProfile -Command "Get-CimInstance -Namespace root\subscription -Class __EventFilter | Select Name,Query"
powershell -NoProfile -Command "Get-CimInstance -Namespace root\subscription -Class CommandLineEventConsumer,ActiveScriptEventConsumer | Select Name,CommandLineTemplate,ScriptText"
powershell -NoProfile -Command "Get-CimInstance -Namespace root\subscription -Class __FilterToConsumerBinding | Select Filter,Consumer"
```

其余常被忽略的持久化面：

```
powershell -NoProfile -Command "Get-CimInstance Win32_StartupCommand | Select Name,Command,Location,User"
dir /a "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
dir /a "C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
dir /a "C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" /s
schtasks /query /fo csv /v > C:\Windows\Temp\out\schtasks.csv
```

**对照基线（正常项，别误报）**：`EasyAntiCheat_EOSSys`、`FvKMDSvc`（显卡配套）、各类主板/超频/游戏平台驱动。异常特征 = 路径含 `C:\Windows\Temp\*.jpg`、`C:\ProgramData\<随机>.exe`、`C:\Users\Public\...`、`C:\Program Files (x86)\<6~8 位随机>\`。

判定补充：

- 木马 Run 值名可仿冒正常系统项（`SecurityHealth` 旁多出 `Tencent SecurityHealth`、`Alibaba SecurityHealth`）——**比对相邻正常项**即可识别。
- 计划任务 `Hidden=true` + `Repetition.Interval=PT1M` + `RunLevel=Highest` + `GroupId=S-1-5-32-545(Users)` 是典型木马组合；`Author=Administrator` 的“人类可读英文名”任务多为同一投放脚本产物。
- 时间线里出现“Windows 更新服务被置为已禁用”（`7040`）属于破坏防御，必须写进报告。

## 2. BYOVD（自带合法签名但易被滥用/第三方驱动）

判定信号：

- `7045` 事件的 `BINARY_PATH_NAME` 指向 `C:\Windows\Temp\*.jpg` / `*.dat`，`StartType` 自动启动；
- 驱动文件有**有效签名但不是安全厂商**（例：反 rootkit 工具模块、各类反作弊/超频/硬件监控驱动名）；
- `sc query <svc>` 显示 `STOPPED` + `WIN32_EXIT_CODE 4551` —— 常见于驱动被 WDAC 拦下未能启动（与 §3 联动判断）；
- 木马目录出现 `DENY(DC)` ACL、文件删不动或改名报“拒绝访问”，且普通 ACL 修复无效 —— 说明确有内核态组件在保护。

取指纹（写报告要用）：

```
dir /a /tc "C:\Windows\Temp"
certutil -hashfile "C:\Windows\Temp\<drv>.jpg" SHA256
powershell -NoProfile -Command "$s=Get-AuthenticodeSignature 'C:\Windows\Temp\<drv>.jpg'; $s.Status; $s.SignerCertificate.Subject; (Get-Item 'C:\Windows\Temp\<drv>.jpg').VersionInfo | Format-List CompanyName,FileDescription,ProductName,FileVersion,OriginalFilename"
```

处置（需审批）：`sc stop <svc>` → `sc delete <svc>` → 驱动文件**移动到隔离目录**（不删除）。驱动已 `STOPPED` 时 `sc delete` 立即生效；`sc query` 报 1060 即成功。

## 3. 恶意 WDAC / 代码完整性策略（“杀软杀手”）

### 症状

- 装杀软：安装程序跑完却什么都没装上（程序目录为空、服务注册了但 `STOPPED`、驱动文件在但主程序不在）；
- 运行任意未签名/第三方程序报 **“已被组织的 Device Guard 策略阻止”**；
- Defender `AMRunningMode=Not running`、`AntivirusEnabled=False`，连它自己的 `MpCmdRun.exe` 也被拦。

### 检测

```
CiTool -lp -json            :: 关键字段：PolicyID / FriendlyName / IsSignedPolicy / IsEnforced / IsOnDisk / PolicyOptions
```

恶意策略判定（同时满足）：`IsSignedPolicy=false`、`IsEnforced=true`、`IsSystemPolicy=false`，且 `PolicyOptions` 含 `Enabled:UMCI`。
**内容层面确认**：从 `C:\Windows\System32\CodeIntegrity\SiPolicy.p7b` 提取 UTF-16LE 字符串，会看到被拉黑的杀软目录/进程名清单（各家国产/国外杀软目录与主程序名）。**正规策略永远不会拉黑杀软**，这一条足以定性。

对上事件：`Microsoft-Windows-CodeIntegrity/Operational` 的 `3033`/`3077`（“did not meet the Enterprise signing level requirements … (Policy ID:{...})”）与 `3004`。事件里的 Policy ID 与 `CiTool -lp` 的 `PolicyID` 一致即元凶。

### 处置（可免重启生效，需审批）

```
copy /y "C:\Windows\System32\CodeIntegrity\SiPolicy.p7b" "<隔离目录>\SiPolicy.p7b.bak"
takeown /f "C:\Windows\System32\CodeIntegrity\SiPolicy.p7b"
icacls "C:\Windows\System32\CodeIntegrity\SiPolicy.p7b" /grant *S-1-5-32-544:F
move /y "C:\Windows\System32\CodeIntegrity\SiPolicy.p7b" "<隔离目录>\SiPolicy.p7b(恶意策略).bak"
CiTool -r                  :: 刷新策略；输出“操作成功”，之后 CiTool -lp 里该 PolicyID 消失即已从内核卸载，无需重启
```

验证：再跑一次之前被拦的动作应能正常运行。

### 判读陷阱

- `CodeIntegrity\CiPolicies\Active\*.cip` 里多数是**微软自己签名**的策略（端点安全策略、审计策略、智能应用控制等），`IsEnforced=false` 的都不用管；只有 `IsEnforced=true` 且未签名的才是木马投放。
- 只删盘上策略文件后 `CiTool -lp` 仍显示 `IsEnforced=true, IsOnDisk=false` → 内存里还在跑，必须 `CiTool -r` 或重启。

## 4. 被破坏的杀软残留：装不上也卸不掉

症状：安装程序报“无法写入”；用 `echo ok > "C:\Program Files\<AV>\...\a.txt"` 自测写入被拒，用 `C:\Program Files\~probe\a.txt` 做对照，确认是**路径级**保护而不是权限问题；`net start`/`sc query` 状态自相矛盾（服务键在、`sc query` 报 1060）；卸载程序已被删除。

原因：该杀软自己的**过滤驱动仍在内存中运行**，对自己的安装目录/服务键做自我保护。取证与判定：

```
fltmc filters                                  :: 列表里仍能看到该驱动
fltmc instances | findstr /i <驱动名>           :: 仍 attach 在各卷上
icacls "<驱动文件>"                             :: ACL 正常却仍“拒绝访问” = 内核态保护
Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Services\<svc>"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot" /s /f <驱动名>   :: 是否为安全模式也加载
```

无效做法（别浪费时间，也别写进方案）：

- `fltmc unload <驱动>` → `0x80070005 拒绝访问`（自保护驱动拒绝卸载）；
- `fltmc detach <驱动> C:` → `0x801f0010 此时不要从卷分离筛选器`；
- `sc delete <svc>` → 显示成功，但对**运行中**驱动只是“标记删除”；若服务 `Start=1`（系统启动）且文件仍在，重启后驱动会**再次加载**，保护照旧（实测 `fltmc` 里依旧在）。

有效做法：**安全模式**（驱动未登记在 `Control\SafeBoot` 下就不会加载）。注意安全模式下基于 SSH 的远程通道通常不会启动，**无法远程进入**，因此需要交付一个让用户**手动以管理员身份运行**的清理脚本，并遵守：

1. 管理员权限自检（`fsutil dirty query` + `net session` 双检，非管理员则提示并退出）；
2. `move` 走驱动文件（`<svc>.sys` 及 `*.trashed` 残留、同厂商其它 `.sys`）；
3. `robocopy <杀软目录> <隔离目录> /E /MOVE` 搬走程序目录与 `C:\ProgramData\<AV>`；
4. `sc delete <svc>`（含各失效服务名）；
5. 若 `SiPolicy.p7b` 还在则一并移走；
6. **自证结果**：每一步输出重定向进 `%LOG%`，结尾 `type "%LOG%"` 并 `pause`（你读不到用户侧屏幕）；每步用 `if exist` 守卫，保证异常状态下也能跑完；
7. 提示用户“正常重启后再装杀软”。

## 5. 突破文件级阻塞（DENY ACE / 隐藏属性 / 驱动保护）

典型症状：`dir` 能列出文件，但 `copy`/`ren`/`move` 报“系统找不到指定的文件”或“拒绝访问”。原因通常是给目录写了 **`DENY(DC)`（删除子项）ACE** + 隐藏/系统属性（`icacls` 会显示 `BUILTIN\Users:(OI)(CI)(DENY)(DC)`）。

固定配方（顺序不可换，`move` 不行就用 `robocopy /MOVE`）：

```
takeown /f "<路径>" /r /d y
icacls "<路径>" /remove:d *S-1-5-32-545 /T /C     :: 去 Users 的 DENY
icacls "<路径>" /grant *S-1-5-32-544:(OI)(CI)F /T /C
attrib -s -h -r "<路径>\*" /s /d
robocopy "<路径>" "<隔离目录>\<tag>" /E /MOVE /R:1 /W:1 /NFL /NDL /NJH /NJS
```

坑：

- 对**文件**用 `icacls ... /remove:d <SID> /T` 会顺着历史遗留的 junction（如 `C:\ProgramData\Application Data`）无限递归，输出刷屏后超时 —— **文件不配 `/T`，目录才配**。
- PATH 里用 `*S-1-5-32-545` 这类 SID 写法可避开中文组名编码问题。
- 隔离目录建在 `C:\Quarantine_<日期>\`，并同时保存**任务 XML、Run 键 `.reg` 导出**作为处置证据。
- 处置完后复查：进程 0、恶意端口连接 0、任务 0、Run 键只剩正常项、落地路径全部消失（`Test-Path` 判定），**复查三次**比一次可信。
