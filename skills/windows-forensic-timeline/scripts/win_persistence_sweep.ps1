<#
.SYNOPSIS
  Windows 持久化与防御面「只读」枚举脚本：把结果落盘成文本，供离线分析与出报告。

.DESCRIPTION
  在目标 Windows 主机上以管理员身份运行。脚本只做查询与导出，不修改任何配置、
  不删除任何文件、不结束任何进程。所有输出写入 -OutDir 指定的目录（默认
  C:\Windows\Temp\htai-sweep-<时间戳>），随后由本地侧取回。

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File win_persistence_sweep.ps1 -OutDir C:\Windows\Temp\out
#>
param(
    [string]$OutDir = ("C:\Windows\Temp\htai-sweep-" + (Get-Date -Format "yyyyMMdd-HHmmss")),
    [int]$Days = 60
)

$ErrorActionPreference = "SilentlyContinue"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$log = Join-Path $OutDir "_sweep.log"

function Write-Step {
    param([string]$Name, [scriptblock]$Block)
    $path = Join-Path $OutDir ($Name + ".txt")
    try {
        & $Block | Out-String -Width 4096 | Set-Content -Path $path -Encoding UTF8
        Add-Content -Path $log -Value ("[ok]   {0} -> {1}" -f $Name, $path)
    } catch {
        Add-Content -Path $log -Value ("[FAIL] {0} : {1}" -f $Name, $_.Exception.Message)
    }
}

Add-Content -Path $log -Value ("host={0} user={1} start={2} tz={3}" -f $env:COMPUTERNAME, $env:USERNAME, (Get-Date -Format s), (Get-TimeZone).Id)

# 1. 主机标识与基础信息
Write-Step "01_identity" {
    hostname
    whoami /all
    systeminfo | Select-String -Pattern "Host Name|OS Name|OS Version|System Boot Time|Domain|Product ID|Original Install Date|Time Zone"
    Get-TimeZone | Select-Object Id, DisplayName, BaseUtcOffset
    (Get-Date).ToUniversalTime()
}

# 2. 进程 / 网络快照
Write-Step "02_process" { Get-Process | Select-Object Id, ProcessName, Path, Company, Description, StartTime | Sort-Object StartTime }
Write-Step "03_net" {
    Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
    netstat -ano
    arp -a
    ipconfig /displaydns
}

# 3. 持久化：Run 键 / 启动项 / 启动文件夹 / 计划任务
Write-Step "04_run_keys" {
    @(
        "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    ) | ForEach-Object { "=== $_"; reg query $_ }
    "=== Winlogon"
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit
    "=== UserAssist"
    reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist" /s
}
Write-Step "05_startup_folders" {
    @(
        "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
        (Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup")
    ) | ForEach-Object { "=== $_"; Get-ChildItem -Force -Path $_ }
    Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User
}
Write-Step "06_tasks" { Get-ScheduledTask | Select-Object TaskPath, TaskName, State, Author, @{n = "Hidden"; e = { $_.Settings.Hidden } }, @{n = "RunLevel"; e = { $_.Principal.RunLevel } }, Actions }
Write-Step "07_tasks_by_action" {
    Get-ScheduledTask | ForEach-Object {
        $t = $_
        $t.Actions | Where-Object { $_.Execute -and $_.Execute -notmatch "(?i)^(C:\\Windows|C:\\Program Files|%SystemRoot%|%windir%)" } | ForEach-Object {
            "{0}{1} | {2} {3}" -f $t.TaskPath, $t.TaskName, $_.Execute, $_.Arguments
        }
    }
}

# 4. 服务 / 内核驱动
Write-Step "08_services" { Get-CimInstance Win32_Service | Select-Object Name, State, StartMode, PathName, StartName, DisplayName }
Write-Step "09_kernel_drivers" { Get-CimInstance Win32_SystemDriver | Where-Object { $_.PathName -and $_.PathName -notmatch "(?i)System32\\drivers|DriverStore" } | Select-Object Name, State, StartMode, PathName, DisplayName }
Write-Step "10_sc_drivers" { sc.exe query type= driver state= all }
Write-Step "11_filter_drivers" { fltmc filters; fltmc instances }

# 5. 服务/驱动安装事件（时间线用）
Write-Step "12_event_7045" {
    Get-WinEvent -FilterHashtable @{LogName = "System"; Id = 7045; StartTime = (Get-Date).AddDays(-$Days) } -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, @{n = "ServiceName"; e = { $_.Properties[0].Value } }, @{n = "ImagePath"; e = { $_.Properties[1].Value } }, @{n = "StartType"; e = { $_.Properties[3].Value } }
}

# 6. 防御面：Defender / 防火墙 / 代码完整性策略
Write-Step "13_defender" { Get-MpComputerStatus | Select-Object AMRunningMode, AntivirusEnabled, RealTimeProtectionEnabled, TamperProtected, AMServiceEnabled }
Write-Step "14_firewall" { netsh advfirewall show allprofiles }
Write-Step "15_code_integrity" { CiTool.exe -lp -json; Get-ChildItem "C:\Windows\System32\CodeIntegrity\CiPolicies\Active" }

# 7. WMI 事件订阅（无文件落地也能持久化）
Write-Step "16_wmi_subscription" {
    Get-CimInstance -Namespace root\subscription -Class __EventFilter | Select-Object Name, Query, EventNamespace
    Get-CimInstance -Namespace root\subscription -Class CommandLineEventConsumer | Select-Object Name, CommandLineTemplate
    Get-CimInstance -Namespace root\subscription -Class ActiveScriptEventConsumer | Select-Object Name, ScriptText
    Get-CimInstance -Namespace root\subscription -Class __FilterToConsumerBinding | Select-Object Filter, Consumer
}

# 8. 反取证锚点：日志清除 / 关机重启 / 服务意外终止
Write-Step "17_log_cleared" {
    Get-WinEvent -FilterHashtable @{LogName = "Security"; Id = 1102 } -ErrorAction SilentlyContinue | Select-Object TimeCreated, Message
    Get-WinEvent -FilterHashtable @{LogName = "System", "Application"; Id = 104 } -ErrorAction SilentlyContinue | Select-Object TimeCreated, LogName, Message
}
Write-Step "18_shutdown_events" {
    Get-WinEvent -FilterHashtable @{LogName = "System"; Id = 6005, 6006, 6009, 1074, 1076, 6013, 7031, 7034, 7000, 7009, 7011 } -MaxEvents 500 -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, Id, ProviderName
}

# 9. 冻结的瞬时时间线证据（哈希与 ACL）
Write-Step "19_suspicious_paths" {
    @("C:\ProgramData", "C:\Users\Public", "C:\Windows\Temp") | ForEach-Object {
        "=== $_"
        Get-ChildItem -Force -Path $_ | Select-Object FullName, CreationTime, LastWriteTime, Length, Attributes
    }
}
Write-Step "20_manifest" {
    $targets = Join-Path $OutDir "*.txt"
    Get-ChildItem $targets | ForEach-Object {
        "{0}  {1}  {2}" -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash, $_.Length, $_.Name
    }
}

Add-Content -Path $log -Value ("[done] end={0}" -f (Get-Date -Format s))
Get-Content $log
