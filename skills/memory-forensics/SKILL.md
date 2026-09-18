---
name: memory-forensics
description: "内存取证与主机溯源：当事件响应需要从内存镜像确认进程隐藏、代码注入、异常模块、C2 外联、命令历史与凭据暴露痕迹并重建时间线时使用；覆盖镜像采集方式与哈希登记、Volatility 3 分析序列、Volatility 2 差异、malfind 注入判定、模块与句柄核对、与 PCAP 交叉验证；产出事实/推断/待验证三分清单、IOC 与时间线、置信度及处置建议。"
metadata:
  tags: ["溯源", "内存取证", "volatility", "windows", "linux"]
  version: "1.0.0"
---

# 内存取证与主机溯源

内存镜像回答三问：**有没有隐藏进程或被注入的代码、它和谁通信、它在磁盘上留了什么**。

## 适用条件

- 主机疑似被入侵：异常外联、窃密、挖矿、持久化被改、日志被清、即将重启或被隔离；线索如 EDR 告警进程名可疑、进程列表正常但资源占用异常、出现陌生外联。
- 加载前必须问清：主机标识与 OS/内核版本；镜像路径、格式（raw/lime/aff4/vmem）、字节数、**采集方式与采集工具版本**；采集时刻（中招前/后）；同段 PCAP、磁盘镜像、EDR 日志是否可得；访问方式（主机通道 SSH/WinRM，或只有镜像文件）。
- 只有镜像时全流程离线执行；镜像仍在目标主机上时，先做第 0 步登记与哈希，再拷副本分析。

## 证据要求

落盘 `<case-dir>/evidence/<hostname>/`，并在 `<case-dir>/notebook.md` 逐条登记：

| 项 | 要求 |
|---|---|
| 镜像 | 采集方式（WinPmem/LiME/AVML/DumpIt/虚拟化平台 dump）、工具名与版本、**主机内存总大小**、文件字节数 |
| 哈希 | 采集后立即 `sha256sum` 或 `Get-FileHash -Algorithm SHA256` 写入清单；每次复制/转换后再校验并注明 |
| 时间 | 采集起止时间**带时区**（`2026-01-02T03:04:05+08:00`）；主机系统时钟与真实时间的偏差单独记录 |
| 命令与输出 | 完整命令行（`-f`、插件、`--pid`、转储目录、重定向）与插件 stdout 原文；`grep` 结果另存，不覆盖原始输出 |
| 定位 | 结论须指回对象：`pslist` 的 PID 与 `Offset(V)`、`malfind` 的 `Start VPN`/`Tag`、`netscan` 的 `Offset(P)`、`dumpfiles` 的 `Virtual` |
| 可信度 | 标明来自内存（易失、可被反取证篡改）还是磁盘/日志 |

原始镜像只读，分析基于副本；二次采集的镜像作为独立证据，不替代第一次。

## 工具顺序

命令以 Volatility 3（`vol3`）为主，Volatility 2 差异见本节末尾。

### 第 0 步 登记与哈希

```bash
ls -l <case-dir>/images/
sha256sum <case-dir>/images/mem.raw | tee <case-dir>/evidence/<hostname>/image.sha256
stat -c '%n %s bytes %y' <case-dir>/images/mem.raw
# Windows 采集机：Get-FileHash -Algorithm SHA256 <case-dir>\images\mem.raw
```

采集方式、内存大小、哈希三项先写进清单。

### 第 1 步 识别系统

```bash
vol3 -f mem.raw banners.Banners
vol3 -f mem.raw windows.info
vol3 -f mem.lime linux.info
```

与现场描述不符时先核对镜像来源，不要外推。

### 第 2 步 进程与隐藏进程

```bash
vol3 -f mem.raw windows.pslist > out/pslist.txt
vol3 -f mem.raw windows.psscan > out/psscan.txt
vol3 -f mem.raw windows.pstree  > out/pstree.txt
vol3 -f mem.raw windows.cmdline > out/cmdline.txt
diff <(awk 'NR>2{print $1,$2}' out/pslist.txt|sort -u) <(awk 'NR>2{print $1,$2}' out/psscan.txt|sort -u)
```

- `psscan` 有、`pslist` 无 → 进程已从 EPROCESS 活动链表摘除（DKOM 隐藏），高置信恶意。
- `pslist` 有、`psscan` 无 → 多为采集中刚退出的陈旧对象，降级为线索。
- 父子异常：`svchost.exe` 非 `services.exe` 子进程；`lsass.exe` 非 `wininit.exe` 子进程；`cmd.exe`/`powershell.exe` 由办公软件、浏览器或 Web 服务进程拉起。
- 路径落在 `\Users\<user>\AppData\Local\Temp\`、`\ProgramData\`、`C:\Windows\Temp\` 且文件名为随机串。
- 正常基线：`System(4)→smss.exe→csrss.exe/wininit.exe`；`wininit.exe→services.exe→svchost.exe/spoolsv.exe`、`→lsass.exe`；`winlogon.exe→explorer.exe→用户程序`。

### 第 3 步 代码注入（malfind）

```bash
vol3 -f mem.raw windows.malfind > out/malfind.txt
vol3 -f mem.raw windows.malfind --pid <pid> --dump -D out/malfind_dump/
vol3 -f mem.raw windows.vadinfo --pid <pid>
```

命中特征：区域可执行权限且**无磁盘映射文件**；起始有 `MZ` 头为疑似反射式 PE 注入，无 PE 头为裸 shellcode。用 `--dump` 落盘并做 `sha256sum`。误报来源：.NET JIT、`clr.dll`、加壳软件、安全产品模块，必须结合第 2、5 步再下结论。

### 第 4 步 模块 / DLL / 驱动

```bash
vol3 -f mem.raw windows.dlllist --pid <pid>
vol3 -f mem.raw windows.ldrmodules --pid <pid>    # 三个 in*Load 列全 False = 未链接
vol3 -f mem.raw windows.modules
vol3 -f mem.raw windows.modscan                   # 与 modules 对比
vol3 -f mem.raw windows.driverscan
vol3 -f mem.raw windows.callbacks                 # 非微软模块注册的内核回调
```

`modscan` 有、`modules` 无 → 隐藏或已卸载驱动残留；DLL 在 `ldrmodules` 三列全 False → 反射式加载。

### 第 5 步 网络连接

```bash
vol3 -f mem.raw windows.netscan > out/netscan.txt
vol3 -f mem.raw windows.netstat
grep -vE '127\.0\.0\.1|0\.0\.0\.0|::1|\[::\]' out/netscan.txt
```

把连接与 PID、进程路径对齐，找"陌生进程 + 对外 443/8443/53/高位端口"组合；记录 `Offset(P)`、本地/远端 `IP:port`、状态、创建时间作为与 PCAP 交叉验证的锚点（转 `pcap-traffic-analysis`）。`netscan` 保留已关闭连接，不能反证未外联。

### 第 6 步 命令历史

```bash
vol3 -f mem.raw windows.cmdline
vol3 -f mem.raw windows.consoles
vol3 -f mem.raw windows.envars --pid <pid>
vol3 -f mem.raw windows.clipboard
vol3 -f mem.lime linux.bash
vol3 -f mem.lime linux.tty_check
```

重点模式：`-enc`/`-nop`/`-w hidden` 的 PowerShell、`certutil -urlcache -f`、`bitsadmin /transfer`、`curl`/`Invoke-WebRequest` 下载、`net user`/`sc create`/`schtasks /create`、`wmic process call create`。

### 第 7 步 凭据暴露痕迹（只确认暴露面）

```bash
vol3 -f mem.raw windows.hashdump > out/hashdump.txt
vol3 -f mem.raw windows.lsadump
vol3 -f mem.raw windows.cachedump
```

目的是判断凭据是否已被读取、需轮换哪些账号。报告只写账号名与是否存在记录，不写完整哈希；原始文件加密存放。禁止对哈希爆破、离线破解或重放。

### 第 8 步 文件与持久化

```bash
vol3 -f mem.raw windows.filescan | grep -iE '\.(exe|dll|ps1|bat|vbs|js|lnk|zip|7z|kdbx)$'
vol3 -f mem.raw windows.dumpfiles --virtaddr <virtaddr>
vol3 -f mem.raw windows.registry.hivelist
vol3 -f mem.raw windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"
vol3 -f mem.raw windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\RunOnce"
vol3 -f mem.raw windows.registry.userassist
```

落盘文件逐个 `sha256sum`，报告中给出 `Virtual` 地址与提取路径，便于与磁盘镜像比对。

### 第 9 步 时间线

```bash
vol3 -f mem.raw timeliner.Timeliner --output-file out/timeline.body --output body
mactime -b out/timeline.body -d > out/timeline.csv
```

只保留执行（`pslist`/`userassist`）、落地（`filescan`/`dumpfiles`）、外联（`netscan`）三类事件；重点看"进程启动后即外联"。

### 第 10 步 Linux rootkit 方向

```bash
vol3 -f mem.lime linux.pslist
vol3 -f mem.lime linux.elfs
vol3 -f mem.lime linux.check_syscall
vol3 -f mem.lime linux.check_afinfo
vol3 -f mem.lime linux.check_modules
```

### Volatility 2 差异

| 概念 | Volatility 2 | Volatility 3 |
|---|---|---|
| 环境 | Python 2，需 `--profile=Win10x64_19041` | Python 3，符号表自动匹配 |
| 识别 | `imageinfo` / `kdbgscan` | `windows.info` / `banners.Banners` |
| 进程 | `pslist` / `psscan` / `pstree` | `windows.pslist` / `windows.psscan` / `windows.pstree` |
| 注入 | `malfind -D dir` | `windows.malfind --dump -D dir` |
| 模块 | `dlllist` / `ldrmodules` | `windows.dlllist` / `windows.ldrmodules` |
| 网络 | `netscan`（XP 用 `connections`/`connscan`） | `windows.netscan` / `windows.netstat` |
| 转储 | `dumpfiles -Q <offset>` | `windows.dumpfiles --virtaddr <addr>` |
| 注册表 | `hivelist` / `printkey -K "path"` | `windows.registry.hivelist` / `printkey --key "path"` |
| 时间线 | `timeliner --output=body` | `timeliner.Timeliner` |

坑位：Vol2 profile 选错时 `psscan` 会**静默返回空**而不报错，profile 必须取自 `imageinfo` 的 Suggested Profile；Vol3 插件名带 `windows.`/`linux.` 前缀，照抄旧写法会失败。

## 停止条件

- 三问有答案即停：①有无隐藏进程/注入/未链接模块；②外联对象与时间；③落地文件与持久化痕迹。
- 命中审批项且未获批 → 停在该步，只输出事实与方案。
- 同一插件两次结果不一致（镜像不稳或截断）→ 记录差异、复核镜像哈希后停止外推。
- 结论足以判恶并支撑处置即停；无新线索时不把全部插件跑一遍。插件报 `unsupported`、符号表缺失、镜像不完整 → 记录后停止，改用磁盘与日志证据。

## 输出格式

写 `<case-dir>/report.md`：

- **事实**：命令 + 原始输出路径 + 定位。例：`windows.malfind` 命中 PID 4596，`Start VPN 0x00007ff600380000`、`Tag VadS`，转储 `out/malfind_dump/pid.4596...dmp`。
- **推断**：事实 → 结论的推理链 + 置信度（高/中/低）。例：区域可执行且无磁盘映射 → 推断反射式注入，置信度 高。
- **待验证**：需哪些外部证据才能定论（哪个日志、哪个磁盘路径、哪段 PCAP）。

附：①时间线（UTC；时间/主机/事件/来源/定位）；②IOC 清单（文件哈希、落地路径、远端 IP:port、注册表键、服务与计划任务名）；③凭据暴露评估（受影响账号与轮换建议）；④建议动作（只读项先做，处置项走审批）。

## 红线与审批

- 只读可直接做：跑 Volatility 插件、`sha256sum`、读镜像副本、导出文件与进程列表。
- 先出方案再审批：终止进程、禁用或删除服务与驱动、改注册表与启动项、隔离主机、阻断外联、下载或外带样本、重启主机。
- 禁止：对哈希爆破、离线破解或重放；删除任何非恶意文件（含"疑似"文件）；对非目标主机发起连接或扫描；把真实哈希与凭据原文写进报告或外传。
- 镜像按证据保管：只读、留 SHA-256、限定访问；处置前先做副本。
