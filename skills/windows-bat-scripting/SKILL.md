---
name: windows-bat-scripting
description: "中文 Windows 批处理脚本编写与执行：当需要向 Windows 主机下发 .bat 采集脚本或处置脚本（一键取证、搬文件、清任务、装/停服务）时，规避 GBK 编码、CRLF、BOM、chcp 换码页、多行括号块、管理员检测、服务与配置可还原等坑，保证脚本一键跑通、失败可见、可幂等重跑。"
metadata:
  tags: ["windows", "bat", "脚本", "中文编码", "应急响应"]
  version: "1.0.0"
---

# 中文 Windows 批处理脚本编写规则

## 适用条件

- 需要向目标 Windows 主机（Win10/11/Server，多为中文系统）下发 `.bat`：一键采集脚本（日志/进程/持久化/文件清单）、处置脚本（移动文件、清计划任务、装停服务），或需要用户在主机本地双击运行的脚本。
- 前置：`<target-ip>`、系统版本与默认代码页（中文系统多为 936）、脚本落地路径、当前会话权限、是否存在中文路径与中文输出、主机通道是否可用（安全模式下通道常不可用，只能人工本地执行）。
- 用 `write_file` 把脚本写到 `<case-dir>/scripts/`，经主机通道用 `execute` 下发；下发后用 `execute` 复核主机侧字节，本地用 `grep`、`glob`、`read_file` 检查产物。

## 证据要求

- 脚本本体与其 SHA-256、下发方式与时间、执行账号与权限、退出码，随证据一起落盘（`<case-dir>/scripts/` 与 `<case-dir>/raw/`）。
- 脚本必须自己写运行日志（`>> "%LOG%" 2>&1`），日志与脚本一一对应；运行后把日志取回本地、按 GBK 解码再 `grep`，不得只看"跑过了"。
- 凡改动主机状态的动作（改配置、装停服务、删账户、移动文件），执行前备份原件（`<文件名>.orig-kit`）、执行后记录还原方式；备份必须幂等（`if exist <备份> goto BK_DONE` 守卫），避免二次运行用自己的输出覆盖真备份。
- 写盘后必须复核字节级事实：行尾全为 CRLF、无 BOM、编码为 GBK（或纯 ASCII）。这些是事实，不是假设。

## 工具顺序

1. 编码与行尾（最优先）
   - 正文用 GBK(cp936) 编码 + CRLF + 无 BOM，首行 `chcp 936 >nul 2>&1`。LF-only 会被 cmd 拆错行（`'xxx' 不是内部或外部命令`）；BOM 会让 `@echo off` 失效。
   - `write_file` 之后用 `execute` 跑转码脚本兜底：
     ```python
     t = text.replace("\r\n", "\n").replace("\n", "\r\n")
     open(dst, "w", encoding="gbk", newline="").write(t)
     raw = open(dst, "rb").read()
     assert raw.count(b"\n") == raw.count(b"\r\n") and raw[:3] != b"\xef\xbb\xbf"
     ```
2. `chcp` 会改变后续行的解码代码页
   - 文件内含中文路径/中文文本 → 用 GBK 编码且不要再切 65001；确需 UTF-8 控制台时，该 `.bat` 必须纯 ASCII，中文路径交给通配符或参数找：`for /d %%D in ("%~dp004-*") do if not defined P set "P=%%~fD\x.ps1"`。
   - 典型症状：GBK 文件里写了 `chcp 65001`，紧随其后的中文路径按 UTF-8 解码成乱码，`-File` 参数报路径不存在。
3. 绝不用多行括号块
   - `if ... ( ... )` 块内 `echo` 出现半角 `)`（如 `echo 失败(原因)`）会被当作块结束符，解析失败、窗口闪退，连 `pause` 都执行不到。改用 `goto` 标签流程：
     ```bat
     net session >nul 2>&1
     if errorlevel 1 goto NOT_ADMIN
     goto MAIN
     :NOT_ADMIN
     echo 请右键以管理员身份运行
     pause
     exit /b 1
     :MAIN
     ```
   - 要输出括号用全角 `（）`，或不写括号。
4. 管理员检测要双保险
   - `net session` 依赖 Server 服务，被优化禁用时会把管理员误判为普通用户：
     ```bat
     fsutil dirty query %SystemDrive% >nul 2>&1
     if not errorlevel 1 goto ADMIN_OK
     net session >nul 2>&1
     if not errorlevel 1 goto ADMIN_OK
     goto NOT_ADMIN
     ```
   - 检测不到权限时提示"请以管理员身份运行"并 `pause`，绝不静默退出；失败分支先打印日志尾部 `powershell -NoProfile -Command "Get-Content '<log>' -Tail 15"`。
5. 标记文件与服务状态的判据
   - `echo 文本 > file` 会在文件里留尾随空格；写标记统一用 `>"file" echo KEY`，判读用 `findstr /l "KEY" file`，不要 `set /p` 读入后比对（会带进 `\r`）。
   - 服务是否启动看**状态查询**，不看返回码：`net start` 可能返回非零码但服务已启动；用 `sc query <svc> | findstr /i "RUNNING"` 作判据，`if errorlevel 1 goto START_FAIL`。服务卡在 `START_PENDING` 时 `sc stop` 报 1052，可先 `taskkill /F /IM <proc>.exe` 清进程再启动。
6. 修改系统状态必须可还原
   - 改配置文件（如 `C:\ProgramData\ssh\sshd_config`，Windows OpenSSH **服务**只认这个路径，脚本目录旁的便携配置对服务无效）前先备份，改完用 `sshd.exe -t -f <config>` 校验语法，比事后排 `START_PENDING` 快得多。
   - 不要照抄 Linux 配置模板：`SyslogFacility AUTHLOG` 在 Windows 端口报 `unsupported log facility`，sshd 起不来、服务停在 `START_PENDING`；配置项名多一个或多个字母会直接 `Bad configuration option`，别照抄 Linux 样例。
   - 目标机可能已有系统自带的 sshd（关系到溯源通道能否使用）：检测到就复用、只备份配置；卸载时只还原配置，不卸载服务、不删 `ProgramData`。用 `.kit-state` 标记 PREEXIST/NEW 区分两条路径。
   - 脚本中涉及账户状态变更或主动外连的语句，在测试机上验证时必须先屏蔽，避免把自己所在会话锁在外面。
7. 配套 `.ps1` 必须 UTF-8 带 BOM
   - PowerShell 5.1 读无 BOM 的 `.ps1` 会按 ANSI(936) 解码，中文注释与中文输出全变乱码：
     ```python
     open(dst, "wb").write(b"\xef\xbb\xbf" + text.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8"))
     ```
   - 改完先做语法预检，比运行后猜错行号快：
     ```powershell
     $e=$null;$t=$null;[System.Management.Automation.Language.Parser]::ParseFile('C:\path\a.ps1',[ref]$t,[ref]$e)|Out-Null
     if($e.Count){$e|%{"ERR line $($_.Extent.StartLineNumber): $($_.Message)"}}else{'PARSE OK'}
     ```
   - 部分编辑工具改写文件后会丢 BOM，改完复查 `raw[:3] != b'\xef\xbb\xbf'` 之类的字节事实。
8. 执行与验证
   - 需要管理员权限时抓输出：`powershell -NoProfile -Command "Start-Process cmd -ArgumentList '/c <script> > <out.txt> 2>&1' -Verb RunAs -Wait"`，再 `iconv -f GBK -t UTF-8 <out.txt>` 读中文输出。
   - 包装脚本自身也要 CRLF；用 `call "%%f" < nul` 传递 EOF 让 `pause`/`set /p` 自动跳过；中文文件名用 `for %%f in (1-*.bat)` 通配规避编码问题。

## 停止条件

- 脚本跑通、日志与产物可逐条核对即停；出现下列情形停下上报：
- 需要管理员权限但无法取得（UAC 关闭且当前为普通用户时没有可用手段）→ 交回用户手动执行，不做旁路尝试。
- 需要改系统配置/服务/驱动/账户（清残留、卸载、改账户状态）而用户未确认 → 只交付脚本与还原方案，等审批。
- 脚本行为可能影响业务（重启、停服务、移动业务目录、全盘扫描）→ 先报影响面与执行时间窗。
- 连续两次重跑结果不一致（幂等被破坏）→ 停止重试，先查清状态漂移原因。

## 输出格式

- 交付物：脚本本体（`<case-dir>/scripts/<名称>.bat`）、SHA-256、下发与运行命令、预期产物路径、运行日志路径。
- 运行结果分三段：`事实`（实际输出、退出码、日志原文）、`推断`、`待验证`。
- 每个坑位写"症状 → 判据 → 修复"，并注明本次实际验证过的现象（例如"改名探针报拒绝访问"）；未验证的不要写成结论。
- 改动过的主机状态列还原清单：原值、新值、还原命令、是否需要重启。

## 红线与审批

- 只读采集脚本可直接执行；任何写操作脚本（改配置、装停服务、移动或删除文件、改注册表、改账户）先提交脚本内容与还原方案，审批后再执行。
- 脚本中禁止：删除非恶意文件、尝试任何口令、对非目标主机发起连接或扫描、覆盖业务数据、静默失败退出（必须 `pause` 并打印日志尾部）。
- 脚本必须可幂等重跑；改动的系统状态（配置、服务、账户、回滚点）必须可还原，不可还原的动作不写进脚本。
- 提交前自查：CRLF、无 BOM、编码、是否有括号块、管理员检测、每条失败分支是否都有提示与日志。
