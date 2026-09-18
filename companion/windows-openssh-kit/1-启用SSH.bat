@echo off
chcp 936 >nul 2>&1
setlocal EnableDelayedExpansion
title SSH 临时启用 - 溯源用
rem ============================================================
rem  OpenSSH-Win64 多版本自适应启用脚本
rem  兼容: Windows Server 2012 / 2012 R2 / 2016 / 2019 及 Windows 7 / 8 / 8.1 / 10 / 11
rem  原理: 按系统 build 号选一套 OpenSSH, 装到固定目录并做回环自测;
rem        自测失败自动换下一套版本重试, 最后把失败原因(sshd -ddd)打进日志
rem ============================================================

set "ROOT=%~dp0"
set "LOG=%ROOT%ssh-trace.log"
set "CFGDIR=%ProgramData%\ssh"
set "ACCOUNT=administrator"
set "FWNAME=SSH-TRACE-TEMP"
set "KITSTATE=%ROOT%.kit-state"
set "BINROOT=%ROOT%bin"
if not defined SSH_TRACE_INSTDIR set "SSH_TRACE_INSTDIR=%ProgramFiles%\OpenSSH-Win64"
set "INSTDIR=%SSH_TRACE_INSTDIR%"
if not defined SSH_TRACE_PORT set "SSH_TRACE_PORT=22"
set "PORT=%SSH_TRACE_PORT%"
if not defined SSH_TRACE_TESTHOST set "SSH_TRACE_TESTHOST=127.0.0.1"
set "SELFTEST_TMP=%TEMP%\ssh-trace-selftest.txt"
set "DEBUG_OUT=%TEMP%\ssh-trace-debug.out"
set "DEBUG_ERR=%TEMP%\ssh-trace-debug.err"

if /i "%SSH_TRACE_TEST%"=="1" goto TESTMODE

echo ===== %date% %time% 启用 ===== > "%LOG%"

fsutil dirty query %SystemDrive% >nul 2>&1
if not errorlevel 1 goto ADMIN_OK
net session >nul 2>&1
if not errorlevel 1 goto ADMIN_OK
goto NOT_ADMIN

:ADMIN_OK
cd /d "%ROOT%"
echo [i] 工作目录: %CD%
echo [i] 安装目录: %INSTDIR%
echo [i] 端口: %PORT%

echo.
echo [*] 步骤 1/7: 账号 %ACCOUNT%
powershell -NoProfile -Command "if ((Get-LocalUser -Name '%ACCOUNT%' -ErrorAction SilentlyContinue).Enabled) { exit 0 } else { exit 1 }"
if errorlevel 1 goto ACCT_OFF
set "WASON=1"
net user %ACCOUNT% /active:yes >> "%LOG%" 2>&1
goto ACCT_READY
:ACCT_OFF
net user %ACCOUNT% /active:yes >> "%LOG%" 2>&1
if errorlevel 1 goto ACCT_FAIL
:ACCT_READY
if defined SSH_TRACE_PW goto PW_AUTO
if "%WASON%"=="1" goto PW_OPT
goto PW_REQ
:PW_OPT
echo     账号原本就是启用状态。
set /p CHPW=     输入 Y 重设密码, 直接回车跳过: 
if /i "%CHPW%"=="Y" goto PW_REQ
echo [OK] 沿用现有密码
goto PW_OK
:PW_REQ
echo     请为 %ACCOUNT% 设置密码, 回车后输入两次, 输入时不显示:
net user %ACCOUNT% *
if errorlevel 1 goto PW_FAIL
goto PW_OK
:PW_AUTO
net user %ACCOUNT% "%SSH_TRACE_PW%" >> "%LOG%" 2>&1
if errorlevel 1 goto PW_FAIL
:PW_OK
echo [OK] 账号就绪

echo.
echo [*] 步骤 2/7: 检查原有 SSH 服务, 备份原配置
if not exist "%CFGDIR%" mkdir "%CFGDIR%" >> "%LOG%" 2>&1
set "PREEXIST="
set "OWNSVC="
sc query sshd >nul 2>&1
if errorlevel 1 goto SVC_NEW
set "PREEXIST=1"
rem 判断现有 sshd 服务是不是本工具以前装的(install 目录/本脚本目录), 是则接管重装
sc qc sshd > "%TEMP%\ssh-trace-qc.txt" 2>&1
findstr /i /c:"OpenSSH-Win64" /c:"ssh-trace" "%TEMP%\ssh-trace-qc.txt" >nul 2>&1
if not errorlevel 1 set "OWNSVC=1"
>"%KITSTATE%" echo PREEXIST
if exist "%CFGDIR%\sshd_config.orig-kit" goto BK_DONE
if exist "%CFGDIR%\sshd_config" copy /y "%CFGDIR%\sshd_config" "%CFGDIR%\sshd_config.orig-kit" >nul 2>&1
:BK_DONE
echo [i] 本机已有 sshd 服务, 原配置已备份为 sshd_config.orig-kit >> "%LOG%"
if defined OWNSVC echo [i] 该服务指向 OpenSSH-Win64 目录, 判定为以前用本工具装的, 将接管重装 >> "%LOG%"
goto SVC_PREP
:SVC_NEW
>"%KITSTATE%" echo NEW
echo [i] 本机无 sshd 服务, 将由本工具安装 >> "%LOG%"
:SVC_PREP

echo.
echo [*] 步骤 3/7: 探测系统版本, 生成版本阶梯
call :DETECT_OS
if not defined BUILDN set "BUILDN=0"
echo [i] 系统 build 号: %BUILDN%   (7601=Win7/2008R2  9200=2012  9600=2012R2  14393=2016  17763=2019  19041+=Win10  22000+=Win11)
call :PICK_LADDER
echo [i] 版本尝试顺序: %LADDER%
if defined PREEXIST if not defined OWNSVC if not "%SSH_TRACE_FORCE_INSTALL%"=="1" goto USE_EXISTING

echo.
echo [*] 步骤 4/7 - 6/7: 逐版本部署 + 启动 + 回环自测
:TRY_LOOP
if "%CAND%"=="" goto ALL_FAIL
for /f "tokens=1*" %%a in ("%CAND%") do (set "VER=%%a" & set "CAND=%%b")
if not exist "%BINROOT%\%VER%\sshd.exe" goto TRY_LOOP
echo.
echo ------------------------------------------------------------
echo [*] 尝试 OpenSSH %VER%
call :STAGE_ONE
if errorlevel 1 goto TRY_LOOP
call :MAKE_KEYS
if errorlevel 1 goto KEY_FAIL
call :WRITE_CFG
call :INSTALL_SVC
if errorlevel 1 goto TRY_LOOP
call :SELFTEST
if "%SELFTEST_OK%"=="1" goto READY
echo.
echo [!] OpenSSH %VER% 回环自测失败, 该版本在本机不可用
echo     自测原始输出:
type "%SELFTEST_TMP%"
call :DUMP_DEBUG
echo [!] 继续尝试下一个版本...
goto TRY_LOOP

:READY
echo.
echo [OK] OpenSSH %VER% 部署并自测通过
>"%KITSTATE%" echo OURS %VER%

echo.
echo [*] 步骤 7/7: 防火墙放行 TCP %PORT%
netsh advfirewall firewall delete rule name="%FWNAME%" >nul 2>&1
netsh advfirewall firewall add rule name="%FWNAME%" dir=in action=allow protocol=TCP localport=%PORT% >> "%LOG%" 2>&1
if errorlevel 1 goto FW_FAIL

echo.
echo ============ SSH 已就绪 ============
echo   账号: %ACCOUNT%
echo   端口: %PORT%
echo   版本: OpenSSH %VER%
echo   目录: %INSTDIR%
echo   本机地址:
ipconfig | findstr /C:"IPv4"
echo.
echo   日志: %LOG%
echo   连接测试: ssh -o StrictHostKeyChecking=no %ACCOUNT%@本机IP
echo   溯源完成后运行 2-停止卸载.bat
echo ====================================
pause
exit /b 0

:USE_EXISTING
echo.
echo [i] 本机已有独立的 sshd 服务 -- 判定为系统自带/他人安装, 本工具不替换其程序,
echo     只写入配置并重启该服务.
call :MAKE_KEYS
if errorlevel 1 goto KEY_FAIL
call :WRITE_CFG
net stop sshd >nul 2>&1
ping -n 3 127.0.0.1 >nul
net start sshd >> "%LOG%" 2>&1
ping -n 4 127.0.0.1 >nul
call :SELFTEST
if not "%SELFTEST_OK%"=="1" goto EXIST_FAIL
set "VER=EXISTING"
goto READY

:EXIST_FAIL
echo.
echo [XX] 现成 sshd 服务回环自测失败, 输出:
type "%SELFTEST_TMP%"
echo     两个选择:
echo       A. 让本工具用自带 OpenSSH 接管: 先执行  sc stop sshd ^& sc delete sshd
echo          再重跑本脚本; 或直接设  SSH_TRACE_FORCE_INSTALL=1  后重跑本脚本
echo       B. 保留现成服务, 人工排查其 sshd_config 与本机兼容性
pause
exit /b 1

:ALL_FAIL
echo.
echo [XX] 三套 OpenSSH 版本全部自测失败, 请把上面的 sshd 调试输出发出来分析。
echo      常见原因:
echo        1) 安装目录权限不严 -- 必须只有 SYSTEM/管理员可写, 本脚本已自动收紧;
echo        2) 系统太老缺少运行库 -- Win7/2008R2 需先装 KB2999226 通用 C 运行库;
echo        3) 主机侧安全软件拦截 sshd 子进程;
echo        4) 该机器的 22 端口被别的程序占用 -- 用 netstat -ano ^| findstr :%PORT% 确认。
pause
exit /b 1

rem ================= 子过程 =================

:DETECT_OS
set "BUILDN="
for /f "usebackq tokens=*" %%a in (`powershell -NoProfile -Command "[Environment]::OSVersion.Version.Build" 2^>nul`) do set "BUILDN=%%a"
if defined BUILDN goto :eof
for /f "tokens=2 delims==" %%a in ('wmic os get buildnumber /value 2^>nul ^| find "="') do set "BUILDN=%%a"
for /f "tokens=1 delims=." %%a in ("%BUILDN%") do set "BUILDN=%%a"
goto :eof

:PICK_LADDER
if not defined BUILDN set "BUILDN=0"
if defined SSH_TRACE_FAKEBUILD set "BUILDN=%SSH_TRACE_FAKEBUILD%"

if %BUILDN% LSS 17763 goto LADDER_LEGACY
set "LADDER=10.0.0.0 8.9.1.0 7.7.2.0"
goto LADDER_SET
:LADDER_LEGACY
set "LADDER=7.7.2.0 8.9.1.0 10.0.0.0"
:LADDER_SET
set "CAND=%LADDER%"
goto :eof

:STAGE_ONE
set "SRC=%BINROOT%\%VER%"
if /i "%SSH_TRACE_TEST%"=="1" goto STAGE_COPY
if not exist "%SRC%\sshd.exe" ( echo [!] 缺少 %VER% 的程序文件, 跳过 & exit /b 1 )
net stop sshd >nul 2>&1
ping -n 2 127.0.0.1 >nul
taskkill /F /IM sshd.exe >nul 2>&1
taskkill /F /IM sshd-session.exe >nul 2>&1
taskkill /F /IM sshd-auth.exe >nul 2>&1
ping -n 2 127.0.0.1 >nul
:STAGE_COPY
if not exist "%INSTDIR%" mkdir "%INSTDIR%" >> "%LOG%" 2>&1
copy /y "%SRC%\*.exe" "%INSTDIR%\" >> "%LOG%" 2>&1
copy /y "%SRC%\*.dll" "%INSTDIR%\" >> "%LOG%" 2>&1
copy /y "%SRC%\*.ps1" "%INSTDIR%\" >> "%LOG%" 2>&1
copy /y "%SRC%\*.psd1" "%INSTDIR%\" >> "%LOG%" 2>&1
copy /y "%SRC%\*.psm1" "%INSTDIR%\" >> "%LOG%" 2>&1
copy /y "%SRC%\*.man" "%INSTDIR%\" >> "%LOG%" 2>&1
copy /y "%SRC%\sshd_config_default" "%INSTDIR%\" >> "%LOG%" 2>&1
copy /y "%SRC%\moduli" "%INSTDIR%\" >> "%LOG%" 2>&1
if not exist "%INSTDIR%\sshd.exe" ( echo [!] 复制 %VER% 失败 & exit /b 1 )
call :SET_ACL
echo [OK] 已部署 OpenSSH %VER% 到 %INSTDIR%
exit /b 0

:SET_ACL
rem 目录权限必须只有 SYSTEM/管理员可写, Authenticated Users 只读+执行,
rem 否则 sshd 会拒绝服务(表现为连接被 reset)。用 SID 写, 避免中英文系统组名差异。
icacls "%INSTDIR%" /inheritance:r >> "%LOG%" 2>&1
icacls "%INSTDIR%" /grant "*S-1-5-18:(OI)(CI)F" >> "%LOG%" 2>&1
icacls "%INSTDIR%" /grant "*S-1-5-32-544:(OI)(CI)F" >> "%LOG%" 2>&1
icacls "%INSTDIR%" /grant "*S-1-5-11:(OI)(CI)RX" >> "%LOG%" 2>&1
goto :eof

:MAKE_KEYS
"%INSTDIR%\ssh-keygen.exe" -A >> "%LOG%" 2>&1
if errorlevel 1 ( echo [!] 主机密钥生成失败 & exit /b 1 )
echo [OK] 主机密钥就绪 -- %CFGDIR%
exit /b 0

:WRITE_CFG
>"%CFGDIR%\sshd_config" echo Port %PORT%
>>"%CFGDIR%\sshd_config" echo PasswordAuthentication yes
>>"%CFGDIR%\sshd_config" echo PermitEmptyPasswords no
>>"%CFGDIR%\sshd_config" echo StrictModes no
>>"%CFGDIR%\sshd_config" echo LogLevel INFO
>>"%CFGDIR%\sshd_config" echo Subsystem sftp "%INSTDIR%\sftp-server.exe"
>>"%CFGDIR%\sshd_config" echo SyslogFacility LOCAL0
goto :eof

:INSTALL_SVC
powershell -NoProfile -ExecutionPolicy Bypass -File "%INSTDIR%\install-sshd.ps1" >> "%LOG%" 2>&1
sc query sshd >nul 2>&1
if errorlevel 1 goto SVC_SC
goto SVC_START
:SVC_SC
echo [i] install-sshd.ps1 未成功, 改用 sc create >> "%LOG%"
sc create sshd binPath= "\"%INSTDIR%\sshd.exe\"" start= auto DisplayName= "OpenSSH SSH Server" >> "%LOG%" 2>&1
:SVC_START
net stop sshd >nul 2>&1
ping -n 3 127.0.0.1 >nul
sc query sshd | findstr /i "STOPPED" >nul
if not errorlevel 1 taskkill /F /IM sshd.exe >nul 2>&1
ping -n 2 127.0.0.1 >nul
net start sshd >> "%LOG%" 2>&1
ping -n 4 127.0.0.1 >nul
sc query sshd | findstr /i "RUNNING" >nul
if errorlevel 1 ( echo [!] sshd 服务未能启动, 看日志 %LOG% & exit /b 1 )
sc config sshd start= auto >> "%LOG%" 2>&1
exit /b 0

:SELFTEST
rem 用回环 ssh-keyscan 做真正的密钥交换测试: 拿到主机公钥 = 服务正常;
rem 只回显 "SSH-2.0" 横幅而没有公钥 = 会话子进程崩了(就是连接被 reset 的那种)。
set "SELFTEST_OK=0"
set "KEYSCAN="
if exist "%BINROOT%\7.7.2.0\ssh-keyscan.exe" set "KEYSCAN=%BINROOT%\7.7.2.0\ssh-keyscan.exe"
if not defined KEYSCAN if exist "%INSTDIR%\ssh-keyscan.exe" set "KEYSCAN=%INSTDIR%\ssh-keyscan.exe"
if not defined KEYSCAN if exist "%ROOT%ssh-keyscan.exe" set "KEYSCAN=%ROOT%ssh-keyscan.exe"
if not defined KEYSCAN goto SELFTEST_END
"%KEYSCAN%" -T 8 -t rsa,ed25519 -p %PORT% %SSH_TRACE_TESTHOST% > "%SELFTEST_TMP%" 2>&1
findstr /c:" ssh-rsa " /c:" ssh-ed25519 " "%SELFTEST_TMP%" >nul 2>&1
if errorlevel 1 goto SELFTEST_END
set "SELFTEST_OK=1"
:SELFTEST_END
goto :eof

:DUMP_DEBUG
echo [i] 采集 sshd -ddd 调试输出 ...
taskkill /F /IM sshd.exe >nul 2>&1
ping -n 3 127.0.0.1 >nul
if exist "%DEBUG_OUT%" del /f /q "%DEBUG_OUT%" >nul 2>&1
if exist "%DEBUG_ERR%" del /f /q "%DEBUG_ERR%" >nul 2>&1
powershell -NoProfile -Command "Start-Process -FilePath '%INSTDIR%\sshd.exe' -ArgumentList '-ddd','-f','%CFGDIR%\sshd_config' -RedirectStandardOutput '%DEBUG_OUT%' -RedirectStandardError '%DEBUG_ERR%' -NoNewWindow -ErrorAction SilentlyContinue"
ping -n 6 127.0.0.1 >nul
"%KEYSCAN%" -T 5 -t rsa -p %PORT% %SSH_TRACE_TESTHOST% >nul 2>&1
ping -n 3 127.0.0.1 >nul
taskkill /F /IM sshd.exe >nul 2>&1
echo ---- sshd -ddd 标准输出末尾 ----
powershell -NoProfile -Command "if (Test-Path '%DEBUG_OUT%') { Get-Content '%DEBUG_OUT%' -Tail 20 } else { 'no output' }"
echo ---- sshd -ddd 错误输出末尾 ----
powershell -NoProfile -Command "if (Test-Path '%DEBUG_ERR%') { Get-Content '%DEBUG_ERR%' -Tail 20 } else { 'no output' }"
goto :eof

rem ================= 测试钩子 =================
rem 设 SSH_TRACE_TEST=1 只调用上面的子过程, 不装服务不改系统:
rem   SSH_TRACE_TEST=1 SSH_TRACE_TESTVER=7.7.2.0 SSH_TRACE_INSTDIR=临时目录
rem   SSH_TRACE_TESTHOST=127.0.0.1(默认) 可指向一台坏掉的服务器验证失败判定
:TESTMODE
echo [TEST] 只跑真实子过程, 不装服务、不改系统
call :DETECT_OS
echo BUILD=%BUILDN%
call :PICK_LADDER
echo LADDER=%LADDER%
set "VER=%SSH_TRACE_TESTVER%"
if not defined VER set "VER=7.7.2.0"
echo INSTDIR=%INSTDIR%
echo VER=%VER%
call :STAGE_ONE
echo STAGE_ONE=%errorlevel%
call :SELFTEST
echo SELFTEST_OK=%SELFTEST_OK%
echo ---- ssh-keyscan 原始输出 ----
type "%SELFTEST_TMP%"
exit /b 0

rem ================= 错误分支 =================
:NOT_ADMIN
echo [!] 当前不是管理员权限, 尝试提权重启...
powershell -NoProfile -Command "try { Start-Process cmd.exe -ArgumentList '/c \"\"%~f0\"\"' -Verb RunAs -ErrorAction Stop } catch { exit 1 }"
if errorlevel 1 goto ADMIN_FAIL
exit /b 0

:ADMIN_FAIL
echo.
echo [XX] 提权失败。本机可能关闭了 UAC 且当前账号不在管理员组。
echo      解决办法: 用管理员账号运行本脚本, 或使用反向隧道的方案。
pause
exit /b 1

:ACCT_FAIL
echo.
echo [XX] 启用账号 %ACCOUNT% 失败, 日志末尾:
powershell -NoProfile -Command "Get-Content '%LOG%' -Tail 10"
pause
exit /b 1

:PW_FAIL
echo.
echo [XX] 密码设置失败, 通常是未满足复杂度要求, 或该账号被策略限制。
echo      日志末尾:
powershell -NoProfile -Command "Get-Content '%LOG%' -Tail 10"
pause
exit /b 1

:KEY_FAIL
echo.
echo [XX] 主机密钥生成失败, 日志末尾:
powershell -NoProfile -Command "Get-Content '%LOG%' -Tail 10"
echo      排查: 检查 %CFGDIR% 目录权限与磁盘空间, 或手工执行:
echo            "%INSTDIR%\ssh-keygen.exe" -A
pause
exit /b 1

:FW_FAIL
echo.
echo [XX] 防火墙规则添加失败。服务已启动, 但端口可能被防火墙拦截。
echo      可手动执行: netsh advfirewall firewall add rule name="%FWNAME%" dir=in action=allow protocol=TCP localport=%PORT%
pause
exit /b 1