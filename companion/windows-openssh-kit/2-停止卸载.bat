@echo off
chcp 936 >nul 2>&1
setlocal
title SSH 停止卸载 - 溯源用
rem ============================================================
rem  与 1-启用SSH.bat 配套: 停服务、还原配置、删掉本工具装进去的程序目录
rem ============================================================

set "ROOT=%~dp0"
set "LOG=%ROOT%ssh-trace.log"
set "CFGDIR=%ProgramData%\ssh"
set "ACCOUNT=administrator"
set "FWNAME=SSH-TRACE-TEMP"
set "KITSTATE=%ROOT%.kit-state"
if not defined SSH_TRACE_INSTDIR set "SSH_TRACE_INSTDIR=%ProgramFiles%\OpenSSH-Win64"
set "INSTDIR=%SSH_TRACE_INSTDIR%"

if /i "%SSH_TRACE_TEST%"=="1" goto TESTMODE

fsutil dirty query %SystemDrive% >nul 2>&1
if not errorlevel 1 goto ADMIN_OK
net session >nul 2>&1
if not errorlevel 1 goto ADMIN_OK
goto NOT_ADMIN

:ADMIN_OK
cd /d "%ROOT%"
echo ===== %date% %time% 停止卸载 ===== >> "%LOG%"

echo [*] 步骤 1/7: 停止 sshd / ssh-agent 服务与残留进程
net stop sshd >> "%LOG%" 2>&1
sc stop ssh-agent >> "%LOG%" 2>&1
ping -n 3 127.0.0.1 >nul
taskkill /F /IM sshd.exe >nul 2>&1
taskkill /F /IM sshd-session.exe >nul 2>&1
taskkill /F /IM sshd-auth.exe >nul 2>&1
ping -n 2 127.0.0.1 >nul

echo [*] 步骤 2/7: 删除防火墙规则 %FWNAME%
netsh advfirewall firewall delete rule name="%FWNAME%" >> "%LOG%" 2>&1

echo [*] 步骤 3/7: 处理 sshd 服务与程序目录
set "KITPRE="
findstr /l "PREEXIST" "%KITSTATE%" >nul 2>&1
if not errorlevel 1 set "KITPRE=1"
if defined KITPRE goto RESTORE

rem --- 本工具自己装的: 卸载服务并删掉程序目录 ---
if exist "%INSTDIR%\uninstall-sshd.ps1" powershell -NoProfile -ExecutionPolicy Bypass -File "%INSTDIR%\uninstall-sshd.ps1" >> "%LOG%" 2>&1
sc delete sshd >> "%LOG%" 2>&1
sc delete ssh-agent >> "%LOG%" 2>&1
ping -n 3 127.0.0.1 >nul
if not exist "%INSTDIR%" goto SVC_DONE
rem 安装目录的权限被启用脚本收紧过(只有 SYSTEM/管理员可写), 删之前先放开
takeown /f "%INSTDIR%" /r /d y >> "%LOG%" 2>&1
icacls "%INSTDIR%" /grant "*S-1-5-32-544:(OI)(CI)F" /t /c >> "%LOG%" 2>&1
rd /s /q "%INSTDIR%" >> "%LOG%" 2>&1
if exist "%INSTDIR%" echo [i] 提示: 程序目录未能删除(文件被占用), 重启本机后再删 %INSTDIR%
if not exist "%INSTDIR%" echo [OK] 已删除程序目录 %INSTDIR%
goto SVC_DONE

:RESTORE
echo [i] 本机原有 sshd 服务, 只还原配置, 不卸载服务、不动其程序 >> "%LOG%"
if exist "%CFGDIR%\sshd_config.orig-kit" copy /y "%CFGDIR%\sshd_config.orig-kit" "%CFGDIR%\sshd_config" >nul 2>&1
del /f /q "%CFGDIR%\sshd_config.orig-kit" >nul 2>&1
sc config sshd start= auto >> "%LOG%" 2>&1
taskkill /F /IM sshd.exe >nul 2>&1
ping -n 2 127.0.0.1 >nul
net start sshd >> "%LOG%" 2>&1
ping -n 4 127.0.0.1 >nul
sc query sshd | findstr /i "RUNNING" >nul
if errorlevel 1 echo [i] 提示: sshd 服务未恢复为运行状态, 请人工确认 >> "%LOG%"

:SVC_DONE
echo [*] 步骤 4/7: 关闭 %ACCOUNT% 账号
net user %ACCOUNT% /active:no >> "%LOG%" 2>&1

echo [*] 步骤 5/7: 清理配置目录与状态文件
if defined KITPRE goto SKIP_CFGDEL
rd /s /q "%CFGDIR%" >> "%LOG%" 2>&1

:SKIP_CFGDEL
del /f /q "%KITSTATE%" >nul 2>&1

echo.
echo [*] 步骤 6/7: 自检
echo     22 端口监听情况(应为空):
netstat -an | findstr ":22 " | findstr "LISTENING"
echo.

echo [*] 步骤 7/7: 收尾
echo ============ 清理完成 ============
set /p DELSELF=输入 Y 删除本文件夹, 其他任意键保留: 
if /i "%DELSELF%"=="Y" goto SELFDEL
echo [OK] 文件夹已保留。日志在本目录内, 可手动删除。
goto END

:SELFDEL
cd /d "%USERPROFILE%"
ping -n 3 127.0.0.1 >nul
cmd /c rd /s /q "%~dp0"

:END
pause
exit /b 0

:TESTMODE
echo [TEST] 只打印判定结果, 不动系统
echo KITSTATE=%KITSTATE%
if exist "%KITSTATE%" (echo 状态文件内容: & type "%KITSTATE%") else (echo 状态文件不存在: 将按"本工具自己装的"处理)
findstr /l "PREEXIST" "%KITSTATE%" >nul 2>&1
if errorlevel 1 (echo 判定: 非PREEXIST -- 会卸载服务并删除 %INSTDIR%) else (echo 判定: PREEXIST -- 只还原配置, 保留现成服务)
echo CFGDIR=%CFGDIR%
if exist "%CFGDIR%\sshd_config.orig-kit" (echo 存在原配置备份 sshd_config.orig-kit) else (echo 无原配置备份)
exit /b 0

:NOT_ADMIN
echo [!] 当前不是管理员权限, 尝试提权重启...
powershell -NoProfile -Command "try { Start-Process cmd.exe -ArgumentList '/c \"\"%~f0\"\"' -Verb RunAs -ErrorAction Stop } catch { exit 1 }"
if errorlevel 1 goto ADMIN_FAIL
exit /b 0

:ADMIN_FAIL
echo.
echo [XX] 提权失败。本机可能关闭了 UAC 且当前账号不在管理员组。
echo      解决办法: 用管理员账号运行本脚本。
pause
exit /b 1