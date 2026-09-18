---
name: webroot-forensics
description: "Web 目录取证：从 Web 根目录、脚本文件时间戳、上传与缓存目录、访问日志、Web 进程子进程还原后门落地与访问时间线。当需要判断 Web 站点是否被挂后门、后门是什么时候怎么进来的、谁访问过、影响面多大时加载本技能（配合 webshell-triage 专家使用）。"
metadata:
  tags: ["溯源", "webshell", "web", "日志分析"]
  version: "1.0.0"
---

# Web 目录取证（WebShell 溯源）

## 适用条件

- 站点疑似被挂后门：安全设备告警、页面被篡改、出现异常外联、`uploads` 目录出现脚本文件、日志里出现异常参数请求。
- 已知：站点根路径、Web 服务类型与运行用户、可访问的 Web 日志目录、可疑时间窗。
- 目标：定位后门文件、推断入口、还原访问与利用时间线、界定影响范围。

前置确认：站点是否有多个虚拟主机/多个根目录、是否有 CDN/反向代理（真实客户端 IP 在 `X-Forwarded-For`）、是否有代码发布流程（正常发布也会批量改文件时间，必须区分）。

## 证据要求

- 后门文件：**只读复制副本**（保留相对路径）、记录路径/大小/时间戳（MACB）/权限/属主/哈希（SHA-256 或 MD5，站点自带的校验文件优先沿用同一算法）；**不删除、不改名、不改权限**。
- 日志：保留原始行（时间、来源 IP、方法、路径、状态码、UA、Referer），标注日志文件绝对路径与行号区间；注意日志轮转（`.1`、`.gz`）要一起查。
- 目录清单：候选文件的**修改时间基线**必须记录，用于和代码发布记录（Git/部署/备份时间）比对排除。
- 时间线四要素：文件落地时间、首次被访问时间、首次外联时间、管理员正常维护时间。

## 工具顺序

1. **环境确认**：`ps -ef | egrep 'nginx|httpd|apache|php-fpm|tomcat|java'`（IIS：`Get-Process w3wp | Select Id,Path,StartTime`）；站点根目录（`nginx -T | grep root`、`grep -r DocumentRoot /etc/apache2`、IIS 用 `%windir%\system32\inetsrv\appcmd list vdir`）。
2. **目录级时间异常**：`find <webroot> -maxdepth 3 -type d -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort`；先看"低峰时间新建/改动的目录"。
3. **按修改时间筛候选脚本**：
   `find <webroot> -type f \( -name '*.php' -o -name '*.jsp' -o -name '*.jspx' -o -name '*.asp' -o -name '*.aspx' -o -name '*.ashx' \) -newermt '<case-start>' -printf '%TY-%Tm-%Td %TH:%TM %s %p\n' | sort`
   IIS：`Get-ChildItem -Recurse -Include *.aspx,*.ashx,*.asp | Where-Object LastWriteTime -gt '<time>' | Select FullName,Length,LastWriteTime`
4. **上传/缓存/模板目录重点扫描**：`find <webroot>/{uploads,upload,temp,cache,attachments,data} -type f -newermt '<case-start>' -ls 2>/dev/null`；检查 `.htaccess` / `web.config` 是否被改成允许解析脚本、`auto_prepend_file`、tomcat filter/valve、IIS 模块是否新增。
5. **内容特征匹配**（人工判读，剔除框架自带命中）：
   `grep -rInE 'eval\(|assert\(|system\(|shell_exec\(|passthru\(|popen\(|proc_open\(|base64_decode\(|gzinflate\(|str_rot13\(|\$_(POST|GET|REQUEST|COOKIE)\[' <webroot> --include=*.php | head -200`
   常见形态：一行的 `<?php @eval($_POST['x']);?>`、双扩展 `shell.php.jpg`、伪装成图片/日志的脚本、超长单行、注释头伪装成框架组件、`chr()` 拼接键名。
6. **框架基线比对**：用同版本官方包/发布仓库哈希逐文件比对，只保留**差异文件**；业务自有代码则与备份/Git 记录比对（注意"只在服务器上被改过、Git 无记录"是关键信号）。
7. **日志还原（后门访问画像）**：
   - 按文件名检索：`grep -n '<candidate-file>' <access_log>*`；
   - 按特征参数检索：`grep -nE '<param>=|base64|eval|assert' <access_log>*`；
   - 频次与首次出现：`awk '{print $1}' <access_log> | sort | uniq -c | sort -rn | head -30`；
   - 时间分布：`awk -F'[][]' '{print $2}' <access_log> | cut -c1-14 | sort | uniq -c`（看是否集中在某几天/某小时）。
   - 反向代理场景：真实 IP 取 `X-Forwarded-For` 首个地址，并在报告中写明取值来源。
8. **进程与外联**：`ss -antp | egrep 'httpd|nginx|php-fpm|java'`（Windows：`netstat -ano` → `Get-CimInstance Win32_Process -Filter "ProcessId=<pid>"` 看 `CommandLine` 与父进程）；重点看 Web 用户身份拉起的 `bash/sh/cmd/powershell/curl/wget/nc/python/perl`。
9. **持久化面**：crontab（`crontab -l`、`/etc/cron.d`、`/var/spool/cron`）、systemd 单元、`.user.ini`、启动脚本、Web 计划任务、数据库里的定时作业；IIS 看 `applicationHost.config` 变更时间。
10. **影响面评估**：站点配置里的数据库连接（是否被读走）、`/proc/<pid>/environ`、`.bash_history`、被访问过的敏感接口日志、是否出现对外扫描/连接（跳板迹象）。
11. **处置建议**（提交审批后执行）：隔离后门文件（移动 + 保留哈希）、封禁来源 IP、修复入口（上传校验、组件升级、目录禁止执行）、轮换泄露凭据、审计数据是否外泄。

## 停止条件

- 已定位后门文件 + 来源 IP + 时间线 + 影响面，且有日志与文件双重证据 → 输出结论。
- 需要删除/隔离/封禁/停服 → 停止，交审批。
- 排查完候选窗口与上传目录后无后门特征 → 如实报告"未发现后门"，并列出已核查范围、排除依据与残余风险（例如无法回溯的日志缺口）。

## 输出格式

```
【目标站点】<host:port> 根目录 <path> 环境 <nginx/apache/iis + php/java/.net 版本>
【结论】确认后门/疑似/未发现（置信度 高/中/低）
【后门清单】路径 → 类型 → 大小 → 时间戳 → SHA-256 → 样本副本位置
【入口推断】入口类型 → 证据（日志行/文件变更）→ 置信度
【时间线】落地 → 首次访问 → 首次外联 → 正常运维对比
【来源 IP】IP → 首次/末次 → 请求特征 → 内网/外网
【影响面】可执行权限、可读数据、是否跳板（证据）
【已固化证据】证据包路径 / SHA-256
【建议处置】动作 → 命令 → 影响 → 回滚（标注需审批）
【待验证】…
```

## 红线与审批

- 只读：列目录、读文件、读日志、算哈希、复制副本 → 直接执行。
- 需审批：删除/隔离后门文件、封禁 IP、修改站点或 Web 服务器配置、重启服务。
- 禁止：对站点做漏洞利用测试、上传测试文件、使用扫描器打目标、外传业务数据与个人信息。
