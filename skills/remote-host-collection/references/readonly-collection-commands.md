# 只读采集命令速查（Windows / Linux）

配套 `SKILL.md` 的 S2/S5 使用。全部为只读操作，通过主机通道执行；输出先写 `<case-dir>/hosts/<host>/raw/NN-<项目>.txt`，再回读。

## Windows（PowerShell / 内置工具）

| 采集项 | 命令 | 解析要点 |
|---|---|---|
| 系统与环境 | `Get-Date -Format o; hostname; whoami; [System.Environment]::OSVersion.VersionString` | 时间带时区；`whoami` 判断是否 SYSTEM |
| 磁盘与空间 | `Get-PSDrive -PSProvider FileSystem \| Select-Object Name,@{n='FreeGB';e={[math]::Round($_.Free/1GB,2)}}` | 落临时文件前必查 |
| 进程 | `Get-CimInstance Win32_Process \| Select-Object ProcessId,ParentProcessId,CreationDate,CommandLine,ExecutablePath` | 命令行含落地路径；看异常父子关系 |
| 网络连接 | `netstat -ano` | PID 与进程表对齐；关注固定间隔外联 |
| 服务 | `Get-CimInstance Win32_Service \| Select-Object Name,State,StartMode,PathName` | `PathName` 指向 Temp/AppData 属高价值线索 |
| 计划任务 | `schtasks /query /v /fo LIST` | 记录任务路径、运行账号、触发器、执行命令 |
| 自启项 | `reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /s`；同样查 `HKCU\...\Run`、`RunOnce` | 记录键值原文与写入时间（键的 LastWriteTime 需 reg 导出或工具） |
| 事件日志 | `wevtutil qe Security /f:text /c:200 /rd:true` | 按时间倒序限量；大范围导出 evtx 需审批 |
| 近期文件 | `Get-ChildItem C:\Users -Recurse -Force -ErrorAction SilentlyContinue \| Where-Object LastWriteTime -gt (Get-Date).AddDays(-7)` | 递归要限目录，避免压满磁盘 IO |
| 文件哈希 | `Get-FileHash -Algorithm SHA256 <path> \| Format-List` | 与传输后本机复算比对 |
| 备用数据流 | `Get-Item <path> -Stream *` | `Zone.Identifier` 可还原下载来源 |

## Linux

| 采集项 | 命令 | 解析要点 |
|---|---|---|
| 系统与环境 | `date -Is; hostname; uname -a; id; uptime; cat /etc/os-release` | `uptime` 作为负载基线 |
| 磁盘与空间 | `df -h; lsblk -f` | 只读查看，不做任何分区操作 |
| 进程 | `ps -eo pid,ppid,user,lstart,etime,cmd` | 启动时间与父进程是还原释放链的关键 |
| 网络连接 | `ss -antp` | 记录监听与已建立连接、对应 PID |
| 服务 | `systemctl list-units --type=service --state=running`；`systemctl list-unit-files --state=enabled` | enabled 列表是持久化重点 |
| 计划任务 | `crontab -l`；`ls -l /etc/cron.*`；`systemctl list-timers --all` | 记录条目原文与文件 mtime |
| 日志 | `journalctl --since '-2 days' -n 500 --no-pager` | 按时间窗口取，不做整库导出 |
| 近期文件 | `find /tmp /var/tmp /etc /home -xdev -mtime -7 -type f -ls` | `-xdev` 防止跨越挂载点 |
| 账号与登录 | `last -n 50`；`ls -l /var/log/auth.log*` | 与进程时间线交叉 |
| 文件元数据与哈希 | `stat -c '%n %s %y' <path>`；`sha256sum <path>` | 与传输后本机复算比对 |
| 打开文件 | `lsof -p <pid>`（需足够权限） | 无权限即记缺口，不尝试提权 |

## 采集纪律

- 一次交互多带几条命令（用 `;` 或 `&&` 串），减少往返；分段落盘时用可辨识的分隔符（如 `echo "===SERVICES==="`）把各段隔开。
- 输出为空必须看退出码与 stderr，不得直接写"无异常"。
- 时间窗口有限的项（日志、近期文件）要写明查询区间，便于复核。
- 采集项按工单取舍：能直接回答工单问题的先采，其余列入待采；不要"能采的都采"。
- 主机侧只读，不写文件、不打包、不改配置；需要落临时文件先查空间并走审批。
