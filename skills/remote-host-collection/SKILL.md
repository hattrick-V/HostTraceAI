---
name: remote-host-collection
description: "远程主机只读采集（主机通道接入）：当需要在授权范围内通过平台主机通道（SSH/MCP）接入目标主机，采集进程、网络连接、服务、计划任务、注册表、日志与可疑文件等溯源证据时使用。覆盖连接与主机指纹确认、非交互执行与超时控制、中文 Windows 输出编码（GBK/UTF-8）处理、大文件与恶意样本的只读外带（先算 SHA-256、传回后复核哈希）、断连与重试、多主机批量采集的节奏控制与业务影响规避。产出带主机标识、时区、命令原文、落盘路径与哈希的采集清单。"
metadata:
  tags: ["溯源", "应急响应", "主机采集", "ssh", "证据固定"]
  version: "1.0.0"
---

# 远程主机只读采集

## 适用条件

- 触发场景：溯源/应急工单已授权，需要在若干台主机上取证据；或本地已有镜像但需补采主机侧易失数据（进程、连接、服务、日志）。
- 前置信息（缺一项先补齐）：主机标识（主机名/内网地址/资产编号）、系统版本、账号与权限级别、连接方式（平台主机通道名或 SSH 主机+端口+凭据引用）、采集项清单、业务时间窗（能否在高峰执行）。
- 前置判断：**本技能只做只读采集**。写文件、打包、导出大文件、终止进程、禁用服务、改注册表都属于处置动作，必须先出方案走审批。
- 凭据口径：由平台通道/凭据库注入，Agent 不接触明文口令，也不得写入脚本或报告。
- 本技能不覆盖磁盘分区、LVM、扩容等存储变更操作（属容量运维，与取证无关）。

## 证据要求

- 每条采集物落盘五要素：主机标识、采集时间（含时区，如 `2026-09-17T10:22:31+08:00`）、执行命令原文、原始输出、落盘路径 + SHA-256。
- 原始输出先落盘再解读：取回的文本写入 `<case-dir>/hosts/<host>/raw/<序号>-<项目>.txt`，再用 `read_file`/`grep` 回读。不要在会话里当场"整理"掉原文。
- 二进制（样本、镜像、evtx、数据库文件）必须以**二进制方式**传输，禁止经文本编解码，禁止用 `cat`/`type`/`Get-Content` 通过命令通道传二进制；传输前后各算一次 SHA-256 并核对大小。
- 时间统一：记录主机时间与本机时间的偏差；所有时间戳标注时区，跨时区比对前先换算。
- 来源可信度：通道直接返回的原始输出（高）／命令被包装或二次转码（中）／人工转述或截图（低）。
- 用 `write_file` 维护 `<case-dir>/collection-index.md`，每完成一项追加一行；收工前用 `grep -c` 核对条数与工单要求一致。

## 工具顺序

S1 通道建立与主机指纹确认
- 使用平台能力中心已配置的主机通道（SSH/MCP）；跨主机并发前先单机跑通，避免批量错连。
- 必须用本机 OpenSSH 客户端时按非交互处理：
```bash
ssh -o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=15 <user>@<target-ip> 'id; hostname; date -Is'
```
- 首次连接先采集主机公钥指纹写入 `<case-dir>/hosts/<host>/fingerprint.txt`（`ssh-keyscan -p <port> <target-ip>`，或通道返回 `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`）。**不要长期用 `StrictHostKeyChecking=no`**：指纹需与资产台账或上次采集记录比对，不一致即停并上报。
- 连不上时按序排查：端口/通道配置 → 主机负载与防火墙策略 → 凭据来源是否绑定该主机。不要反复试口令，也不要对非目标主机发起连接。

S2 环境确认（一次交互取全，减少往返）
Linux：`date -Is; hostname; uname -a; id; uptime; cat /etc/os-release | head -3; df -h; nproc; free -m`。
Windows：
```powershell
Get-Date -Format o; hostname; whoami; [System.Environment]::OSVersion.VersionString
Get-PSDrive -PSProvider FileSystem | Select-Object Name,@{n='FreeGB';e={[math]::Round($_.Free/1GB,2)}}
```

S3 非交互执行与超时控制
- Linux 单条命令加 `timeout`：`timeout 60 <cmd>`，采日志类可放宽到 300 秒。
- 长任务尽量拆小；确需后台执行用 `nohup <cmd> > /tmp/collect.out 2>&1 &`，轮询 `tail -n 50 /tmp/collect.out`。**在目标机落临时文件前先确认可用空间**（`df -h` / `Get-PSDrive`），并在索引登记路径与清理计划（清理属处置动作，需审批）。
- 脚本模板（凭据由通道注入，脚本内不出现口令）：

```python
c = paramiko.SSHClient(); c.load_system_host_keys()
c.connect("<target-ip>", port=22, username="<user>", timeout=15, allow_agent=False, look_for_keys=False)
_, out, err = c.exec_command("timeout 60 ps -eo pid,ppid,user,etime,cmd")
print(out.read().decode("utf-8", "replace"), err.read().decode("utf-8", "replace"), out.channel.recv_exit_status())
```

- `exec_command` 要 `read()` 完才拿到结果；退出码必须显式取 `recv_exit_status()`，否则会把"命令没跑起来"误判成"没有输出"。
- 多行 `python -c` 经 SSH 会被压成一行报 SyntaxError：脚本写成本地文件再推送执行，或严格写成单行。
- 完整采集脚本（含超时包装、GBK 解码、SFTP 外带）见 `references/host-channel-templates.md`。

S4 输出编码处理（中文 Windows 是重灾区）
- Windows 中文环境默认 GBK（cp936），会话开头统一设置：
```powershell
chcp 65001 > $null
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
```
- 读日志显式指定编码：`Get-Content -Encoding UTF8 <path>`（用默认编码读 UTF-8 文件必乱码）；写输出用 `Out-File -Encoding utf8`。
- 已拿到乱码文本时按原始字节解码，不要猜：
```bash
python3 -c "print(open('<case-dir>/hosts/h1/raw/03-tasks.txt','rb').read().decode('gbk',errors='replace')[:2000])"
```
- 优先保存原始字节再转码；用 `grep` 搜中文关键词前先确认文件已是 UTF-8。细节见 `references/encoding-and-transfer.md`。

S5 证据采集项（逐条落盘，通过主机通道只读执行）
- Windows：`Get-CimInstance Win32_Process`、`netstat -ano`、`Get-CimInstance Win32_Service`、`schtasks /query /v /fo LIST`、`reg query "...\CurrentVersion\Run" /s`、`wevtutil qe Security /f:text /c:200 /rd:true`、按 `LastWriteTime` 筛近期文件。
- Linux：`ps -eo pid,ppid,user,lstart,cmd`、`ss -antp`、`systemctl list-units --state=running`、`systemctl list-unit-files --state=enabled`、`crontab -l`、`journalctl --since '-2 days' -n 500`、`find /etc /home -xdev -mtime -7 -type f -ls`。
- 完整命令与解析字段见 `references/readonly-collection-commands.md`；采集项按工单取舍，不要"能采的都采"。

S6 样本与大文件外带
1. 先在目标机算哈希与大小（只读）：`sha256sum /path/sample.bin; stat -c '%s' /path/sample.bin`；Windows 用 `Get-FileHash -Algorithm SHA256` 与 `(Get-Item <path>).Length`。
2. 用 SFTP 二进制方式拉回，不要经命令通道拼流：
```python
sftp = c.open_sftp(); sftp.get("/path/sample.bin", r"<case-dir>/hosts/h1/samples/sample.bin"); sftp.close()
```
Win32-OpenSSH 的 SFTP 路径要写成 `/D:/path/file` 而非 `D:\path\file`；先用 `sftp.listdir("/D:")` 确认盘符，再用 `sftp.stat()` 核对存在性与大小。
3. 传回后本机复核哈希与大小（`sha256sum` / `Get-FileHash`）一致才算成功；不一致重传最多 2 次，仍不一致则标记"传输不可信"并保留记录。
4. 大文件（>1GB）分块传输或先压缩（写目标机临时文件需审批）；超时后先确认远端进程状态，**不要在 D 状态（不可中断 I/O）下强杀进程**。
5. SFTP 以登录用户身份认证，读不到的文件不要尝试提权读取；缺项写进缺口清单。

S7 断连与重试
- 只读命令幂等可重发；退避 2s/4s/8s，最多 3 次，每次记录原因（握手超时/通道重置/负载过高）。
- 输出为空时先看退出码与 stderr，再考虑换命令；不要凭"没有输出"写"无异常"。
- "TCP 通但无协议应答"时，先在主机本机回环验证服务正常，再判断链路/网关策略，随后停止重复调试并上报。

S8 多主机批量采集的节奏控制
- 并发 2–4 台，单台串行执行采集项；主机之间 3–5 秒抖动，避免同时压满出口链路与存储。
- 先取负载基线（`uptime` / `Get-CimInstance Win32_Processor | Select LoadPercentage`），采集中定期复查。
- 避免全盘递归：`find` 加 `-xdev` 与时间/目录限制，日志按时间窗口取而非整库导出，查询限制字段。
- 每台一个输出目录 `<case-dir>/hosts/<host>/`，命名不用中文与空格；一台失败不影响其余，失败主机登记重试清单。

## 停止条件

- 采集清单全部完成或达到工单时间盒：收工出首版结论，剩余项列入待采。
- 主机负载越线（load average > CPU 核数、CPU 持续 > 80%、出现业务告警）→ 暂停该主机采集并上报，不加压不加速。
- 目标机可用空间低于阈值、或需写临时文件而无审批 → 停止该项，改为流式取回。
- 通道反复失败 3 次，或主机指纹与台账不符 → 停止并上报通道/资产问题。
- 权限不足，或涉及需审批的处置动作（写文件、导出大量日志、隔离主机、终止进程）→ 出方案走审批后再继续。
- 新证据已不再改变结论时停止，不做无边界"多采一点"。

## 输出格式

`write_file` 产出 `<case-dir>/report/collection-<host>-<yyyymmdd>.md`：

- **事实**：采集清单表（主机标识｜采集项｜命令原文｜落盘路径｜SHA-256｜采集时间+时区｜账号权限），逐行可复核。
- **推断**：由采集结果得出的判断并标注置信度——高（原始输出直接支持且有第二来源印证）／中（单一来源直接支持）／低（间接线索）。
- **待验证**：缺失项、需审批的采集、需第二来源交叉的结论。
- 附：主机与本机时间偏差、通道与指纹记录、采集期间主机负载、失败项与原因、建议动作（是否升级为事件、是否扩大采集范围）。

## 红线与审批

- 只读可直接做：`ps`/`ss`/`systemctl`/`schtasks`/`reg query`/`wevtutil qe`/`Get-CimInstance`/`journalctl`/`find`/`stat`/哈希计算、SFTP 读取文件、读取注册表与日志。
- 先出方案走审批：在目标机写任何文件（含临时文件、打包、日志导出）、批量下载样本、导出大体积镜像或事件日志、终止进程、禁用服务或计划任务、修改注册表/驱动/安全策略、隔离主机、批量外发 IOC。
- 禁止：试探或猜测口令、使用来源不明凭据、对非目标主机发起连接或扫描、删除目标机文件、关闭安全软件、把采集物上传到未授权外部服务、把含敏感数据的文件写到案卷目录之外、在脚本或报告里出现明文口令。
- 本技能只解决"取证"，不解决"处置"；越界即停。
