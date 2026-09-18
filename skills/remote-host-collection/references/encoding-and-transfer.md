# 输出编码与文件外带

配套 `SKILL.md` 的 S4/S6 使用。

## 1. 中文 Windows 的编码问题

中文版 Windows 默认代码页是 GBK（cp936）。同一条命令在本地看正常、落到案卷里变乱码，几乎都是"按 UTF-8 解 GBK 字节"。三条纪律：

1. **会话开头统一编码**（PowerShell）：
```powershell
chcp 65001 > $null
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
```
2. **显式指定读写编码**：读文件 `Get-Content -Encoding UTF8 <path>`（默认编码读 UTF-8 文件必乱码）；写文件 `... | Out-File -Encoding utf8 <path>`；导出文本 `wevtutil qe Security /f:text /c:200 /rd:true > out.txt` 后再统一转码。
3. **先存原始字节，再转码**：通道返回的内容先落成 `.bin`，再决定用哪种编码解：

```bash
python3 -c "import sys;b=open('<case-dir>/hosts/h1/raw/03-tasks.bin','rb').read();
open('<case-dir>/hosts/h1/raw/03-tasks.txt','w',encoding='utf-8').write(b.decode('gbk',errors='replace'))"
```

- 解码失败不要丢字符：用 `errors='replace'`，并在报告里标注"含未解码字节"。
- 需要同时保留两版时，`.bin` 为准，`.txt` 为转码产物，两者都写进采集索引。
- 用 `grep` 搜中文关键词前先确认目标文件是 UTF-8；GBK 文件里的中文关键词在 UTF-8 检索下必然搜不到，容易误判"没有命中"。
- Linux 侧一般是 UTF-8；若遇到 `LANG=C` 环境导致输出被转义，显式设 `LC_ALL=C.UTF-8` 或后续用 `iconv -f <原编码> -t utf-8` 转换。

## 2. 文本外带（日志、命令输出、注册表导出）

- 优先让命令**在主机侧产生文本**再走命令通道取回（体积小、可读性好），例如 `reg query ... /s`、`journalctl ... --no-pager`。
- 输出较大时按时间或 PID 切片，分多次取，避免单次响应过大导致超时截断。
- 每条输出都要记录**命令原文 + 采集时间 + 主机标识**，否则后续无法复核。

## 3. 二进制外带（样本、镜像、事件日志文件、数据库文件）

1. 远端算哈希与大小（只读）：
```bash
sha256sum /path/sample.bin; stat -c '%s' /path/sample.bin
```
```powershell
Get-FileHash -Algorithm SHA256 <path> | Format-List; (Get-Item <path>).Length
```
2. 用 SFTP/SCP 二进制方式拉回 `<case-dir>/hosts/<host>/samples/`；**禁止**用 `cat`/`type`/`Get-Content` 通过命令通道传输（会破坏字节并污染行尾）。
3. 传回后本机复算 SHA-256 与大小，三者一致才写进采集索引；不一致重传最多 2 次，仍不一致则标记"传输不可信"，保留本地副本与失败次数。
4. 大文件：分块或断点续传，设超时；传输中监控远端进程与磁盘空间；**不要在 D 状态（不可中断 I/O）下强杀进程**。
5. 权限不足读不到的文件不要提权硬取，登记为缺口并说明原因。

## 4. 超时、断连与重试

- 单条命令加超时（`timeout 60 <cmd>`），长任务拆小；需要后台执行时记录临时文件路径与轮询方式。
- 重试只对只读、幂等命令做：退避 2s/4s/8s，最多 3 次；每次记录失败原因（握手超时/通道重置/负载过高）。
- 输出为空先看退出码与 stderr；"没有输出"不等于"没有异常"。
- 反复失败 3 次即停止并上报（通道配置、指纹不符、网络策略三类原因分别记录），不要无限重试拖住工单。
