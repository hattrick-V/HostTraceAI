---
name: pcap-traffic-analysis
description: "PCAP 抓包与流量分析溯源：当事件响应需要确定被控主机的 C2 外联、DNS 隧道、心跳信标、大流量外传与明文凭据泄露并给出帧级定位时使用；覆盖抓包方式与哈希登记、先看会话统计再逐流追踪的分析顺序、Wireshark 过滤表达式与 tshark 命令行、DNS/TLS/HTTP 元数据启发式、文件雕刻、与内存取证交叉验证；产出事实/推断/待验证清单、IOC 与时间线及处置建议。"
metadata:
  tags: ["溯源", "流量分析", "tshark", "wireshark", "c2"]
  version: "1.0.0"
---

# PCAP 流量分析与 C2 外联定位

分析顺序固定：**先看会话统计（谁和谁、多少、多久），再收敛到少数会话逐流追踪**。一上来就 Follow Stream 会在海量会话里瞎翻。

## 适用条件

- 需要回答：被控主机在跟谁通信、C2 在哪、外传了什么、从什么时间开始。
- 输入可能是：主机抓包（tcpdump/dumpcap）、交换机镜像口或网关旁路捕获、EDR/NDR 导出的 PCAP。
- 加载前必须问清：PCAP 路径与字节数；**抓包点**（主机自身/镜像口/网关）与抓包工具版本、snaplen、BPF 过滤条件（决定能看见什么）；抓包起止时间与时区；是否有 SSLKEYLOGFILE；抓包设备与主机时钟偏差。
- 只有 PCAP 无内存/磁盘时，仍可定外联对象、外传体量与起始时间，进程归属只能标为推断。

## 证据要求

落盘 `<case-dir>/evidence/<hostname>/pcap/`，并在 `<case-dir>/notebook.md` 登记：

| 项 | 要求 |
|---|---|
| PCAP 原始文件 | SHA-256（`sha256sum capture.pcap`）、字节数、包数（`capinfos -c`）、首末包时间（`capinfos -a -e`，**带时区**） |
| 抓包元数据 | 抓包点、工具与版本（tcpdump/tshark/dumpcap/Wireshark）、snaplen、BPF 条件 |
| 命令与输出 | 完整 tshark 命令行与原始输出；统计结果另存 |
| 定位 | 每条结论必须指到 **frame.number / tcp.stream / 具体会话**，例："frame 1832（tcp.stream 4）向 `<remote-ip>:443` POST 上传 1.2MB" |
| 时间 | 统一 UTC；抓包点与主机时钟偏差单独记录，偏差大时结论只写时间区间 |
| 可信度 | 标注结论是"抓包点直接可见"还是"元数据推断"；TLS 加密载荷不可读必须写明 |

- 原始 PCAP 只读。裁剪、转换（`editcap`/`mergecap`/`pcapfix`）一律产出新文件并改名 `*.work.pcap`，重新计算哈希并在清单注明差异。

## 工具顺序

### 第 0 步 校验与修包

```bash
sha256sum capture.pcap | tee out/pcap.sha256
capinfos capture.pcap                           # 包数/首末时间/链路类型
editcap -F pcap capture.pcapng capture.work.pcap    # pcapng → pcap
mergecap -w merged.work.pcap a.pcap b.pcap          # 多段合并
pcapfix corrupted.pcap -o fixed.work.pcap           # 头部/包边界损坏时修复
```

魔法字节：`d4c3b2a1`=pcap(LE)、`a1b2c3d4`=pcap(BE)、`0a0d0d0a`=pcapng。

### 第 1 步 先看会话统计（不要跳过）

```bash
tshark -r capture.pcap -q -z io,phs          # 协议层级：什么占主导
tshark -r capture.pcap -q -z endpoints,ip    # 端点：谁发了多少字节
tshark -r capture.pcap -q -z conv,tcp        # TCP 会话：字节数/包数/时长
tshark -r capture.pcap -q -z io,stat,60      # 每分钟包/字节，看突发与等高峰
```

收敛顺序：① `conv,tcp` 按字节数排序，最上面几个先确认是否属业务；② 排除内网互访与已知业务，剩下的对外会话才是候选 C2；③ 收敛到少数 `tcp.stream` 后才做 follow 与导出对象。

### 第 2 步 会话筛选与逐流追踪

```bash
tshark -r capture.pcap -q -z conv,tcp | sort -k5 -nr | head -20
tshark -r capture.pcap -Y "tcp.stream==<n>" -T fields -e frame.number -e frame.time_epoch -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tcp.len
tshark -r capture.pcap -q -z follow,tcp,ascii,<n>
```

Wireshark 常用过滤（把 `<target-ip>` 换成实际地址）：

```
ip.addr == <target-ip>
!ip.addr == <target-ip>
tcp.stream eq <n>
tcp.flags.syn == 1 && tcp.flags.ack == 0     # 新连接
tcp.len > 0
```

### 第 3 步 DNS：隧道与心跳

```bash
tshark -r capture.pcap -Y "dns.flags.response==0" -T fields -e frame.number -e ip.src -e dns.qry.name | sort -u
tshark -r capture.pcap -Y "dns.qry.name.len>50" -T fields -e frame.number -e ip.src -e dns.qry.name
tshark -r capture.pcap -Y "dns.qry.type==16" -T fields -e frame.number -e dns.qry.name
tshark -r capture.pcap -Y "dns.resp.len>200" -T fields -e frame.number -e dns.qry.name -e dns.resp.len
```

隧道启发式（≥3 条同时成立再判隧道，单条只是线索）：子域名标签长（>30 字符）且左侧像 Base32/Base64；同一域名高频查询（>1 次/秒）且几乎无其他域名；大量 TXT 查询或 `dns.resp.len` 异常大；查询名熵高、极少重复；域名与业务无关。Wireshark 侧：`dns.qry.name.len > 50`、`dns.qry.type == 16`、`dns.resp.len > 512`。

### 第 4 步 心跳 / 信标识别

```bash
tshark -r capture.pcap -Y "ip.addr==<remote-ip> && tcp.flags.ack==1 && tcp.len==0" -T fields -e frame.time_epoch | sort -n
```

心跳特征：间隔近似固定（如 60s±2s）、包长相近、持续数小时、端口集中在 80/443/8443 或高位；`io,stat,60` 上表现为等高峰。Wireshark 把时间列切成 Seconds Since Previous Displayed Packet 可直观看间隔。

### 第 5 步 TLS 元数据（不解密也能定位）

```bash
tshark -r capture.pcap -Y "tls.handshake.type==1" -T fields -e frame.number -e ip.src -e ip.dst -e tls.handshake.extensions_server_name
tshark -r capture.pcap -Y "tls.handshake.extensions_server_name" -T fields -e tls.handshake.extensions_server_name | sort | uniq -c | sort -nr
tshark -r capture.pcap -Y "x509sat.printableString" -T fields -e x509sat.printableString | sort -u
```

- 有 TLS 但 **SNI 为空** → 直连 IP 或自定义协议隧道，重点看。
- 证书自签、有效期极短、主题与 SNI 不一致 → 可疑。
- 用 JA3（新版 tshark 的 `tls.handshake.ja3`）聚类客户端指纹，找出只有单台主机在用的罕见指纹。
- 只有拿到 SSLKEYLOGFILE 才解密（Wireshark Preferences → Protocols → TLS → (Pre)-Master-Secret log filename）；无密钥就只用元数据下结论，不尝试破解。

### 第 6 步 明文协议与凭据泄露

```bash
tshark -r capture.pcap -Y "http.request" -T fields -e frame.number -e http.host -e http.request.method -e http.request.uri -e http.user_agent
tshark -r capture.pcap -Y "http.request.method==POST" -T fields -e frame.number -e http.host -e http.request.uri -e http.content_type
tshark -r capture.pcap -Y "http.authbasic" -T fields -e frame.number
tshark -r capture.pcap -Y "ftp.request.command==USER || ftp.request.command==PASS" -T fields -e frame.number -e ftp.request.arg
tshark -r capture.pcap -Y "smtp.req.command==AUTH" -T fields -e frame.number
tshark -r capture.pcap -Y "ntlmssp.auth.username" -T fields -e frame.number -e ntlmssp.auth.username -e ntlmssp.auth.domain
```

只做识别与告警：报告写"受影响账号 + 协议 + 帧号"，凭据值单独加密存放。`frame contains "password"` 只是线索，须落到具体协议字段再定性；NTLM 只记录位置与账号，**不提取响应做离线破解**。

### 第 7 步 文件雕刻与对象导出

```bash
tshark -r capture.pcap --export-objects http,out/objects/http
tshark -r capture.pcap --export-objects smb,out/objects/smb
```

Wireshark 等价：File → Export Objects → HTTP / SMB / TFTP / IMF / DICOM。导出后逐个 `sha256sum` 并与内存 `dumpfiles` 落地物比对；手工重建用 Follow → TCP Stream → Show as Raw → Save As，再 `binwalk -e` 或 `foremost -i` 二次雕刻。文件名可能被伪造（.jpg 实为 PE），以魔数和哈希判定：`file out/objects/*`。

### 第 8 步 大流量外传定位

```bash
tshark -r capture.pcap -q -z conv,tcp | sort -k5 -nr | head
tshark -r capture.pcap -Y "ip.src==<target-ip> && tcp.len>0" -q -z io,stat,10
tshark -r capture.pcap -Y "ip.dst==<target-ip>" -T fields -e frame.number -e ip.src -e tcp.dstport -e tcp.len
```

判据：单会话出向字节数远超基线、持续短、之后与同一远端保持心跳——"先大批量上传、后持续心跳"是窃密常见节奏。

### 第 9 步 与内存取证交叉验证

- PCAP 会话远端 `IP:port` ↔ 内存 `windows.netscan` 的 Foreign Address（可对上 PID 与进程路径）；
- 三处时间（抓包点、主机系统时钟、内存 netscan 记录）统一到 UTC 比对，偏差大时结论只写区间；
- 交叉结果写进同一份时间线，并按 `memory-forensics` 的结论合并 IOC。

## 停止条件

- 三问有答案即停：①有无对外 C2 或隧道；②外传了什么、多少；③从什么时间开始。
- 明文凭据已定位且影响账号明确 → 转审批轮换流程，不再翻更多凭据。
- 要解密但没有密钥（无 SSLKEYLOGFILE、无服务器私钥）→ 记录"该会话无法解密"，只用 TLS 元数据给结论。
- 包量巨大且无嫌疑目标 → 用会话统计与时间窗收敛，再申请定向抓包。
- 需要主机侧信息但无主机通道 → 停，把待验证项列清。

## 输出格式

写 `<case-dir>/report-pcap.md`：

- **事实**：帧号/会话号 + 命令 + 输出路径。例：`conv,tcp` 显示 `<target-ip>:52341 → <remote-ip>:443`（tcp.stream 12）单会话出向 1.2MB，首包 frame 1043。
- **推断**：依据 + 置信度（高/中/低）。例：60s 固定间隔心跳 + 无 SNI 的 443 长连接 → 推断为 C2，置信度 中（缺主机侧进程证据）。
- **待验证**：需要内存/磁盘/EDR 补哪一条证据。

附：①时间线（UTC；时间/主机/远端/协议/字节/帧号）；②IOC（远端 IP:port、域名、SNI、证书指纹、User-Agent、导出文件哈希）；③建议动作（阻断外联、隔离主机、凭据轮换均需审批）；对外副本的地址按需脱敏。

## 红线与审批

- 只读可直接做：`capinfos`、`tshark` 统计与过滤、导出对象到本地目录、`sha256sum`。
- 先出方案再审批：在现网交换机做端口镜像或抓包、在目标主机重新抓包（影响性能与磁盘）、阻断外联、下发 ACL、断开可疑会话、隔离主机。
- 禁止：对捕获中出现的任何外部地址发起主动连接或扫描；对捕获的哈希或凭据做爆破、离线破解或重放；把凭据原文、完整哈希、真实公网受害地址写进对外报告；把 PCAP 或提取样本上传到本机以外。
- 原始 PCAP 按证据保管：只读、留 SHA-256、限定访问；任何裁剪或转换产出新文件并注明。
