# 时间线证据源 · 事件 ID 清单 · 时间换算（深度附录）

配合 `windows-forensic-timeline` 主文件使用。所有命令在目标 Windows 主机上以管理员会话执行，全部为**只读**动作；导出类命令写入 `<case-dir>`，不在系统盘留痕（除 `C:\Windows\Temp\<out>\` 这类显式临时目录）。

## 1. 事件日志 ID 清单（按用途分组）

### 1.1 落地 / 安装类（System 日志）

| ID | 含义 | 判读要点 |
|---|---|---|
| 7045 | 服务或**内核驱动**安装 | 恶意驱动必从此暴露。字段：`ServiceName`、`ImagePath`、`ServiceType`、`StartType`。`ImagePath` 指向 `C:\Windows\Temp\*.jpg|*.dat`、`C:\ProgramData\<随机>\*.sys` 即高危 |
| 7040 | 服务启动类型变更 | 木马关 Windows 更新 / Defender / 第三方杀软会留这条（`StartType` 由 auto 变 disabled） |
| 7036 | 服务状态变更 | 量大，只在已锁定可疑服务名后按名过滤 |
| 1000 | 应用程序崩溃 | 崩溃的 `Faulting application` 字段会带**路径与版本号**，可暴露伪装的版本信息 |
| 1 | 系统时间被修改 | `provider: Microsoft-Windows-Kernel-General`，事件数据直接写明是哪个进程改的 |
| 6013 | 系统启动时长（N 秒） | 用采集时刻倒推开机时间，判断是否重启（详见 §3） |

批量导出（近 60 天，落盘回本地看，不要在线 grep 大日志）：

```
powershell -NoProfile -Command "Get-WinEvent -FilterHashtable @{LogName='System';Id=7045,7040,1000,1;StartTime=(Get-Date).AddDays(-60)} -ErrorAction SilentlyContinue | Select TimeCreated,Id,ProviderName,@{n='Msg';e={$_.Message -replace '\s+',' '}} | Export-Csv C:\Windows\Temp\out\sys_60d.csv -NoTypeInformation -Encoding UTF8"
wevtutil epl System <case-dir>\evt\System.evtx
```

### 1.2 关机 / 重启 / 服务终止类（区分“真重启”与“看门狗拉起”）

| ID | 含义 | 判读要点 |
|---|---|---|
| 6005 / 6006 | 事件日志服务已启动 / 已停止 | 有 6005 才说明该时段发生过启动 |
| 6009 | 启动时的 OS 版本 | 与正常基线比对，突然换版本 = 异常 |
| 1074 | 进程发起关机/重启（记录发起进程与用户） | 木马/勒索不常走这里，但企业工具会 |
| 1076 | 异常关机原因记录 | 配合 1074 判断非正常断电 |
| 1077 | 关机原因已记录 | — |
| 7031 / 7034 | 服务**意外终止**（7031 含恢复次数）/ 服务意外停止 | 成组出现表示进程被杀或被清；`7031` 带“第 N 次”可量化 |
| 7000 / 7009 | 服务启动失败 / 超时 | 杀软驱动被拦、被抢占时的典型 |
| 7011 | 等待服务事务超时（默认 30000ms） | 常见于安全软件/驱动卡死 |
| 100  | `provider winsrvext`「进程延迟关机」 | **正常关机也会出现，不是恶意项**，不要写进报告 |

判定“是否重启过”：把 6005/6006/6009/1074/1076 全部拉到本地按时间排序，某个时刻之后**一条都没有**，且关键远控/业务进程的 PID 和启动时间跨天未变 → 未重启。远端日志里“服务以新实例启动”常只是守护进程拉起被杀的实例。

### 1.3 日志清除与反取证类

| 来源 | ID | 含义 |
|---|---|---|
| Security | 1102 | 审核日志已被清除（记录清除者账号） |
| System / Application / PowerShell | 104 | 日志文件已被清除（`EventLog` provider） |
| Security | 1100 | 事件日志服务被关闭 |
| Security | 4719 | 系统审核策略被修改（攻击者常先关审计再干坏事） |
| Security | 4907 | 对象审核设置被修改 |
| Security / System | 4616 | 系统时间被修改（带旧值/新值） |

判读：

- **Application 日志同秒被反复清几十到几百次** = 加密器或批处理循环清日志的特征。
- 清空时刻**之前不可回溯**。报告必须写“自 <时刻> 起无日志，无法取证”，不要把“查不到入口”写成“没有入口”。
- 若 `Security` 日志被清，所有依赖它的来源（4624/4625 登录、4688 进程创建、5156/5157 连接审计）**一并失效**。

### 1.4 网络与外联相关（能否拿到源/目的地址）

| 来源 | ID / 字段 | 是否含真实地址 |
|---|---|---|
| Security 4624 / 4625 | “源网络地址”“工作站名” | 仅登录类型 **3（网络）/8（网络明文）/10（RDP）** 有真实地址；类型 2/5 恒为 `-` |
| Security 5156 / 5157 | WFP 连接审计五元组 | 默认关闭，且属 Security 日志 |
| Security 5140 / 5145 | 共享访问的网络地址 | 需先开对象访问审计 |
| Microsoft-Windows-RdpCoreTS/Operational 131 | “服务器已接受来自客户端 X:port 的连接” | 有 IP + 端口 |
| RemoteConnectionManager 1149 | “用户 X 已于 Y 时间连接到会话” | **本身不带 IP**，需与 131 按秒对齐 |
| Microsoft-Windows-Windows Firewall | 2002~2011 | **只有规则变更/配置文件切换，不含成功连接五元组** |
| Microsoft-Windows-SMBServer/SmbClient Security | 审计 | 多为空 |
| CodeIntegrity/Operational 3033 / 3077 / 3004 | “未满足企业签名级别要求（Policy ID:{GUID}）” | 用于把被拦行为和 WDAC 策略对上 |

`CodeIntegrity` 事件里的 Policy ID 与 `CiTool -lp` 的 `PolicyID` 一致即元凶；也可在 `SiPolicy.p7b` 里按 GUID 的**小端字节序**搜索确认归属。

## 2. 落地时刻的证据源（按性价比排序）

1. **NTFS 文件 MACB**：`CreationTime` 是第一手落地证据（木马一般不改时间戳）：
   ```
   powershell -NoProfile -Command "Get-Item 'C:\path\payload.exe' | Select CreationTime,LastWriteTime,LastAccessTime,ChangeTime,Length"
   powershell -NoProfile -Command "Get-ChildItem 'C:\ProgramData\<随机目录>' -Force -Recurse | Select FullName,CreationTime,LastWriteTime,Length | Export-Csv C:\Windows\Temp\out\mtime.csv -NoTypeInformation -Encoding UTF8"
   ```
   注意：复制/压缩样本会改 `LastAccessTime`，落地判据用 `CreationTime`；`ChangeTime`（MFT 项变更）需 `fsutil` 类接口或离线解析。
2. **计划任务文件时间**：`dir /a /tc C:\Windows\System32\Tasks | findstr /i "<关键字>"`，任务文件创建时间与恶意文件释放时间一一对应 = 自动化投放。
3. **System 事件**：`7045`（服务/驱动安装，含 `ImagePath` 与 `StartType`）、`7040`、`1000`、`1`。
4. **浏览器下载记录**：见 §2.3，定位初始投毒载体最有效。
5. **USN journal**（仅当覆盖到目标时间）：
   ```
   fsutil usn queryjournal C:
   fsutil usn readjournal C: csv > C:\Windows\Temp\out\usn.csv
   ```
   默认 32MB 上限，繁忙主机常只保留最近几天；**先看覆盖范围再决定是否投入**。
6. **$MFT / 卷影副本**：在线主机不跑第三方 raw 解析器。用 `vssadmin list shadows` 找到历史快照，`mklink /d <挂载点> \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\` 挂载后**只读比对**；也可用 `fsutil` 只读查询。
7. **执行痕迹**（复杂度高，需要时再上）：
   - **Prefetch**：`C:\Windows\Prefetch\*.pf`（Win10/11 默认开启），文件名 = 可执行名 + 8 位哈希；文件自身 `CreationTime` ≈ 首次执行时间。读取需管理员权限：
     ```
     dir /a /tw C:\Windows\Prefetch\*.pf
     ```
   - **UserAssist**（GUI 程序启动次数与最后运行时间，路径名**ROT13 编码**）：
     ```
     reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist" /s
     ```
     键路径：`...\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count`（可执行）与 `{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\Count`（快捷方式）。
   - **Amcache**（应用安装/执行痕迹，含 SHA-1 与路径）：
     ```
     copy /y C:\Windows\AppCompat\Programs\Amcache.hve <case-dir>\Amcache.hve
     ```
     离线挂载为 hive 后看 `Root\InventoryApplicationFile`；文件本身 `LastWriteTime` ≈ 记录更新时间。
   - **ShimCache / AppCompatCache**（兼容性缓存，记录执行与路径）：
     ```
     reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
     ```
     二进制值，需解析；Win10 后记录“是否执行”标志。
   - **SRUM**：`C:\Windows\System32\sru\SRUDB.dat`（30~60 天每进程网络/CPU 用量），需 VSS 拷贝后离线解析——是少数能反映**历史网络用量**的来源。
   - **BAM/DAM**：`HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>`（最后执行时间）。
   - **MUICache / LastVisitedPidlMRU / TypedPaths**：`HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache`、`HKCU\...\Explorer\ComDlg32\LastVisitedPidlMRU` 与 `...\TypedPaths`（用户手敲/粘贴过的路径）。

### 2.1 时间字段定义（避免把 MACB 弄错）

| 缩写 | NTFS 属性 | 含义 |
|---|---|---|
| M | `$STANDARD_INFORMATION.Modified` | 文件内容最后修改 |
| A | `... Accessed` | 最后访问（默认可能关闭更新） |
| C | `... Changed / MFT Changed` | MFT 记录项变更（改名、改权限会更新） |
| B | `... Birth / Creation` | **创建时间 = 落地时刻首选** |

木马常改 `Modified` 伪装，`Birth` 与 `Changed` 出现“被改小”矛盾时以卷影/日志交叉验证。

### 2.2 USN 判读

`fsutil usn readjournal C: csv` 输出的关键列：`FileName`、`Reason`（`FileCreate`、`DataExtend`、`RenameNewName`、`BasicInfoChange`…）、`TimeStamp`（UTC）。同一路径成组出现 `FileCreate → DataExtend` 即为文件写出完成时刻。

### 2.3 浏览器下载/访问记录

库路径（Chrome/Edge 同构，SQLite；**先只读复制再解析**，运行中的库被锁）：

- Edge：`C:\Users\<user>\AppData\Local\Microsoft\Edge\User Data\Default\History`
- Chrome：`C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\History`
- 多配置时还有 `Profile 1`、`Profile 2`…

关键表：

```sql
select target_path, tab_url, total_bytes, start_time, end_time from downloads;
select u.url, v.visit_time, v.transition from visits v join urls u on u.id=v.url;
```

- **时间字段为自 1601-01-01 UTC 起的微秒数**：`unix = chrome_us/1e6 - 11644473600`。
- 库里是 UTC，报告换主机本地时区（如 +8）。
- 判读：把“下载完成 `end_time`”与“落地文件 `CreationTime`”对齐，相差几分钟内即高度可疑；投毒载体常是未签名、伪装成国外厂商版本的安装器。
- 解析与输出时间线用 `scripts/browser_history_timeline.py`（已封装时间换算与 CSV 输出）。
- 其它浏览器：Firefox 为 `places.sqlite`（`moz_*` 微秒自 1970）；IE/旧版用 `WebCacheV01.dat`（ESE，需专门解析）。

## 3. 日志清除与勒索加密锚点（weax/Mallox 类）

1. 先定“攻击者动手”锚点：Security `1102` + Application/PowerShell `104`。清日志往往是加密前一步，落地时间通常在其前后。
2. 勒索信（如 `RECOVERY INFORMATION.txt`、`*_readme.txt`）与 `*.<扩展名>` 文件的 `LastWriteTime` = 加密开始的可靠下限；勒索信**每个目录都落一份**（含软件日志目录），是最容易拿到的样本。
3. 主机是否有重启（见 §1.2）。若窗口内 6005/6006/6009/1074/1076 全为 0 且远控/服务 PID 跨天未变 → 未重启。
4. 加密前置动作常见链（可直接写进时间线）：安全软件等待超时/启动失败 → 杀软组件意外终止 ×N → 数据库服务意外停止 → 远控服务意外终止。
5. Application 同一秒被清几十次以上 = 批处理/加密器特征，务必统计“清除次数”写进报告。
6. 若 `Security` 日志被清，而 `System`/`Application` 保留，则仍可从 `System` 侧建立落地→加密的粗时间线，报告中说明证据缺口。

## 4. 采集包与第三方工具（按需）

- 第三方应急采集包（如各类“一键采集”工具）：壳外多为 `_MetaData.json`/`base.json` 明文，敏感 JSON 常为十六进制密文，密钥材料在 `base.json` 的 `SEED` 字段（base64 套 base64）。**不要试图爆破 KDF**（SHA-256/MD5 + AES-128/256 各模式已多次验证失败），直接请用户用配套查看器导出明文；`disc_C/disc_D` 之类的“磁盘全量文件清单”正是落地时间的关键。
- 采集包自带的 `VSS` 快照与明文采集日志可给出**采集时刻的进程全量清单（含 PID）**，用来与远端日志/时间线互相印证（例如某远控进程 PID 与日志一致即确认同机）。
- 采集包里的 `sockets`/`arp_table`/`netuse`/`rdp_connect_*` 都是**采集时刻的瞬时快照**，对追溯历史外联价值有限；`dns_caches` 偶尔还能留到前一晚的解析记录。

## 5. 常见误判清单

- `provider winsrvext` 的 `100`（进程延迟关机）：正常关机也有，**不是恶意项**。
- 空目录 + 标准继承 ACL（`Users:(M)`）通常是用户自己卸载软件的残留，不是木马产物。
- `C:\Windows\Temp` 下的 `*.tmp`、第三方软件日志多为正常缓存，先看文件头（`{"` / `<?xml` / `PK`）再定性。
- 计划任务/启动项里成对出现的人类可读英文名（`Author=Administrator`）很可能是同一投放脚本产物，不要逐个当独立事件写。
- 时间线上“事件日志服务已停止（6006）+ 未重启”通常等于有人清日志，而不是系统故障。
