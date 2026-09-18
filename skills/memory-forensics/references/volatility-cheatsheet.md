# Volatility 命令速查（内存取证附录）

`memory-forensics` 技能的配套速查表。所有命令中的 `mem.raw` / `mem.lime` 为镜像路径占位符，`<pid>` / `<virtaddr>` 为运行时取得的实际值；执行后请把完整命令行与原始输出一并落盘（见技能正文"证据要求"）。

## 1. Vol2 / Vol3 对照表

### 系统识别

| 用途 | Volatility 2 | Volatility 3 |
|---|---|---|
| OS 识别 | `imageinfo` | `windows.info` / `linux.info` |
| 内核调试扫描 | `kdbgscan` | 自动匹配符号表 |
| 系统横幅 | `imageinfo` | `banners.Banners` |

### 进程

| 用途 | Volatility 2 | Volatility 3 |
|---|---|---|
| 进程链表 | `pslist` | `windows.pslist` |
| 池标签扫描 | `psscan` | `windows.psscan` |
| 进程树 | `pstree` | `windows.pstree` |
| 命令行 | `cmdline` | `windows.cmdline` |
| 环境变量 | `envars` | `windows.envars` |
| 句柄 | `handles` | `windows.handles` |
| 权限 | `privs` | `windows.privileges` |
| SID | `getsids` | `windows.getsids` |

### 内存 / 模块

| 用途 | Volatility 2 | Volatility 3 |
|---|---|---|
| 已加载 DLL | `dlllist` | `windows.dlllist` |
| 未链接 DLL 检测 | `ldrmodules` | `windows.ldrmodules` |
| 注入检测 | `malfind` | `windows.malfind` |
| VAD 树 | `vadinfo` | `windows.vadinfo` |
| 转储进程内存 | `memdump -p <pid>` | `windows.memmap --dump --pid <pid>` |
| 转储 DLL | `dlldump -p <pid>` | `windows.dlllist --pid <pid> --dump` |
| 内核模块 | `modules` / `modscan` | `windows.modules` / `windows.modscan` |
| 驱动 | `driverscan` | `windows.driverscan` |
| 内核回调 | `callbacks` | `windows.callbacks` |
| SSDT 钩子 | `ssdt` | `windows.ssdt` |

### 网络

| 用途 | Volatility 2 | Volatility 3 |
|---|---|---|
| 连接（Vista+） | `netscan` | `windows.netscan` |
| 连接与监听（XP/2003） | `connections` / `sockets` | 不支持 |
| 已关闭连接（XP/2003） | `connscan` | 不支持 |
| 网络统计 | 无 | `windows.netstat` |

### 凭据（仅用于确认暴露面，禁止破解或重放）

| 用途 | Volatility 2 | Volatility 3 |
|---|---|---|
| SAM 哈希 | `hashdump` | `windows.hashdump` |
| LSA 秘密 | `lsadump` | `windows.lsadump` |
| 域缓存凭据 | `cachedump` | `windows.cachedump` |

### 文件系统 / 注册表

| 用途 | Volatility 2 | Volatility 3 |
|---|---|---|
| 文件对象扫描 | `filescan` | `windows.filescan` |
| 文件转储 | `dumpfiles -Q <offset>` | `windows.dumpfiles --virtaddr <addr>` |
| MFT 分析 | `mftparser` | `windows.mftscan` |
| 注册表 hive 列表 | `hivelist` | `windows.registry.hivelist` |
| 读取键值 | `printkey -K "路径"` | `windows.registry.printkey --key "路径"` |
| 程序执行痕迹 | `userassist` | `windows.registry.userassist` |

### 命令历史 / 用户活动

| 用途 | Volatility 2 | Volatility 3 |
|---|---|---|
| 命令行 | `cmdline` | `windows.cmdline` |
| 控制台回显 | `consoles` | `windows.consoles` |
| 剪贴板 | `clipboard` | `windows.clipboard` |
| 时间线 | `timeliner --output=body` | `timeliner.Timeliner` |
| Linux shell 历史 | `linux_bash`（需自建 profile） | `linux.bash` |

## 2. 常用分析序列（Vol3）

### 快速判恶（4 条命令）

```bash
vol3 -f mem.raw windows.info
vol3 -f mem.raw windows.pstree
vol3 -f mem.raw windows.malfind
vol3 -f mem.raw windows.netscan
```

### 完整主机溯源

```bash
vol3 -f mem.raw windows.info
vol3 -f mem.raw windows.pslist
vol3 -f mem.raw windows.psscan          # 与 pslist 对比，找 DKOM 隐藏
vol3 -f mem.raw windows.pstree          # 父子关系异常
vol3 -f mem.raw windows.cmdline         # 启动参数
vol3 -f mem.raw windows.netscan         # 外联对象
vol3 -f mem.raw windows.malfind         # 注入区段
vol3 -f mem.raw windows.dlllist --pid <pid>
vol3 -f mem.raw windows.ldrmodules --pid <pid>
vol3 -f mem.raw windows.handles --pid <pid>
vol3 -f mem.raw windows.filescan | grep -i "<keyword>"
vol3 -f mem.raw windows.dumpfiles --virtaddr <virtaddr>
```

### 事件时间线重建

```bash
vol3 -f mem.raw windows.info
vol3 -f mem.raw timeliner.Timeliner --output-file out/timeline.body --output body
mactime -b out/timeline.body -d > out/timeline.csv
vol3 -f mem.raw windows.cmdline
vol3 -f mem.raw windows.registry.userassist
vol3 -f mem.raw windows.netscan
vol3 -f mem.raw windows.filescan
```

### Linux 内核完整性检查

```bash
vol3 -f mem.lime linux.pslist
vol3 -f mem.lime linux.pstree
vol3 -f mem.lime linux.bash
vol3 -f mem.lime linux.elfs             # 进程内注入的 ELF 映射
vol3 -f mem.lime linux.check_syscall    # 系统调用表劫持
vol3 -f mem.lime linux.check_afinfo     # 网络结构体劫持
vol3 -f mem.lime linux.check_modules
vol3 -f mem.lime linux.tty_check        # TTY 劫持
```

## 3. Volatility 2 profile 处理

```bash
# 列出可用 profile
vol.py --info | grep -i "Profile"

# 常见 Windows profile
# Win7SP1x64, Win10x64_19041, Win10x64_17763, WinXPSP3x86, Win2016x64_14393

# 选对 profile：以 imageinfo 的 Suggested Profile(s) 为准
vol.py -f mem.raw imageinfo
```

- **坑位**：profile 与镜像不匹配时 `psscan` 会静默返回空表而不报错，容易被误判成"没有隐藏进程"。发现插件输出异常时先回到 `imageinfo` 核对 profile。
- Linux 镜像用 Vol2 需要自建 profile：在对应内核的主机上编译 `volatility/tools/linux`，把 `module.dwarf` 与 `/boot/System.map-<内核版本>` 打包成 zip 放入 `volatility/plugins/overlays/linux/`，否则 `linux_*` 插件不可用。构建过程与产物文件名写入证据清单。

## 4. 常用筛选手法

```bash
# 只保留对外连接（去掉本地回环与未指定地址）
vol3 -f mem.raw windows.netscan | grep -vE '127\.0\.0\.1|0\.0\.0\.0|::1|\[::\]'

# 文档与密钥类文件
vol3 -f mem.raw windows.filescan | grep -iE '\.(txt|doc|xls|pdf|kdbx|key|pem|conf|ini|bat|ps1)$'

# 常见落地位置中的可执行文件
vol3 -f mem.raw windows.filescan | grep -iE '\\(temp|tmp|appdata|downloads)\\.*\.(exe|dll|ps1)$'

# 隐藏进程差集（Vol3 输出前两行为表头）
diff <(awk 'NR>2{print $1,$2}' out/pslist.txt | sort -u) <(awk 'NR>2{print $1,$2}' out/psscan.txt | sort -u)
```

## 5. 判定速记

| 现象 | 含义 | 处置提示 |
|---|---|---|
| `psscan` 有、`pslist` 无 | 进程被从活动链表摘除（DKOM 隐藏） | 高置信恶意，落到报告"事实" |
| `pslist` 有、`psscan` 无 | 采集中刚退出的陈旧对象 | 降级为线索，去磁盘/日志求证 |
| 可执行区段无磁盘映射、起始有 `MZ` | 反射式 PE 注入 | 转储并算哈希，作为文件 IOC |
| 可执行区段无映射、无 PE 头 | 裸 shellcode | 同上，另看其调用链与连接 |
| `ldrmodules` 三列全 False | 未链接模块（幽灵 DLL） | 结合进程路径与启动时间 |
| `modscan` 有、`modules` 无 | 隐藏或已卸载驱动 | 检查内核回调与驱动文件 |
| 陌生进程 + 对外高位端口 | 疑似 C2 外联 | 转 PCAP 侧做会话验证 |
