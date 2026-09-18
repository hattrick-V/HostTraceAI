# Windows SSH 临时启用工具包

[English](README.md) | **简体中文**

[HostTraceAI](../../README_CN.md) 的配套工具。在 Windows 目标机上临时启用 SSH
服务，供平台通过 SSH/MCP 连上去做溯源调查；调查结束后一键清理干净。

工具包内置三套 **上游原版**
[PowerShell/Win32-OpenSSH](https://github.com/PowerShell/Win32-OpenSSH)
程序，会挑一套在这台机器上**真正能用**的装上，而不是装最新版然后碰运气。

## 它解决什么问题

把较新的 Win32-OpenSSH 丢到老服务器上，失败方式很迷惑：安装成功、服务显示
`RUNNING`、端口能连、SSH 横幅也出得来，但客户端一连就断：

```
Connection reset by <IP> port 22
```

`ssh -vvv` 能看到横幅已经收到，reset 发生在客户端发出 `KEXINIT` 之后。

原因是 OpenSSH 9.8 把 `sshd` 拆成了两个进程：`sshd.exe`（监听）和
`sshd-session.exe`（每条连接的会话）。在老系统上 `sshd.exe` 能跑起来，所以
服务看起来正常、横幅也照出 —— 但会话子进程一碰系统里不存在的 API 就被直接
干掉。结果是端口通、协议走两步就断。上游已标明 9.8/10.x 需要
Windows 10 1809+ / Server 2019+。

同一个症状还有一个不那么明显的成因：程序目录必须**只有** SYSTEM 和管理员
可写。把 OpenSSH 放在桌面、下载目录或 U 盘里运行，也会触发同样的 reset。

## 工作原理

`bin/` 下是三套**未经任何修改**的上游程序：

| 版本 | 上游发布 | 架构 | 适用系统 |
|---|---|---|---|
| `7.7.2.0` | v7.7.2.0p1-Beta | 单进程 `sshd` | Win7 / 2008 R2 / 2012 / 2012 R2 / 2016 |
| `8.9.1.0` | v8.9.1.0p1-Beta | 折中版本 | 兜底 |
| `10.0.0.0` | 10.0.0.0p2-Preview | 拆分 `sshd` + `sshd-session` | Win10 1809+ / Server 2019+ |

`1-启用SSH.bat` 随后：

1. 读取系统 build 号，生成版本尝试顺序 —— 新系统从新到旧，老系统从旧到新。
2. 把该版本复制到 `C:\Program Files\OpenSSH-Win64`，并收紧目录权限
   （SYSTEM 与管理员可写，Authenticated Users 只读+执行）。权限用 **SID**
   授予，中英文系统结果一致。
3. 生成主机密钥、写 `sshd_config`、安装 `sshd` 服务。
4. **用回环 ssh-keyscan 做真实密钥交换自测**。拿到主机公钥 = 该版本确实可用；
   只回显 `SSH-2.0` 横幅 = 会话子进程起不来，正是那个 reset 故障。自测失败会
   自动换下一套版本重试。
5. 三套全部失败时，自动跑 `sshd -ddd` 并把调试输出打出来 —— 让你看到真实
   报错，而不是一句笼统的"安装失败"。
6. 放行防火墙端口（默认 22）。

`2-停止卸载.bat` 负责还原：停服务、删防火墙规则；若服务是本工具装的，就卸载
服务并删掉程序目录；若本机原本就有自己的 `sshd`，则只从备份还原
`sshd_config`，不动它的服务与程序。

## 用法

```text
1. 把整个工具包文件夹拷到目标机（放哪都行，脚本会自己装到 Program Files）
2. 管理员运行 1-启用SSH.bat
3. 溯源结束后运行 2-停止卸载.bat
```

非管理员启动时脚本会自行通过 UAC 提权。

### 可选环境变量

| 变量 | 默认值 | 作用 |
|---|---|---|
| `SSH_TRACE_PW` | — | 免交互设置 `administrator` 密码 |
| `SSH_TRACE_PORT` | `22` | 换端口 |
| `SSH_TRACE_INSTDIR` | `%ProgramFiles%\OpenSSH-Win64` | 换安装目录 |
| `SSH_TRACE_FORCE_INSTALL` | — | 本机已有他人安装的 `sshd` 时，强制用本工具的程序接管 |
| `SSH_TRACE_FAKEBUILD` | — | 人工指定版本阶梯（调试用） |
| `SSH_TRACE_TEST=1` | — | **空跑**：只调用真实子过程，不装服务、不改系统 |

在新机器上正式使用前，建议先用 `SSH_TRACE_TEST=1` 空跑验证一遍。

## 系统对照表

| 系统 | build | 默认优先尝试 |
|---|---|---|
| Windows Server 2012 / 2012 R2 | 9200 / 9600 | `7.7.2.0` |
| Windows Server 2016 | 14393 | `7.7.2.0` |
| Windows Server 2019 | 17763 | `10.0.0.0` |
| Windows 10 / 11 | 19041+ / 22000+ | `10.0.0.0` |
| Windows 7 / Server 2008 R2 | 7601 | `7.7.2.0`（需先装 KB2999226 通用 C 运行库） |

上表只是默认顺序，实际以自测结果为准 —— 不通就自动换版本。

## 排错

```text
日志:     工具包目录下的 ssh-trace.log
服务状态: sc query sshd
```

**判断服务是不是"活的"**（端口通不代表活）：

```cmd
bin\7.7.2.0\ssh-keyscan.exe -T 8 -t rsa,ed25519 127.0.0.1
```

- 打印 `127.0.0.1 ssh-ed25519 AAAA...` —— 正常。
- 只打印 `# 127.0.0.1:22 SSH-2.0-...` —— 服务在，但会话子进程起不来。这就是
  reset 那个故障。

**前台手工调试**（能看到最原始的报错）：

```cmd
cd /d "C:\Program Files\OpenSSH-Win64"
sshd.exe -ddd -f "%ProgramData%\ssh\sshd_config"
```

然后在另一台机器上连本机，观察这个窗口刷出来的内容。

**端口被占用：** `netstat -ano | findstr :22`

**三套版本全部失败：** 脚本会打印常见原因 —— 目录权限不严、老系统缺运行库、
主机侧安全软件拦截 `sshd` 子进程、端口冲突。

## 获取工具包

本仓库只存放脚本与文档。28 MB 的上游 OpenSSH 二进制**不**纳入版本控制 ——
它们属于第三方可再分发程序，应当放在带版本的构建产物里，而不是 git 历史中。

从 [Releases 页面](https://github.com/hattrick-V/HostTraceAI/releases)
下载已组装好的工具包，或自行从上游构建：

```powershell
powershell -ExecutionPolicy Bypass -File build-kit.ps1
```

该脚本会下载三个固定版本的上游发布包、逐个按硬编码的 SHA-256 校验、铺好
`bin\<版本>\` 目录，并产出 `HostTraceAI-WindowsSSHKit-<version>.zip`。
它只做下载、校验、打包 —— 不安装任何东西、不注册服务、不修改系统状态。
运行后 `bin\` 会留在脚本旁边，因此直接 clone 下来的目录即可使用。

固定的下载来源：

| `bin\` | 上游标签 | 压缩包 SHA-256 |
|---|---|---|
| `7.7.2.0` | `v7.7.2.0p1-Beta` | `8631f000…34fa5bce` |
| `8.9.1.0` | `v8.9.1.0p1-Beta` | `b3d31939…0befb9fc` |
| `10.0.0.0` | `10.0.0.0p2-Preview` | `23f50f34…7b43aba5` |

三套 `bin\` 目录均已与对应的上游压缩包**逐文件比对**，工具包发出去的就是上游
原样的产物 —— 没有打补丁，也没有本地重新编译。若上游将来替换了某个附件，
构建会直接报错，而不是悄悄换掉二进制。

### 压缩包内容

```text
HostTraceAI-WindowsSSHKit-<version>\
    1-启用SSH.bat                  启用 SSH（自动提权）
    2-停止卸载.bat                 停止、卸载与还原
    OpenSSH-Win64-兼容性说明.txt   原始中文现场笔记（GBK）
    README.md / README_CN.md       本文档
    THIRD-PARTY-NOTICES.md         内置第三方许可全文
    LICENSE                        Apache-2.0
    build-kit.ps1                  从上游重新构建该压缩包
    bin\7.7.2.0\                   19 个文件
    bin\8.9.1.0\                   26 个文件
    bin\10.0.0.0\                  33 个文件
```

## 关于编码

`1-启用SSH.bat`、`2-停止卸载.bat` 与 `OpenSSH-Win64-兼容性说明.txt` 是
**GBK 编码 + CRLF 行尾** —— 因为脚本内部执行 `chcp 936` 并输出中文。
`.gitattributes` 把它们标记为 `-text`，git 不会做任何改写。
**请不要转成 UTF-8**，否则控制台输出会乱码。

可读的中文文档以 UTF-8 形式提供在本文件（`README_CN.md`）中。

工具包压缩包内的文件名以 **UTF-8 + ZIP 语言编码标志位** 存放，7-Zip、WinRAR
以及 Windows 10 及以上自带的解压都能正确还原中文名。若用较老的解压工具导致
中文名乱码，工具包依然可用 —— 两个脚本之间并不互相调用，也不按名字读取同目录
的其他文件，所以批处理叫什么名字都能正常跑。

`build-kit.ps1` 本身刻意**只使用 ASCII 字符**。Windows PowerShell 5.1 对没有
BOM 的 `.ps1` 文件按系统 ANSI 代码页解码，非 ASCII 源码在部分机器上会损坏。

## 适用范围与授权

本工具会**启用内置 `administrator` 账号、设置其密码、并开放一个防火墙端口**。
它仅用于已获明确授权的主机调查与事件响应，且只应在你被书面许可访问的主机上
使用。`2-停止卸载.bat` 的存在就是为了让改动完全可逆 —— 调查结束请务必执行。

请勿在你不拥有、或未获书面授权调查的系统上使用。

## 许可

本目录下的脚本与文档采用 Apache License 2.0 许可 —— 全文见本目录
[`LICENSE`](LICENSE)，项目整体的许可见仓库根目录 [`LICENSE`](../../LICENSE)。

内置的 OpenSSH 二进制**不适用**该许可。它们按各自的上游条款再分发 ——
OpenSSH（BSD/ISC/MIT）、OpenSSL、LibreSSL、zlib、libfido2、libcbor。
完整文本与必须保留的致谢语句见
[`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md)。
上游项目：[PowerShell/Win32-OpenSSH](https://github.com/PowerShell/Win32-OpenSSH)。
