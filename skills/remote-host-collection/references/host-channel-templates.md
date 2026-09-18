# 主机通道脚本模板（只读采集）

配套 `SKILL.md` 的 S3/S6 使用。凭据由平台通道/凭据库注入——模板内**不出现明文口令**，也不要写进本地配置文件。

## 1. 通用只读采集骨架（Paramiko）

```python
import hashlib, os, time
import paramiko

HOST, PORT, USER = "<target-ip>", 22, "<user>"
CASE = os.path.join("<case-dir>", "hosts", "<host>")

def connect():
    c = paramiko.SSHClient()
    c.load_system_host_keys()                       # 复用已核对过指纹的 known_hosts
    c.set_missing_host_key_policy(paramiko.RejectPolicy())
    c.connect(HOST, port=PORT, username=USER, timeout=15,
              banner_timeout=20, auth_timeout=20,
              allow_agent=False, look_for_keys=False)  # 只走通道注入的凭据
    return c

def run(c, cmd, timeout=60, encoding="utf-8"):
    """同步执行一条只读命令；返回 (退出码, 解码后的输出)。"""
    _, out, err = c.exec_command(f"timeout {timeout} bash -lc {cmd!r}")
    raw = out.read()                                # 必须 read() 才等到结束
    err_raw = err.read()
    rc = out.channel.recv_exit_status()             # 显式取退出码
    os.makedirs(os.path.join(CASE, "raw"), exist_ok=True)
    open(os.path.join(CASE, "raw", "_last_cmd.txt"), "w", encoding="utf-8").write(cmd)
    open(os.path.join(CASE, "raw", "_last_raw.bin"), "wb").write(raw)   # 先存原始字节
    return rc, raw.decode(encoding, "replace"), err_raw.decode(encoding, "replace")

def retry(c, cmd, tries=3, **kw):
    for i in range(tries):
        try:
            rc, o, e = run(c, cmd, **kw)
            if rc == 0 or "exit status" not in e:
                return rc, o, e
        except Exception as ex:                     # 通道断开/超时
            print(f"[retry {i+1}] {type(ex).__name__}: {ex}")
        time.sleep(2 ** (i + 1))                    # 退避 2s/4s/8s
    return -1, "", "channel failed after retries"
```

## 2. 只读外带 + 哈希复核

```python
def pull(c, remote, local_name, sha_cmd="sha256sum"):
    sftp = c.open_sftp()
    remote_hash = run(c, f"{sha_cmd} {remote!r}")[1].split()[0]
    remote_size = int(run(c, f"stat -c %s {remote!r}")[1].strip())
    local = os.path.join(CASE, "samples", local_name)
    os.makedirs(os.path.dirname(local), exist_ok=True)
    for attempt in range(3):
        sftp.get(remote, local)                     # 二进制方式，不经文本编解码
        h = hashlib.sha256(open(local, "rb").read()).hexdigest()
        if h == remote_hash and os.path.getsize(local) == remote_size:
            sftp.close()
            return {"local": local, "sha256": h, "size": remote_size, "verified": True}
        print(f"[pull retry {attempt+1}] hash mismatch: {h} != {remote_hash}")
    sftp.close()
    return {"local": local, "sha256": None, "size": remote_size, "verified": False}
```

要点：

- 先取远端哈希与大小，再传输，传回后本机复算；三者一致才算成功。
- 不要在命令通道上用 `cat`/`type` 拼二进制流——编码与行尾转换会破坏文件，且哈希必然不符。
- 大文件分段拉取（记录已传偏移）或先压缩；压缩会写目标机临时文件，属处置动作，需审批。
- 采集物落盘路径固定为 `<case-dir>/hosts/<host>/samples/`，命名不用中文或空格。

## 3. Windows 主机的通道坑（Win32-OpenSSH）

- **SFTP 路径形态**：要 `/D:/path/file`，不要 `D:\path\file`；先 `sftp.listdir("/D:")` 确认盘符，再用 `sftp.stat()` 核对存在性与大小。
- **`dir` / `if exist` 会假报文件不存在**：路径经转义后可能误判，判真伪以 `sftp.stat()` / `sftp.listdir_attr()` 为准。
- **会话作用域的盘符映射对 SSH 服务不可见**：用户在交互式桌面里 `net use Z:` 建立的映射在服务上下文里不存在；要么取 UNC 路径，要么请用户在交互会话里取文件，不要把时间耗在重新映射上。
- **多行 `python -c` 经 SSH 会被压成一行**报 SyntaxError：改用脚本文件，或严格写成单行。
- **服务未就绪与协议未通不同**：端口可连不等于协议可用，先用真实握手/横幅验证通道，再决定是否重试或上报。

## 4. 通道不可用时的合规退路

1. 换用平台能力中心里另一条已授权通道（同主机不同通道）。
2. 让用户在主机本地会话执行同一批只读命令，并把输出与哈希回传，落盘时标注"人工采集，可信度中"。
3. 通过镜像离线采集（内存/磁盘镜像），采集口径与时间线单独标注。

无论哪条退路，都不得对非目标主机发起连接或扫描，也不得使用来源不明的凭据。
