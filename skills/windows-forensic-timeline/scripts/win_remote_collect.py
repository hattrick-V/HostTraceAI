# -*- coding: utf-8 -*-
"""Windows 主机远程取证驱动（paramiko）：逐条执行命令、批量落盘、拉回文件。

用法（本地侧，用平台 execute 调用）：
    export TRACE_HOST=<target-ip> TRACE_PORT=22 TRACE_USER=<user> TRACE_PWD=<password>
    export TRACE_RAW=<case-dir>/raw
    python win_remote_collect.py whoami /all          # 直接跑一条命令
    python win_remote_collect.py --file cmds.txt      # 批量跑文件里的命令（每行一条）
    python win_remote_collect.py --pull 'C:\\Windows\\Temp\\out\\sys.csv' ./raw/sys.csv

约定与坑（别改）：
  * 主机、账号、口令一律由环境变量注入，**脚本内不写死任何地址与凭据**。
  * run() 用 recv_ready 轮询 + 硬性 deadline：远端命令挂住时 chan.recv_exit_status() 会永久阻塞。
  * 每条命令的输出都落盘到 TRACE_RAW，便于事后复核与出证据清单（首行记录命令原文与返回码）。
  * pull()/pull_dir() 用于把远端落盘的长输出（CSV/日志/样本）拉回本地。
  * wait_online() 用于目标机重启/瞬断期间自动重试，连上即补采。
"""
import os
import sys
import time
import hashlib

import paramiko

HOST = os.environ.get("TRACE_HOST", "")
PORT = int(os.environ.get("TRACE_PORT", "22"))
USER = os.environ.get("TRACE_USER", "")
PWD = os.environ.get("TRACE_PWD", "")
RAW = os.environ.get("TRACE_RAW", "./raw")
PS = 'powershell -NoProfile -ExecutionPolicy Bypass -Command "%s"'


def client(host=None, port=None, user=None, pwd=None, timeout=30):
    """建立 SSH 会话。参数为空时回落到环境变量。"""
    host = host or HOST
    user = user or USER
    pwd = pwd or PWD
    if not host or not user:
        raise ValueError("缺少主机/账号：请设置 TRACE_HOST / TRACE_USER 环境变量")
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(host, port=port or PORT, username=user, password=pwd or None,
              timeout=timeout, allow_agent=False, look_for_keys=False)
    return c


def run(c, cmd, timeout=120):
    """执行单条命令；超时强制关通道并返回部分输出（绝不挂死）。"""
    chan = c.get_transport().open_session()
    chan.settimeout(10)
    chan.exec_command(cmd)
    out = b""
    err = b""
    rc = -1
    deadline = time.time() + timeout
    while True:
        try:
            if chan.recv_ready():
                out += chan.recv(65536)
                continue
            if chan.recv_stderr_ready():
                err += chan.recv_stderr(65536)
                continue
            if chan.exit_status_ready():
                while chan.recv_ready():
                    out += chan.recv(65536)
                while chan.recv_stderr_ready():
                    err += chan.recv_stderr(65536)
                rc = chan.recv_exit_status()
                break
        except Exception:
            pass
        if time.time() > deadline:
            err += b"\n<<driver: TIMEOUT, channel closed>>"
            break
        time.sleep(0.05)
    chan.close()

    def dec(buf):
        if not buf:
            return ""
        for enc in ("utf-8", "gbk", "latin-1"):
            try:
                return buf.decode(enc)
            except Exception:
                continue
        return repr(buf)

    return rc, dec(out), dec(err)


def sanitize(name):
    keep = []
    for ch in name:
        keep.append(ch if ch.isalnum() or ch in "-_." else "_")
    return "".join(keep)[:80] or "cmd"


def runset(c, tag, cmds, timeout=180):
    """批量执行命令并把每条输出落盘到 RAW/<tag>__<name>.txt；返回 {name: stdout}。"""
    os.makedirs(RAW, exist_ok=True)
    res = {}
    for name, cmd in cmds:
        rc, out, err = run(c, cmd, timeout)
        body = "$ %s\n[rc=%s]\n%s%s" % (cmd, rc, out, ("\n[stderr]\n" + err) if err.strip() else "")
        path = os.path.join(RAW, "%s__%s.txt" % (tag, sanitize(name)))
        with open(path, "w", encoding="utf-8") as f:
            f.write(body)
        res[name] = out
        print("### %s/%s rc=%s len=%d -> %s" % (tag, name, rc, len(out), path))
    return res


def sha256(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def pull(c, remote, local):
    """SFTP 拉取单个文件，返回 (size, sha256)。"""
    os.makedirs(os.path.dirname(local) or ".", exist_ok=True)
    sftp = c.open_sftp()
    try:
        sftp.get(remote, local)
    finally:
        sftp.close()
    return os.path.getsize(local), sha256(local)


def pull_dir(c, remote_dir, local_dir, skip_dirs=True):
    """递归拉取远端目录（默认跳过子目录，避免跟随重解析点）。返回证据清单行。"""
    sftp = c.open_sftp()
    rows = []
    try:
        os.makedirs(local_dir, exist_ok=True)
        for attr in sftp.listdir_attr(remote_dir):
            if skip_dirs and (attr.st_mode & 0o40000):
                continue
            local_path = os.path.join(local_dir, attr.filename)
            remote_path = remote_dir.rstrip("\\") + "\\" + attr.filename
            sftp.get(remote_path, local_path)
            rows.append("%012d  %s  %s" % (os.path.getsize(local_path), sha256(local_path), remote_path))
    finally:
        sftp.close()
    return rows


def wait_online(host=None, port=None, attempts=50, delay=30):
    """目标机重启/瞬断时使用：连上即返回 client，否则按 delay 重试。"""
    last = None
    for i in range(attempts):
        try:
            return client(host=host, port=port)
        except Exception as exc:  # noqa: BLE001
            last = exc
            print("attempt %d failed: %s %s" % (i + 1, type(exc).__name__, str(exc)[:80]))
            time.sleep(delay)
    raise last


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    conn = client()
    try:
        if argv[0] == "--file":
            with open(argv[1], "r", encoding="utf-8") as f:
                cmds = [(ln.strip(), ln.strip()) for ln in f if ln.strip() and not ln.startswith("#")]
            runset(conn, os.path.basename(argv[1]).split(".")[0], cmds)
        elif argv[0] == "--pull":
            size, digest = pull(conn, argv[1], argv[2])
            print("pulled %s -> %s (%d bytes, sha256=%s)" % (argv[1], argv[2], size, digest))
        else:
            cmd = " ".join(argv)
            rc, out, err = run(conn, cmd, timeout=300)
            os.makedirs(RAW, exist_ok=True)
            path = os.path.join(RAW, "%s__%s.txt" % ("adhoc", sanitize(cmd)))
            with open(path, "w", encoding="utf-8") as f:
                f.write("$ %s\n[rc=%s]\n%s%s" % (cmd, rc, out, ("\n[stderr]\n" + err) if err.strip() else ""))
            print(out)
            if err.strip():
                print("[stderr]\n" + err, file=sys.stderr)
            print("### rc=%s -> %s" % (rc, path))
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except ValueError as exc:
        print("[配置错误] %s" % exc, file=sys.stderr)
        print("示例: export TRACE_HOST=<target-ip> TRACE_USER=<user> TRACE_PWD=<password> TRACE_RAW=<case-dir>/raw", file=sys.stderr)
        sys.exit(1)

