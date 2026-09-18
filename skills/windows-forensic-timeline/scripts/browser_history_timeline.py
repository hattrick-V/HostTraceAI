# -*- coding: utf-8 -*-
"""解析 Chrome / Edge 的 History（SQLite），输出可并入取证时间线的 CSV。

用法（本地侧，先只读复制目标机上的 History 文件再解析）：
    python browser_history_timeline.py <History路径> <输出.csv> [主机本地时区偏移，默认 8]
    python browser_history_timeline.py ./raw/History ./raw/history_timeline.csv 8

要点：
  * 源库可能被浏览器独占/处于 WAL 状态，脚本以 immutable 只读方式打开副本；
    若失败，请先把 History 复制到本地（SFTP 拉回）再跑。
  * Chrome/Edge 时间戳 = 自 1601-01-01 UTC 起的**微秒数**，本脚本统一换算成
    主机本地时间（含偏移）与 UTC 双列，便于与文件 MACB / 事件日志对齐。
  * 只读解析，不修改源库；输出列：kind,time_local,time_utc,url,target_path,detail
"""
import csv
import os
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

CHROME_EPOCH_OFFSET = 11644473600  # 1601-01-01 -> 1970-01-01 的秒数


def chrome_to_dt(us):
    """Chrome/Edge 微秒时间戳 -> (UTC aware datetime, None on error)。"""
    try:
        us = int(us or 0)
    except (TypeError, ValueError):
        return None
    if us <= 0:
        return None
    try:
        return datetime.fromtimestamp(us / 1_000_000 - CHROME_EPOCH_OFFSET, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def open_ro(path):
    uri = "file:%s?immutable=1" % path.replace("\\", "/")
    return sqlite3.connect(uri, uri=True)


def table_exists(conn, name):
    row = conn.execute("select name from sqlite_master where type='table' and name=?", (name,)).fetchone()
    return bool(row)


def collect(conn, tz_offset):
    rows = []

    def emit(kind, dt, url="", target="", detail=""):
        if dt is None:
            return
        local = dt + timedelta(hours=tz_offset)
        rows.append({
            "kind": kind,
            "time_local": local.strftime("%Y-%m-%d %H:%M:%S"),
            "time_utc": dt.strftime("%Y-%m-%d %H:%M:%S"),
            "url": (url or "").replace("\n", " ")[:300],
            "target_path": (target or "").replace("\n", " ")[:300],
            "detail": str(detail or "")[:200],
        })

    if table_exists(conn, "downloads"):
        q = ("select target_path, tab_url, total_bytes, start_time, end_time "
             "from downloads")
        try:
            for target, url, size, start, end in conn.execute(q):
                dt = chrome_to_dt(end) or chrome_to_dt(start)
                emit("download", dt, url, target, "%s bytes" % size)
        except sqlite3.Error as exc:
            print("[warn] downloads 表解析失败: %s" % exc, file=sys.stderr)

    if table_exists(conn, "visits") and table_exists(conn, "urls"):
        q = ("select u.url, v.visit_time, v.transition, u.title "
             "from visits v join urls u on u.id = v.url order by v.visit_time")
        try:
            for url, ts, transition, title in conn.execute(q):
                emit("visit", chrome_to_dt(ts), url, "", "transition=%s title=%s" % (transition, title))
        except sqlite3.Error as exc:
            print("[warn] visits/urls 解析失败: %s" % exc, file=sys.stderr)

    rows.sort(key=lambda r: (r["time_local"], r["kind"]))
    return rows


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    src, out = argv[0], argv[1]
    tz_offset = float(argv[2]) if len(argv) > 2 else 8.0
    if not os.path.exists(src):
        print("源文件不存在: %s" % src, file=sys.stderr)
        return 1
    conn = open_ro(src)
    try:
        rows = collect(conn, tz_offset)
    finally:
        conn.close()
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=["kind", "time_local", "time_utc", "url", "target_path", "detail"])
        writer.writeheader()
        writer.writerows(rows)
    print("解析 %d 条记录 -> %s（本地时区 UTC%+g）" % (len(rows), out, tz_offset))
    for r in rows[:20]:
        print("  %s | %s | %s | %s" % (r["time_local"], r["kind"], r["url"][:60], r["target_path"][:60]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
