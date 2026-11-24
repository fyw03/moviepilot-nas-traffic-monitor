"""NAS 流量统计插件 - 核心逻辑层。

职责：SQLite 持久化、日志/下载器/网卡三类数据源采集、IP 内外网判定、格式化工具。
只包含纯逻辑，不持有跨调用的可变全局状态；所有运行状态由插件实例保存在自身或数据库中。
"""
from __future__ import annotations

import ipaddress
import re
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.sdk.logging import logger

LOG_TAG = "[NAS流量统计] "

# 默认内网网段（RFC1918 + 本机 + IPv6 ULA/链路本地）
DEFAULT_LAN_CIDRS = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
]

# 默认"视频流请求"URL 匹配规则（忽略大小写）。
# 覆盖常见视频扩展名 + 飞牛影视/通用媒体服务的播放接口路径。
DEFAULT_VIDEO_PATTERN = (
    r"\.(mp4|mkv|avi|mov|m4v|ts|m2ts|webm|flv|wmv|rm|rmvb|vob|iso|"
    r"mpg|mpeg|3gp|ogv|m3u8|mpd)(\?|$)|"
    r"/(video|videos|stream|streaming|play|playback|media|vod|file|download)/|"
    r"/api/v1/(file|media|video|stream)|/trim/(media|video|stream)"
)

# nginx combined / 常用日志格式解析：
# $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent ...
NGINX_LINE_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<bytes>\d+|-)'
)

# 单次日志最多读取字节数，防止长期未采集时一次性读入过大文件
MAX_LOG_READ_BYTES = 64 * 1024 * 1024

# 每日统计表的数值字段白名单，UPDATE 增量时使用
DAILY_NUM_FIELDS = (
    "media_wan_up", "media_lan_up", "media_wan_down", "media_lan_down",
    "media_req_wan", "media_req_lan", "qb_up", "qb_down",
    "tr_up", "tr_down", "nic_rx", "nic_tx",
)


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------

def build_lan_networks(cidrs: Optional[List[str]]) -> List[ipaddress._BaseNetwork]:
    """把字符串列表解析为 IP 网段对象列表，忽略非法项。"""
    networks: List[ipaddress._BaseNetwork] = []
    for item in cidrs or DEFAULT_LAN_CIDRS:
        text = str(item).strip()
        if not text:
            continue
        try:
            networks.append(ipaddress.ip_network(text, strict=False))
        except ValueError:
            logger.warning(f"{LOG_TAG}忽略无效内网段：{text}")
    return networks


def is_lan_ip(ip: str, networks: List[ipaddress._BaseNetwork]) -> bool:
    """判断 IP 是否属于内网段。非法/空 IP 一律按外网处理。"""
    text = str(ip or "").strip()
    if not text or text in {"-", "unknown", "0.0.0.0"}:
        return False
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    for net in networks:
        if addr.version == net.version and addr in net:
            return True
    return False


def compile_log_pattern(pattern: Optional[str]):
    """编译访问日志行正则；失败时回退到标准 combined 格式。

    自定义正则必须包含命名组：ip、time、request、status、bytes。
    其中 bytes 对应响应字节数（$body_bytes_sent），即 NAS 对外上传流量。
    """
    try:
        return re.compile(pattern or NGINX_LINE_RE.pattern)
    except re.error as err:
        logger.warning(f"{LOG_TAG}日志正则无效，已使用默认规则：{err}")
        return NGINX_LINE_RE


def compile_video_pattern(pattern: Optional[str]):
    """编译视频匹配正则，失败时回退到默认规则。"""
    try:
        return re.compile(pattern or DEFAULT_VIDEO_PATTERN, re.IGNORECASE)
    except re.error as err:
        logger.warning(f"{LOG_TAG}视频匹配正则无效，已使用默认规则：{err}")
        return re.compile(DEFAULT_VIDEO_PATTERN, re.IGNORECASE)


def format_size(num: Any) -> str:
    """把字节数格式化为人类可读字符串。"""
    try:
        value = float(num or 0)
    except (TypeError, ValueError):
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    idx = 0
    while abs(value) >= 1024 and idx < len(units) - 1:
        value /= 1024
        idx += 1
    return f"{value:.2f} {units[idx]}"


def format_speed(num: Any) -> str:
    """把字节每秒格式化为可读速度。"""
    return f"{format_size(num)}/s"


def today_str() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def month_start_str() -> str:
    return datetime.now().strftime("%Y-%m-01")


# ---------------------------------------------------------------------------
# SQLite 存储层
# ---------------------------------------------------------------------------

class TrafficStore:
    """插件自有 SQLite 存储，数据库文件位于插件数据目录。"""

    def __init__(self, db_path: Path):
        self.db_path = str(Path(db_path) / "traffic.db")
        self._ensure_tables()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=15)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_tables(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS daily (
                    day TEXT PRIMARY KEY,
                    media_wan_up INTEGER DEFAULT 0,
                    media_lan_up INTEGER DEFAULT 0,
                    media_wan_down INTEGER DEFAULT 0,
                    media_lan_down INTEGER DEFAULT 0,
                    media_req_wan INTEGER DEFAULT 0,
                    media_req_lan INTEGER DEFAULT 0,
                    qb_up INTEGER DEFAULT 0,
                    qb_down INTEGER DEFAULT 0,
                    tr_up INTEGER DEFAULT 0,
                    tr_down INTEGER DEFAULT 0,
                    nic_rx INTEGER DEFAULT 0,
                    nic_tx INTEGER DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS log_cursor (
                    path TEXT PRIMARY KEY,
                    inode INTEGER DEFAULT 0,
                    offset INTEGER DEFAULT 0,
                    updated_at TEXT
                );
                CREATE TABLE IF NOT EXISTS dl_snapshot (
                    name TEXT PRIMARY KEY,
                    up_total INTEGER DEFAULT 0,
                    down_total INTEGER DEFAULT 0,
                    updated_at TEXT
                );
                CREATE TABLE IF NOT EXISTS nic_snapshot (
                    iface TEXT PRIMARY KEY,
                    rx_total INTEGER DEFAULT 0,
                    tx_total INTEGER DEFAULT 0,
                    updated_at TEXT
                );
                CREATE TABLE IF NOT EXISTS media_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT,
                    ip TEXT,
                    scope TEXT,
                    bytes INTEGER,
                    status INTEGER,
                    url TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_media_events_ts ON media_events(ts);
                """
            )

    # -- 每日聚合 -----------------------------------------------------------
    def add_daily(self, day: str, **fields: int) -> None:
        """把增量字段累加到指定日期。fields 的键必须在白名单内。"""
        valid = {k: int(v or 0) for k, v in fields.items() if k in DAILY_NUM_FIELDS and int(v or 0)}
        if not valid:
            return
        cols = ", ".join(valid.keys())
        placeholders = ", ".join("?" for _ in valid)
        updates = ", ".join(f"{k} = {k} + excluded.{k}" for k in valid)
        sql = (
            f"INSERT INTO daily (day, {cols}) VALUES (?, {placeholders}) "
            f"ON CONFLICT(day) DO UPDATE SET {updates}"
        )
        with self._connect() as conn:
            conn.execute(sql, [day] + list(valid.values()))

    def get_daily(self, start_day: str, end_day: Optional[str] = None) -> List[Dict[str, Any]]:
        end_day = end_day or "9999-12-31"
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM daily WHERE day BETWEEN ? AND ? ORDER BY day",
                (start_day, end_day),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_totals(self) -> Dict[str, int]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT " + ", ".join(f"COALESCE(SUM({f}),0) AS {f}" for f in DAILY_NUM_FIELDS) + " FROM daily"
            ).fetchone()
        return {f: int(row[f] or 0) for f in DAILY_NUM_FIELDS}

    # -- 日志游标 -----------------------------------------------------------
    def get_cursor(self, path: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM log_cursor WHERE path = ?", (path,)).fetchone()
        return dict(row) if row else None

    def set_cursor(self, path: str, inode: int, offset: int) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO log_cursor (path, inode, offset, updated_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(path) DO UPDATE SET inode=excluded.inode, offset=excluded.offset, "
                "updated_at=excluded.updated_at",
                (path, int(inode), int(offset), datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            )

    # -- 下载器快照 ---------------------------------------------------------
    def get_dl_snapshot(self, name: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM dl_snapshot WHERE name = ?", (name,)).fetchone()
        return dict(row) if row else None

    def set_dl_snapshot(self, name: str, up: int, down: int) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO dl_snapshot (name, up_total, down_total, updated_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(name) DO UPDATE SET up_total=excluded.up_total, "
                "down_total=excluded.down_total, updated_at=excluded.updated_at",
                (name, int(up), int(down), datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            )

    # -- 网卡快照 -----------------------------------------------------------
    def get_nic_snapshots(self) -> Dict[str, Dict[str, int]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM nic_snapshot").fetchall()
        return {row["iface"]: {"rx": int(row["rx_total"]), "tx": int(row["tx_total"])} for row in rows}

    def set_nic_snapshot(self, iface: str, rx: int, tx: int) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO nic_snapshot (iface, rx_total, tx_total, updated_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(iface) DO UPDATE SET rx_total=excluded.rx_total, "
                "tx_total=excluded.tx_total, updated_at=excluded.updated_at",
                (iface, int(rx), int(tx), datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            )

    # -- 视频明细 -----------------------------------------------------------
    def add_media_events(self, events: List[Dict[str, Any]]) -> None:
        if not events:
            return
        with self._connect() as conn:
            conn.executemany(
                "INSERT INTO media_events (ts, ip, scope, bytes, status, url) VALUES (?, ?, ?, ?, ?, ?)",
                [
                    (
                        e.get("ts"), e.get("ip"), e.get("scope"),
                        int(e.get("bytes", 0)), int(e.get("status", 0)), e.get("url"),
                    )
                    for e in events
                ],
            )

    def get_media_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT ts, ip, scope, bytes, status, url FROM media_events ORDER BY id DESC LIMIT ?",
                (int(limit),),
            ).fetchall()
        return [dict(row) for row in rows]

    def cleanup(self, retain_days: int) -> None:
        """清理超过保留期的明细，聚合数据保留。"""
        try:
            days = max(1, int(retain_days or 90))
        except (TypeError, ValueError):
            days = 90
        cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
        with self._connect() as conn:
            conn.execute("DELETE FROM media_events WHERE ts < ?", (cutoff,))


# ---------------------------------------------------------------------------
# 采集函数
# ---------------------------------------------------------------------------

def collect_nginx_log(
    store: TrafficStore,
    log_path: str,
    video_re,
    networks: List[ipaddress._BaseNetwork],
    line_re=None,
) -> Dict[str, Any]:
    """增量解析 nginx 访问日志，统计视频流请求的内外网上传流量。

    返回值：ok / error / wan_bytes / lan_bytes / wan_reqs / lan_reqs / events
    """
    result: Dict[str, Any] = {
        "ok": False, "error": "", "wan_bytes": 0, "lan_bytes": 0,
        "wan_reqs": 0, "lan_reqs": 0, "events": [],
    }
    path = Path(log_path)
    if not path.exists():
        result["error"] = f"日志文件不存在：{log_path}"
        return result
    line_re = line_re or NGINX_LINE_RE
    try:
        stat = path.stat()
        inode = stat.st_ino
        cursor = store.get_cursor(str(path))
        offset = int(cursor["offset"]) if cursor and int(cursor["inode"]) == inode else 0
        if offset > stat.st_size:
            offset = 0  # 日志被清空/截断

        with open(path, "rb") as fh:
            fh.seek(offset)
            data = fh.read(MAX_LOG_READ_BYTES)

        last_nl = data.rfind(b"\n")
        if last_nl < 0:
            # 尚无完整新行，维持游标
            store.set_cursor(str(path), inode, offset)
            result["ok"] = True
            return result

        complete = data[: last_nl + 1]
        new_offset = offset + len(complete)
        text = complete.decode("utf-8", errors="replace")
        events: List[Dict[str, Any]] = []
        for line in text.splitlines():
            match = line_re.match(line.strip())
            if not match:
                continue
            try:
                groups = match.groupdict()
                method, _, url = groups["request"].partition(" ")
                status = int(groups["status"])
                size_text = str(groups["bytes"])
                ip = groups["ip"]
            except (KeyError, ValueError, IndexError):
                continue
            if method.upper() != "GET":
                continue
            if status not in (200, 206):
                continue
            size = int(size_text) if size_text.isdigit() else 0
            if size <= 0 or not video_re.search(url):
                continue
            scope = "lan" if is_lan_ip(ip, networks) else "wan"
            events.append({
                "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "ip": ip,
                "scope": scope,
                "bytes": size,
                "status": status,
                "url": url[:500],
            })

        store.set_cursor(str(path), inode, new_offset)
        wan_events = [e for e in events if e["scope"] == "wan"]
        lan_events = [e for e in events if e["scope"] == "lan"]
        result.update({
            "ok": True,
            "wan_bytes": sum(e["bytes"] for e in wan_events),
            "lan_bytes": sum(e["bytes"] for e in lan_events),
            "wan_reqs": len(wan_events),
            "lan_reqs": len(lan_events),
            "events": events,
        })
        return result
    except Exception as err:  # noqa: BLE001 - 采集失败不能影响主程序
        result["error"] = str(err)
        logger.warning(f"{LOG_TAG}解析 nginx 日志失败：{err}")
        return result


def extract_transfer_info(service_type: str, info: Any) -> Optional[Dict[str, int]]:
    """从 qBittorrent / Transmission 的 transfer_info() 结果中提取累计量与速度。"""
    try:
        if service_type == "qbittorrent":
            get = info.get if hasattr(info, "get") else lambda k, d=0: getattr(info, k, d)
            return {
                "up": int(get("up_info_data", 0) or 0),
                "down": int(get("dl_info_data", 0) or 0),
                "up_speed": int(get("up_info_speed", 0) or 0),
                "down_speed": int(get("dl_info_speed", 0) or 0),
            }
        if service_type == "transmission":
            cumulative = getattr(info, "cumulative_stats", None) or {}
            cget = cumulative.get if hasattr(cumulative, "get") else lambda k, d=0: getattr(cumulative, k, d)
            return {
                "up": int(cget("uploaded_bytes", 0) or 0),
                "down": int(cget("downloaded_bytes", 0) or 0),
                "up_speed": int(getattr(info, "upload_speed", 0) or 0),
                "down_speed": int(getattr(info, "download_speed", 0) or 0),
            }
    except Exception as err:  # noqa: BLE001
        logger.warning(f"{LOG_TAG}解析 {service_type} 传输信息失败：{err}")
    return None


def read_net_dev(path: str) -> Dict[str, Dict[str, int]]:
    """读取 /proc/net/dev，返回各物理网卡的累计收发字节数。"""
    result: Dict[str, Dict[str, int]] = {}
    skip_prefixes = ("lo", "docker", "veth", "br-", "virbr", "vnet", "tap", "dummy", "sit", "tun")
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()[2:]
        for line in lines:
            if ":" not in line:
                continue
            name, values = line.split(":", 1)
            name = name.strip()
            if name.startswith(skip_prefixes):
                continue
            fields = values.split()
            if len(fields) < 9:
                continue
            result[name] = {"rx": int(fields[0]), "tx": int(fields[8])}
    except Exception as err:  # noqa: BLE001
        logger.warning(f"{LOG_TAG}读取网卡流量失败（{path}）：{err}")
    return result
