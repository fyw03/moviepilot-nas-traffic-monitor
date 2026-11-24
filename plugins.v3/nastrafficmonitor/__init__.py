"""NAS 流量统计插件（MoviePilot V3）。

统计三类流量：
1. 飞牛影视视频播放流量，按来源 IP 区分内网/外网（解析 nginx access.log）
2. qBittorrent / Transmission 的上传下载增量（读取下载器累计传输量）
3. 整机网卡收发流量（读取 /proc/net/dev）

提供插件详情页汇总卡片 + 明细表 + 历史趋势，以及首页仪表盘小组件。
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import pytz
from apscheduler.schedulers.background import BackgroundScheduler
from pydantic import BaseModel, Field

from app import schemas
from app.sdk.config import settings
from app.sdk.logging import logger
from app.sdk.plugin import _PluginBase
from app.sdk.services import DownloaderHelper

from .core import (
    DAILY_NUM_FIELDS,
    LOG_TAG,
    TrafficStore,
    build_lan_networks,
    collect_nginx_log,
    compile_log_pattern,
    compile_video_pattern,
    extract_transfer_info,
    format_size,
    format_speed,
    month_start_str,
    read_net_dev,
    today_str,
)


# ---------------------------------------------------------------------------
# API 响应模型
# ---------------------------------------------------------------------------

class SummaryData(BaseModel):
    today: Dict[str, int] = Field(default_factory=dict)
    month: Dict[str, int] = Field(default_factory=dict)
    total: Dict[str, int] = Field(default_factory=dict)
    downloaders: List[Dict[str, Any]] = Field(default_factory=list)
    updated_at: str = ""
    errors: List[str] = Field(default_factory=list)


class HistoryPoint(BaseModel):
    day: str
    media_wan_up: int = 0
    media_lan_up: int = 0
    media_wan_down: int = 0
    media_lan_down: int = 0
    media_req_wan: int = 0
    media_req_lan: int = 0
    qb_up: int = 0
    qb_down: int = 0
    tr_up: int = 0
    tr_down: int = 0
    nic_rx: int = 0
    nic_tx: int = 0


class HistoryData(BaseModel):
    points: List[HistoryPoint] = Field(default_factory=list)


class EventsData(BaseModel):
    events: List[Dict[str, Any]] = Field(default_factory=list)


class CollectData(BaseModel):
    message: str = ""
    detail: Dict[str, Any] = Field(default_factory=dict)


class StatusData(BaseModel):
    log_path: str = ""
    log_exists: bool = False
    net_dev_path: str = ""
    net_dev_exists: bool = False
    downloader_count: int = 0
    last_updated: str = ""


# ---------------------------------------------------------------------------
# 主插件
# ---------------------------------------------------------------------------

class NasTrafficMonitor(_PluginBase):
    """飞牛 NAS 流量统计：视频（内外网）/ 下载器 / 整机网卡。"""

    plugin_name = "NAS流量统计"
    plugin_desc = "统计飞牛影视视频播放（区分内外网）、qB/TR 下载器与整机网卡流量，含历史趋势与仪表盘。"
    plugin_icon = "statistic.png"
    plugin_version = "1.0.0"
    plugin_author = "workbuddy"
    author_url = ""
    plugin_config_prefix = "nastrafficmonitor_"
    plugin_order = 50
    auth_level = 1

    # 运行状态（全部保存在实例上，不用模块级全局）
    _enabled: bool = False
    _onlyonce: bool = False
    _store: Optional[TrafficStore] = None
    _once_scheduler: Optional[BackgroundScheduler] = None

    _nginx_log_path: str = "/usr/trim/nginx/logs/access.log"
    _net_dev_path: str = "/proc/net/dev"
    _lan_cidrs: str = ""
    _video_pattern: str = ""
    _log_pattern: str = ""
    _interval: int = 5
    _retain_days: int = 90
    _downloaders: List[str] = []
    _enable_media: bool = True
    _enable_downloader: bool = True
    _enable_nic: bool = True
    _dashboard_type: str = "today"

    # -----------------------------------------------------------------------
    # 基础属性
    # -----------------------------------------------------------------------
    @property
    def store(self) -> TrafficStore:
        """延迟初始化插件自有数据库，避免初始化顺序问题。"""
        if self._store is None:
            self._store = TrafficStore(self.get_data_path())
        return self._store

    @staticmethod
    def _to_int(value: Any, default: int) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def _current_config(self) -> Dict[str, Any]:
        return {
            "enabled": bool(self._enabled),
            "onlyonce": bool(self._onlyonce),
            "nginx_log_path": self._nginx_log_path,
            "net_dev_path": self._net_dev_path,
            "lan_cidrs": self._lan_cidrs,
            "video_pattern": self._video_pattern,
            "log_pattern": self._log_pattern,
            "interval": self._interval,
            "retain_days": self._retain_days,
            "downloaders": self._downloaders,
            "enable_media": self._enable_media,
            "enable_downloader": self._enable_downloader,
            "enable_nic": self._enable_nic,
            "dashboard_type": self._dashboard_type,
        }

    # -----------------------------------------------------------------------
    # 生命周期
    # -----------------------------------------------------------------------
    def init_plugin(self, config: Optional[Dict[str, Any]] = None) -> None:
        config = config or {}
        self.stop_service()

        self._enabled = bool(config.get("enabled"))
        self._onlyonce = bool(config.get("onlyonce"))
        self._nginx_log_path = str(config.get("nginx_log_path") or "/usr/trim/nginx/logs/access.log")
        self._net_dev_path = str(config.get("net_dev_path") or "/proc/net/dev")
        self._lan_cidrs = str(config.get("lan_cidrs") or "")
        self._video_pattern = str(config.get("video_pattern") or "")
        self._log_pattern = str(config.get("log_pattern") or "")
        self._interval = max(1, self._to_int(config.get("interval"), 5))
        self._retain_days = max(1, self._to_int(config.get("retain_days"), 90))
        self._downloaders = list(config.get("downloaders") or [])
        self._enable_media = bool(config.get("enable_media", True))
        self._enable_downloader = bool(config.get("enable_downloader", True))
        self._enable_nic = bool(config.get("enable_nic", True))
        self._dashboard_type = str(config.get("dashboard_type") or "today")

        if self._enabled and self._onlyonce:
            self._onlyonce = False
            self.update_config(self._current_config())
            self._once_scheduler = BackgroundScheduler(timezone=settings.TZ)
            run_date = datetime.now(tz=pytz.timezone(settings.TZ)) + timedelta(seconds=3)
            self._once_scheduler.add_job(
                func=self.collect, trigger="date", run_date=run_date, name="NAS流量立即采集"
            )
            self._once_scheduler.start()

    def get_state(self) -> bool:
        return self._enabled

    def get_service(self) -> Optional[List[Dict[str, Any]]]:
        """注册周期采集服务，由宿主根据插件启用状态调度。"""
        if not self._enabled:
            return []
        return [{
            "id": "nastraffic_collect",
            "name": "NAS流量采集",
            "trigger": "interval",
            "kwargs": {"minutes": self._interval},
            "func": self.collect,
        }]

    @staticmethod
    def get_command() -> Optional[List[Dict[str, Any]]]:
        return []

    def stop_service(self) -> None:
        if self._once_scheduler is not None:
            try:
                self._once_scheduler.shutdown(wait=False)
            except Exception as err:  # noqa: BLE001
                logger.warning(f"{LOG_TAG}关闭一次性调度器失败：{err}")
            self._once_scheduler = None

    # -----------------------------------------------------------------------
    # 数据采集
    # -----------------------------------------------------------------------
    def collect(self) -> Dict[str, Any]:
        """执行一次采集，增量写入 SQLite。返回本次采集明细。"""
        day = today_str()
        detail: Dict[str, Any] = {
            "day": day, "media": None, "downloaders": [], "nic": None,
            "errors": [], "numbers": {},
        }
        numbers: Dict[str, int] = {}

        # 1) 视频流量（内外网区分）
        if self._enable_media:
            lan_cidrs = [c.strip() for c in self._lan_cidrs.split(",") if c.strip()] or None
            media = collect_nginx_log(
                self.store,
                self._nginx_log_path,
                compile_video_pattern(self._video_pattern),
                build_lan_networks(lan_cidrs),
                compile_log_pattern(self._log_pattern),
            )
            detail["media"] = {k: v for k, v in media.items() if k != "events"}
            if media["ok"]:
                numbers.update({
                    "media_wan_up": media["wan_bytes"],
                    "media_lan_up": media["lan_bytes"],
                    "media_req_wan": media["wan_reqs"],
                    "media_req_lan": media["lan_reqs"],
                })
                self.store.add_media_events(media["events"])
            else:
                detail["errors"].append(media["error"])

        # 2) 下载器上传下载
        if self._enable_downloader:
            try:
                helper = DownloaderHelper()
                name_filters = self._downloaders or None
                services = helper.get_services(name_filters=name_filters)
            except Exception as err:  # noqa: BLE001
                services = {}
                detail["errors"].append(f"获取下载器失败：{err}")

            for name, service in (services or {}).items():
                if service.type not in ("qbittorrent", "transmission"):
                    continue
                instance = getattr(service, "instance", None)
                if not instance or not hasattr(instance, "transfer_info"):
                    continue
                try:
                    info = instance.transfer_info()
                except Exception as err:  # noqa: BLE001
                    detail["errors"].append(f"{name} 读取传输信息失败：{err}")
                    continue
                parsed = extract_transfer_info(service.type, info)
                if not parsed:
                    continue
                key = f"{service.type}|{name}"
                snapshot = self.store.get_dl_snapshot(key)
                up_delta = down_delta = 0
                if snapshot:
                    up_delta = max(0, parsed["up"] - int(snapshot["up_total"]))
                    down_delta = max(0, parsed["down"] - int(snapshot["down_total"]))
                self.store.set_dl_snapshot(key, parsed["up"], parsed["down"])
                prefix = "qb" if service.type == "qbittorrent" else "tr"
                numbers[f"{prefix}_up"] = numbers.get(f"{prefix}_up", 0) + up_delta
                numbers[f"{prefix}_down"] = numbers.get(f"{prefix}_down", 0) + down_delta
                detail["downloaders"].append({
                    "name": name,
                    "type": service.type,
                    "up": parsed["up"],
                    "down": parsed["down"],
                    "up_delta": up_delta,
                    "down_delta": down_delta,
                    "up_speed": parsed["up_speed"],
                    "down_speed": parsed["down_speed"],
                })

        # 3) 整机网卡流量
        if self._enable_nic:
            current = read_net_dev(self._net_dev_path)
            previous = self.store.get_nic_snapshots()
            rx_delta = tx_delta = 0
            for iface, values in current.items():
                old = previous.get(iface)
                if old:
                    rx_delta += max(0, values["rx"] - old["rx"])
                    tx_delta += max(0, values["tx"] - old["tx"])
                self.store.set_nic_snapshot(iface, values["rx"], values["tx"])
            numbers["nic_rx"] = rx_delta
            numbers["nic_tx"] = tx_delta
            detail["nic"] = {
                "rx": rx_delta, "tx": tx_delta,
                "ifaces": len(current), "path": self._net_dev_path,
            }

        self.store.add_daily(day, **numbers)
        self.store.cleanup(self._retain_days)
        status = {
            "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "downloaders": detail["downloaders"],
            "errors": detail["errors"],
        }
        self.save_data("last_status", status)
        detail["numbers"] = numbers
        return detail

    # -----------------------------------------------------------------------
    # 数据聚合
    # -----------------------------------------------------------------------
    @staticmethod
    def _merge_rows(rows: List[Dict[str, Any]]) -> Dict[str, int]:
        merged = {field: 0 for field in DAILY_NUM_FIELDS}
        for row in rows:
            for field in DAILY_NUM_FIELDS:
                merged[field] += int(row.get(field) or 0)
        return merged

    def _summary(self) -> Dict[str, Any]:
        status = self.get_data("last_status") or {}
        return {
            "today": self._merge_rows(self.store.get_daily(today_str())),
            "month": self._merge_rows(self.store.get_daily(month_start_str())),
            "total": self.store.get_totals(),
            "downloaders": status.get("downloaders", []),
            "updated_at": status.get("updated_at", ""),
            "errors": status.get("errors", []),
        }

    # -----------------------------------------------------------------------
    # 配置页面
    # -----------------------------------------------------------------------
    def _downloader_items(self) -> List[Dict[str, str]]:
        try:
            configs = DownloaderHelper().get_configs()
            return [{"title": name, "value": name} for name in configs]
        except Exception as err:  # noqa: BLE001
            logger.debug(f"{LOG_TAG}获取下载器列表失败：{err}")
            return []

    def get_form(self) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        return [
            {
                "component": "VForm",
                "content": [
                    {
                        "component": "VRow",
                        "content": [
                            {
                                "component": "VCol",
                                "props": {"cols": 12, "md": 4},
                                "content": [{"component": "VSwitch", "props": {
                                    "model": "enabled", "label": "启用插件"}}],
                            },
                            {
                                "component": "VCol",
                                "props": {"cols": 12, "md": 4},
                                "content": [{"component": "VSwitch", "props": {
                                    "model": "onlyonce", "label": "立即采集一次"}}],
                            },
                            {
                                "component": "VCol",
                                "props": {"cols": 12, "md": 4},
                                "content": [{"component": "VSelect", "props": {
                                    "model": "dashboard_type", "label": "仪表盘展示",
                                    "items": [
                                        {"title": "今日数据", "value": "today"},
                                        {"title": "本月数据", "value": "month"},
                                    ]}}],
                            },
                        ],
                    },
                    {
                        "component": "VRow",
                        "content": [
                            {
                                "component": "VCol",
                                "props": {"cols": 12, "md": 6},
                                "content": [{"component": "VTextField", "props": {
                                    "model": "nginx_log_path", "label": "飞牛 nginx 访问日志路径",
                                    "hint": "容器内路径，需把宿主机 /usr/trim/nginx/logs 挂载进来",
                                    "persistentHint": True}}],
                            },
                            {
                                "component": "VCol",
                                "props": {"cols": 12, "md": 6},
                                "content": [{"component": "VTextField", "props": {
                                    "model": "net_dev_path", "label": "网卡统计文件路径",
                                    "hint": "需宿主机 /proc 挂载，例如 /hostproc/net/dev",
                                    "persistentHint": True}}],
                            },
                        ],
                    },
                    {
                        "component": "VRow",
                        "content": [
                            {
                                "component": "VCol",
                                "props": {"cols": 12, "md": 4},
                                "content": [{"component": "VTextField", "props": {
                                    "model": "interval", "label": "采集周期（分钟）", "type": "number"}}],
                            },
                            {
                                "component": "VCol",
                                "props": {"cols": 12, "md": 4},
                                "content": [{"component": "VTextField", "props": {
                                    "model": "retain_days", "label": "明细保留天数", "type": "number"}}],
                            },
                            {
                                "component": "VCol",
                                "props": {"cols": 12, "md": 4},
                                "content": [{"component": "VSelect", "props": {
                                    "model": "downloaders", "label": "统计的下载器（空=全部）",
                                    "items": self._downloader_items(), "multiple": True,
                                    "chips": True, "closableChips": True}}],
                            },
                        ],
                    },
                    {
                        "component": "VRow",
                        "content": [
                            {
                                "component": "VCol",
                                "props": {"cols": 12, "md": 6},
                                "content": [{"component": "VTextField", "props": {
                                    "model": "lan_cidrs", "label": "自定义内网段（逗号分隔）",
                                    "hint": "留空使用默认：127/8、10/8、172.16/12、192.168/16、IPv6 ULA",
                                    "persistentHint": True}}],
                            },
                            {
                                "component": "VCol",
                                "props": {"cols": 12, "md": 6},
                                "content": [{"component": "VTextField", "props": {
                                    "model": "video_pattern", "label": "视频请求匹配正则（高级）",
                                    "hint": "留空使用内置规则，匹配视频扩展名与播放接口路径",
                                    "persistentHint": True}}],
                            },
                        ],
                    },
                    {
                        "component": "VRow",
                        "content": [
                            {
                                "component": "VCol",
                                "props": {"cols": 12},
                                "content": [{"component": "VTextField", "props": {
                                    "model": "log_pattern", "label": "访问日志行正则（高级）",
                                    "hint": "需包含命名组 ip / request / status / bytes；留空使用标准 nginx combined 格式",
                                    "persistentHint": True}}],
                            },
                        ],
                    },
                    {
                        "component": "VRow",
                        "content": [
                            {
                                "component": "VCol",
                                "props": {"cols": 4},
                                "content": [{"component": "VSwitch", "props": {
                                    "model": "enable_media", "label": "统计视频流量"}}],
                            },
                            {
                                "component": "VCol",
                                "props": {"cols": 4},
                                "content": [{"component": "VSwitch", "props": {
                                    "model": "enable_downloader", "label": "统计下载器"}}],
                            },
                            {
                                "component": "VCol",
                                "props": {"cols": 4},
                                "content": [{"component": "VSwitch", "props": {
                                    "model": "enable_nic", "label": "统计整机网卡"}}],
                            },
                        ],
                    },
                ],
            }
        ], self._current_config()

    # -----------------------------------------------------------------------
    # 详情页
    # -----------------------------------------------------------------------
    @staticmethod
    def _card(title: str, value: str, subtitle: str = "", color: str = "primary") -> Dict[str, Any]:
        return {
            "component": "VCol",
            "props": {"cols": 6, "md": 3},
            "content": [{
                "component": "VCard",
                "props": {"variant": "tonal", "color": color},
                "content": [{
                    "component": "VCardText",
                    "content": [
                        {"component": "div", "props": {"class": "text-caption"}, "text": title},
                        {"component": "div", "props": {"class": "text-h6"}, "text": value},
                    ] + ([{"component": "div", "props": {"class": "text-caption"}, "text": subtitle}] if subtitle else []),
                }],
            }],
        }

    def _history_points(self, days: int = 30) -> List[Dict[str, Any]]:
        start = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
        return self.store.get_daily(start)

    @staticmethod
    def _chart_element(points: List[Dict[str, Any]]) -> Dict[str, Any]:
        categories = [p["day"] for p in points]
        gb = 1024 ** 3

        def series(key: str) -> List[float]:
            return [round(float(p.get(key) or 0) / gb, 2) for p in points]

        options = {
            "chart": {"type": "line", "height": 300, "toolbar": {"show": False}, "animations": {"enabled": False}},
            "xaxis": {"categories": categories, "type": "category"},
            "stroke": {"curve": "smooth", "width": 2},
            "legend": {"position": "top"},
            "grid": {"left": 10, "right": 10, "bottom": 0, "top": 40, "containLabel": True},
            "noData": {"text": "暂无数据"},
        }
        return {
            "component": "VApexChart",
            "props": {
                "height": 300,
                "options": options,
                "series": [
                    {"name": "外网视频上传(GB)", "data": series("media_wan_up")},
                    {"name": "内网视频上传(GB)", "data": series("media_lan_up")},
                    {"name": "PT上传(GB)", "data": series("qb_up")},
                ],
            },
        }

    def get_page(self) -> List[Dict[str, Any]]:
        summary = self._summary()
        today = summary["today"]
        month = summary["month"]
        points = self._history_points(30)
        events = self.store.get_media_events(30)

        cards = [
            self._card("今日·外网视频上传", format_size(today["media_wan_up"]),
                       f"{today['media_req_wan']} 次请求", "primary"),
            self._card("今日·内网视频上传", format_size(today["media_lan_up"]),
                       f"{today['media_req_lan']} 次请求", "success"),
            self._card("今日·PT上传", format_size(today["qb_up"] + today["tr_up"]), color="warning"),
            self._card("今日·PT下载", format_size(today["qb_down"] + today["tr_down"]), color="error"),
            self._card("今日·网卡接收", format_size(today["nic_rx"]), color="info"),
            self._card("今日·网卡发送", format_size(today["nic_tx"]), color="info"),
            self._card("本月·外网视频上传", format_size(month["media_wan_up"]), color="primary"),
            self._card("本月·PT上传", format_size(month["qb_up"] + month["tr_up"]), color="warning"),
        ]

        # 下载器实时状态
        dl_rows: List[Dict[str, Any]] = []
        for item in summary["downloaders"]:
            dl_rows.append({
                "component": "tr",
                "content": [
                    {"component": "td", "text": str(item.get("name", ""))},
                    {"component": "td", "text": str(item.get("type", ""))},
                    {"component": "td", "text": format_speed(item.get("up_speed", 0))},
                    {"component": "td", "text": format_speed(item.get("down_speed", 0))},
                    {"component": "td", "text": format_size(item.get("up_delta", 0))},
                    {"component": "td", "text": format_size(item.get("down_delta", 0))},
                ],
            })
        dl_table = {
            "component": "VTable",
            "props": {"hover": True, "density": "compact"},
            "content": [
                {"component": "thead", "content": [
                    {"component": "th", "text": t} for t in
                    ["下载器", "类型", "上传速度", "下载速度", "本轮上传", "本轮下载"]
                ]},
                {"component": "tbody", "content": dl_rows or [
                    {"component": "tr", "content": [
                        {"component": "td", "props": {"colspan": 6}, "text": "暂无下载器数据"}
                    ]},
                ]},
            ],
        }

        # 视频请求明细
        event_rows: List[Dict[str, Any]] = []
        for item in events:
            event_rows.append({
                "component": "tr",
                "content": [
                    {"component": "td", "text": str(item.get("ts", ""))},
                    {"component": "td", "text": str(item.get("ip", ""))},
                    {"component": "td", "text": "内网" if item.get("scope") == "lan" else "外网"},
                    {"component": "td", "text": format_size(item.get("bytes", 0))},
                    {"component": "td", "text": str(item.get("url", ""))[:120]},
                ],
            })
        event_table = {
            "component": "VTable",
            "props": {"hover": True, "density": "compact"},
            "content": [
                {"component": "thead", "content": [
                    {"component": "th", "text": t} for t in ["时间", "来源IP", "范围", "上传量", "请求路径"]
                ]},
                {"component": "tbody", "content": event_rows or [
                    {"component": "tr", "content": [
                        {"component": "td", "props": {"colspan": 5}, "text": "暂无视频请求记录"}
                    ]},
                ]},
            ],
        }

        warnings = []
        if summary["errors"]:
            warnings.append({
                "component": "VAlert",
                "props": {"type": "warning", "variant": "tonal", "class": "mb-3"},
                "text": "采集提示：" + "；".join(summary["errors"][:3]),
            })
        updated = summary["updated_at"] or "尚未采集"
        warnings.append({
            "component": "VAlert",
            "props": {"type": "info", "variant": "tonal", "class": "mb-3"},
            "text": f"最近采集时间：{updated}　|　日志：{self._nginx_log_path}　|　网卡：{self._net_dev_path}",
        })

        return [{
            "component": "VContainer",
            "content": warnings + [
                {"component": "VRow", "content": cards},
                {"component": "VRow", "content": [{
                    "component": "VCol", "props": {"cols": 12},
                    "content": [{
                        "component": "VCard",
                        "content": [{
                            "component": "VCardTitle", "text": "近 30 天流量趋势"
                        }, {
                            "component": "VCardText",
                            "content": [self._chart_element(points)],
                        }],
                    }],
                }]},
                {"component": "VRow", "content": [{
                    "component": "VCol", "props": {"cols": 12, "md": 6},
                    "content": [{"component": "VCard", "content": [
                        {"component": "VCardTitle", "text": "下载器实时状态"},
                        {"component": "VCardText", "content": [dl_table]},
                    ]}],
                }, {
                    "component": "VCol", "props": {"cols": 12, "md": 6},
                    "content": [{"component": "VCard", "content": [
                        {"component": "VCardTitle", "text": "视频请求明细（最近 30 条）"},
                        {"component": "VCardText", "content": [event_table]},
                    ]}],
                }]},
            ],
        }]

    # -----------------------------------------------------------------------
    # 仪表盘
    # -----------------------------------------------------------------------
    def get_dashboard_meta(self) -> Optional[List[Dict[str, str]]]:
        return [{"key": "nastraffic", "name": "NAS流量统计"}]

    def get_dashboard(
        self, key: str, **kwargs: Any
    ) -> Optional[Tuple[Dict[str, Any], Dict[str, Any], Optional[List[Dict[str, Any]]]]]:
        if not self._enabled:
            return None
        summary = self._summary()
        data = summary["today"] if self._dashboard_type == "today" else summary["month"]
        label = "今日" if self._dashboard_type == "today" else "本月"
        cols = {"cols": 12, "md": 6}
        attrs = {"refresh": max(30, self._interval * 60), "title": f"NAS流量统计 · {label}"}
        elements = [{
            "component": "VRow",
            "content": [
                self._card(f"{label}外网视频", format_size(data["media_wan_up"]), color="primary"),
                self._card(f"{label}内网视频", format_size(data["media_lan_up"]), color="success"),
                self._card(f"{label}PT上传", format_size(data["qb_up"] + data["tr_up"]), color="warning"),
                self._card(f"{label}PT下载", format_size(data["qb_down"] + data["tr_down"]), color="error"),
            ],
        }]
        return cols, attrs, elements

    # -----------------------------------------------------------------------
    # API
    # -----------------------------------------------------------------------
    def get_api(self) -> List[Dict[str, Any]]:
        return [
            {
                "path": "/summary",
                "endpoint": self.api_summary,
                "methods": ["GET"],
                "auth": "bear",
                "summary": "查询流量汇总（今日/本月/累计/下载器状态）",
                "response_model": schemas.Response[SummaryData],
            },
            {
                "path": "/history",
                "endpoint": self.api_history,
                "methods": ["GET"],
                "auth": "bear",
                "summary": "查询按天历史流量",
                "response_model": schemas.Response[HistoryData],
            },
            {
                "path": "/events",
                "endpoint": self.api_events,
                "methods": ["GET"],
                "auth": "bear",
                "summary": "查询视频请求明细",
                "response_model": schemas.Response[EventsData],
            },
            {
                "path": "/collect",
                "endpoint": self.api_collect,
                "methods": ["POST"],
                "auth": "bear",
                "summary": "手动触发一次采集",
                "response_model": schemas.Response[CollectData],
            },
            {
                "path": "/status",
                "endpoint": self.api_status,
                "methods": ["GET"],
                "auth": "bear",
                "summary": "查询数据源可用状态",
                "response_model": schemas.Response[StatusData],
            },
        ]

    def api_summary(self) -> schemas.Response[SummaryData]:
        data = self._summary()
        return schemas.Response(success=True, data=SummaryData(**data))

    def api_history(self, days: int = 30) -> schemas.Response[HistoryData]:
        try:
            days = max(1, min(365, int(days)))
        except (TypeError, ValueError):
            days = 30
        points = self._history_points(days)
        return schemas.Response(
            success=True,
            data=HistoryData(points=[HistoryPoint(day=p["day"], **{
                f: int(p.get(f) or 0) for f in DAILY_NUM_FIELDS
            }) for p in points]),
        )

    def api_events(self, limit: int = 50) -> schemas.Response[EventsData]:
        try:
            limit = max(1, min(500, int(limit)))
        except (TypeError, ValueError):
            limit = 50
        return schemas.Response(success=True, data=EventsData(events=self.store.get_media_events(limit)))

    def api_collect(self) -> schemas.Response[CollectData]:
        detail = self.collect()
        return schemas.Response(
            success=True,
            data=CollectData(message="采集完成", detail=detail),
        )

    def api_status(self) -> schemas.Response[StatusData]:
        from pathlib import Path
        status = self.get_data("last_status") or {}
        try:
            from app.sdk.services import DownloaderHelper as _DH
            count = len(_DH().get_services())
        except Exception:  # noqa: BLE001
            count = 0
        return schemas.Response(success=True, data=StatusData(
            log_path=self._nginx_log_path,
            log_exists=Path(self._nginx_log_path).exists(),
            net_dev_path=self._net_dev_path,
            net_dev_exists=Path(self._net_dev_path).exists(),
            downloader_count=count,
            last_updated=status.get("updated_at", ""),
        ))
