"""配额灾备异常告警路由器（qrouter）。

订阅复制器的隔离/接管/缺口/审计事件，按租户与事件类型聚合成告警，
提供确认、静默、恢复与查询接口及运维页面。纯 Python 3.11 标准库。
"""

from .engine import AlertRouter, alert_id_of
from .store import Store

__all__ = ["AlertRouter", "Store", "alert_id_of"]
