"""配额灾备异常告警路由器。

订阅复制器（``replica``）的四类事件——隔离（ISOLATION）、接管（TAKEOVER）、
缺口（GAP）与审计见证（AUDIT）——按「租户 + 事件类型」聚合成告警，提供确认、
静默、恢复与查询接口及运维页面。

核心模块：

- ``alerter.models``     规范化事件、常量与校验
- ``alerter.store``      SQLite 持久化（事件/链/告警/静默/窗口/审计，条件更新）
- ``alerter.router``     告警路由引擎（水位闸门、链完整性、去重、状态机）
- ``alerter.subscriber`` 订阅复制器 audit-tail / quarantine，合成规范化事件
- ``alerter.http_server`` HTTP 接口 + 运维页面
"""

from .models import AlertError, TAKEOVER, ISOLATION, GAP, AUDIT, ROLES
from .store import AlertStore
from .router import AlertRouter

__all__ = [
    "AlertError",
    "AlertStore",
    "AlertRouter",
    "TAKEOVER",
    "ISOLATION",
    "GAP",
    "AUDIT",
    "ROLES",
]
