"""告警路由器的领域模型：规范化事件、常量与校验。

规范化事件（Normalized Event）
==============================

复制器侧的隔离、接管、缺口与审计记录由 ``alerter.subscriber`` 归一化为同一信封：

    {
      "event_id":   去重幂等键（同源同 id 的重复投递只生效一次），
      "tenant":     租户标识（按租户聚合告警），
      "event_type": ISOLATION / TAKEOVER / GAP / AUDIT，
      "role":       BEGIN / END / WITNESS（AUDIT 事件固定为 WITNESS），
      "chain_id":   同一次灾备异常事件链的标识（同链事件共享），
      "seq":        该租户事件流上的单调水位序号（可选，缺省按到达分配），
      "reason":     原因码（如 LAG_OVER_LIMIT / OWNERSHIP_LOST / SEGMENT_INDEX_MISMATCH），
      "payload":    任意附加明细（segment_index / epoch / detail 等），
      "audit_ref":  WITNESS 指向的审计记录 id（其余角色可空），
      "occurred_at":事件在复制器侧的发生时间（epoch 秒，可选），
    }

链完整性规则（``CHAIN_RULES``）
===============================

只有**完整事件链**（所需角色齐全）且**连续水位成立**（该事件在其租户流上已按
seq 顺序无缺口地应用）时才能触发告警：

- ISOLATION：需要 BEGIN + WITNESS（隔离产生，审计见证后才成立）；
- GAP       ：需要 BEGIN + WITNESS（缺口产生，审计见证后才成立）；
- TAKEOVER  ：需要 BEGIN + END + WITNESS（失主 → 接管完成整段生命周期）。

链的 BEGIN 被 END 关闭时若仍未触发，按“未触发即终态”静默关闭（避免缺口补齐前
先误报）；ISOLATION/GAP 触发后再到达 END，则把既有活动告警自动恢复。
"""

from __future__ import annotations

from typing import Any

# ------------------------------------------------------------------
# 事件类型
# ------------------------------------------------------------------
ISOLATION = "ISOLATION"
TAKEOVER = "TAKEOVER"
GAP = "GAP"
AUDIT = "AUDIT"

ALERT_TYPES = (ISOLATION, TAKEOVER, GAP)
EVENT_TYPES = ALERT_TYPES + (AUDIT,)

# 事件角色：BEGIN 异常开始 / END 异常结束 / WITNESS 审计见证
BEGIN = "BEGIN"
END = "END"
WITNESS = "WITNESS"
ROLES = (BEGIN, END, WITNESS)

# 每类告警需要的链角色集合（“完整事件链”）
CHAIN_RULES = {
    ISOLATION: frozenset({BEGIN, WITNESS}),
    GAP: frozenset({BEGIN, WITNESS}),
    TAKEOVER: frozenset({BEGIN, END, WITNESS}),
}

# 告警状态机
ST_PENDING = "PENDING"        # 尚未触发（链未完整 / 水位未到）——链的内部状态
ST_FIRING = "FIRING"          # 已触发、通知已（或将）发出
ST_ACKED = "ACKED"            # 运维已确认
ST_SILENCED = "SILENCED"      # 被静默规则或人工静默（仍聚合，不通知）
ST_RESOLVED = "RESOLVED"      # 自动恢复（链收到 END / 缺口补齐后补发再关闭）
ST_CLOSED = "CLOSED"          # 人工恢复/关闭
ACTIVE_STATES = (ST_FIRING, ST_ACKED, ST_SILENCED)
TERMINAL_STATES = (ST_RESOLVED, ST_CLOSED)

# 链状态
CHAIN_OPEN = "OPEN"           # 异常进行中（已见 BEGIN，未见 END）
CHAIN_CLOSED = "CLOSED"       # 已见 END
CHAIN_WITNESSED = "WITNESSED"  # 仅见 WITNESS（BEGIN 还在缺口后）
CHAIN_BORN_CLOSED = "BORN_CLOSED"  # 直接收到 END（BEGIN 在缺口后，未触发即终态）

# 告警未触发即终态 / 触发后恢复的原因码
BORN_CLOSED_REASON = "BORN_CLOSED_WITHOUT_FIRING"
AUTO_RESOLVE_REASON = "AUTO_RESOLVED_ON_CHAIN_END"

# 审计轨迹的 kind（每次状态转移一条）
AUDIT_EVENT_RECEIVED = "event_received"           # 事件登记（含重复幂等命中）
AUDIT_GAP_DETECTED = "watermark_gap_detected"     # 连续水位出现缺口
AUDIT_GAP_FILLED = "watermark_gap_filled"         # 缺口补齐、连续水位恢复
AUDIT_CHAIN_COMPLETE = "chain_complete"           # 链角色齐全、具备触发条件
AUDIT_ALERT_FIRED = "alert_fired"                 # 触发并通知
AUDIT_ALERT_DEDUPED = "alert_deduped"             # 滑动窗口去重抑制通知
AUDIT_CHAIN_BORN_CLOSED = "chain_born_closed"     # 未触发即终态关闭
AUDIT_ALERT_RESOLVED = "alert_resolved"           # 自动恢复
AUDIT_ALERT_ACKED = "alert_acked"                 # 确认
AUDIT_ALERT_UNACKED = "alert_unacked"             # 取消确认
AUDIT_ALERT_SILENCED = "alert_silenced"           # 静默（人工/规则）
AUDIT_ALERT_UNSILENCED = "alert_unsilenced"       # 解除静默
AUDIT_ALERT_CLOSED = "alert_closed"               # 人工关闭/恢复
AUDIT_SILENCE_RULE_CREATED = "silence_rule_created"
AUDIT_SILENCE_RULE_DELETED = "silence_rule_deleted"
AUDIT_ROUTER_STARTED = "router_started"
AUDIT_ROUTER_RECOVERED = "router_recovered"


class AlertError(Exception):
    """路由层业务错误；``status`` 是建议的 HTTP 状态码。"""

    status = 400

    def __init__(self, reason: str, message: str, status: int | None = None,
                 details: dict[str, Any] | None = None):
        super().__init__(message)
        self.reason = reason
        if status is not None:
            self.status = status
        self.details = details or {}


def normalize_event(event: dict[str, Any]) -> dict[str, Any]:
    """校验并规范化一条外部事件。缺省字段在此补齐，非法输入抛 :class:`AlertError`。"""
    if not isinstance(event, dict):
        raise AlertError("BAD_EVENT", "事件必须是 JSON 对象", 400)

    event_id = event.get("event_id")
    if not event_id or not isinstance(event_id, str):
        raise AlertError("BAD_EVENT", "缺少 event_id（字符串）", 400)

    tenant = event.get("tenant")
    if not tenant or not isinstance(tenant, str):
        raise AlertError("BAD_EVENT", "缺少 tenant（字符串）", 400)

    event_type = event.get("event_type")
    if event_type not in EVENT_TYPES:
        raise AlertError("BAD_EVENT",
                         f"event_type 必须是 {EVENT_TYPES} 之一，收到 {event_type!r}", 400)

    chain_id = event.get("chain_id")
    if not chain_id or not isinstance(chain_id, str):
        raise AlertError("BAD_EVENT", "缺少 chain_id（字符串）", 400)

    # AUDIT 事件是审计见证：角色固定 WITNESS
    role = WITNESS if event_type == AUDIT else event.get("role")
    if role not in ROLES:
        raise AlertError("BAD_EVENT",
                         f"role 必须是 {ROLES} 之一，收到 {role!r}", 400)
    if event_type == AUDIT and not event.get("audit_ref"):
        raise AlertError("BAD_EVENT", "AUDIT 事件必须携带 audit_ref（见证对象）", 400)

    seq = event.get("seq")
    if seq is not None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
            raise AlertError("BAD_EVENT", "seq 必须是 >= 1 的整数或省略", 400)

    occurred_at = event.get("occurred_at")
    if occurred_at is not None and not isinstance(occurred_at, (int, float)):
        raise AlertError("BAD_EVENT", "occurred_at 必须是数值（epoch 秒）或省略", 400)

    payload = event.get("payload")
    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        raise AlertError("BAD_EVENT", "payload 必须是对象或省略", 400)

    return {
        "event_id": event_id,
        "tenant": tenant,
        "event_type": event_type,
        "role": role,
        "chain_id": chain_id,
        "seq": seq,
        "reason": str(event.get("reason") or ""),
        "payload": payload,
        "audit_ref": str(event.get("audit_ref") or "") or None,
        "occurred_at": float(occurred_at) if occurred_at is not None else None,
    }
