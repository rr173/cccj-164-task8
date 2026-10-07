"""配额灾备异常告警路由器 · 领域模型。

复制器（replica/）在运行中会产生四类**需要人介入的异常信号**，本告警路由器
把它们统一为同构的「事件信封」：

    QUARANTINE  隔离事件  —— 分段校验失败 / 落后超限 / 纪元失主写入被拒
    TAKEOVER    接管事件  —— 新进程纪元提升，接管写入所有权（滚动升级）
    GAP         缺口事件  —— 已确认序列中出现不连续（错序/缺段）
    AUDIT       审计事件  —— 复制器的一致性审计结果（成功或失败）

每条事件属于一条**两阶段事件链**（chain_id 相同）：

    触发相（OPEN）   异常发生：隔离落表 / 纪元提升 / 检测到缺口 / 审计完成
    收口相（RESOLVE）异常消除：隔离标记 resolved / 缺口补齐 / ……

只有「**事件链完整（到达了触发相）**」且「**触发相在该租户连续水位之内
（没有更早的序列还挂起）**」的事件才能触发告警。仍然缺号时事件先挂起，
水位连上后再补发或（链已在挂起期间收口）静默关闭。
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# 事件类型与相
# ---------------------------------------------------------------------------

QUARANTINE = "QUARANTINE"
TAKEOVER = "TAKEOVER"
GAP = "GAP"
AUDIT = "AUDIT"

EVENT_TYPES = (QUARANTINE, TAKEOVER, GAP, AUDIT)

PHASE_OPEN = "OPEN"      # 异常发生（触发相）
PHASE_RESOLVE = "RESOLVE"  # 异常消除（收口相）
PHASES = (PHASE_OPEN, PHASE_RESOLVE)

# 各类型允许出现的相（统一都是完整两阶段链；只到 OPEN 则告警一直开着，
# 直到 RESOLVE 到达）。
PHASES_BY_TYPE: dict[str, tuple[str, ...]] = {
    QUARANTINE: (PHASE_OPEN, PHASE_RESOLVE),
    TAKEOVER: (PHASE_OPEN, PHASE_RESOLVE),
    GAP: (PHASE_OPEN, PHASE_RESOLVE),
    AUDIT: (PHASE_OPEN, PHASE_RESOLVE),
}

# ---------------------------------------------------------------------------
# 告警状态机
# ---------------------------------------------------------------------------

OPEN = "OPEN"            # 活动告警，待处理（或在滑动窗口内重复触发）
ACKED = "ACKED"          # 已人工确认
RECOVERED = "RECOVERED"  # 复制器事件已表明异常消除，等待自动/人工关闭
SILENCED = "SILENCED"    # 命中静默规则（告警本身仍存在，仅抑制通知）
CLOSED = "CLOSED"        # 终态：已关闭（恢复后 TTL 到期 / 人工关闭 /
                         #       缺口补齐后链在挂起期间已收口的静默关闭）

ACTIVE_STATES = (OPEN, ACKED, RECOVERED)
TERMINAL_STATE = CLOSED

# 合法状态转移（命令路径与事件路径共用）
TRANSITIONS: dict[str, set[str]] = {
    OPEN: {ACKED, RECOVERED, SILENCED, CLOSED},
    ACKED: {RECOVERED, SILENCED, CLOSED},
    RECOVERED: {CLOSED, OPEN},
    SILENCED: {OPEN, ACKED, RECOVERED, CLOSED},
    CLOSED: set(),
}

# ---------------------------------------------------------------------------
# 审计 kind（每次状态转移一条；关键非转移事件也留痕）
# ---------------------------------------------------------------------------

AUD_ALERT_FIRED = "alert_fired"                 # 新告警触发（含补发）
AUD_ALERT_DEDUPED = "alert_deduped"             # 滑动窗口内重复，抑制通知
AUD_ALERT_ACKED = "alert_acked"
AUD_ALERT_RECOVERED = "alert_recovered"         # 事件链收口
AUD_ALERT_CLOSED = "alert_closed"               # 终态关闭
AUD_ALERT_SILENCED = "alert_silenced"
AUD_ALERT_UNSILENCED = "alert_unsilenced"
AUD_ALERT_REOPENED = "alert_reopened"           # RECOVERED 后又来 OPEN
AUD_STREAM_GAP = "stream_gap"                   # 租户事件流出现缺号
AUD_WATERMARK_ADVANCE = "watermark_advance"     # 连续水位推进
AUD_CHAIN_HELD = "chain_held"                   # 事件因水位缺口挂起
AUD_CHAIN_PENDING_CLOSED = "chain_pending_closed"  # 挂起链释放时已收口，静默关闭
AUD_SILENCE_CREATED = "silence_created"
AUD_SILENCE_REVOKED = "silence_revoked"
AUD_SILENCE_EXPIRED = "silence_expired"
AUD_RECOVERED_TTL_CLOSED = "recovered_ttl_closed"  # 恢复后 TTL 到期自动关闭
AUD_RECOVERY_IGNORED = "recovery_ignored"       # 恢复事件到达时链已终态


class RouterError(Exception):
    """业务错误：携带稳定错误码与 HTTP 状态。"""

    def __init__(self, reason: str, message: str, status: int = 409,
                 details: dict[str, Any] | None = None):
        super().__init__(message)
        self.reason = reason
        self.status = status
        self.details = details or {}


# ---------------------------------------------------------------------------
# 事件校验
# ---------------------------------------------------------------------------

REQUIRED_FIELDS = ("event_id", "tenant", "type", "phase", "chain_id", "seq",
                   "occurred_at")


def normalize_event(raw: dict[str, Any]) -> dict[str, Any]:
    """校验并规范化一条入站事件。

    成功返回规范化后的 dict；结构不合法抛 RouterError(422 / 400)。
    """
    if not isinstance(raw, dict):
        raise RouterError("BAD_EVENT", "事件必须是 JSON 对象", 400)

    for f in REQUIRED_FIELDS:
        if raw.get(f) in (None, ""):
            raise RouterError("BAD_EVENT", f"事件缺少必需字段: {f}", 422)

    etype = raw["type"]
    if etype not in EVENT_TYPES:
        raise RouterError("BAD_EVENT_TYPE",
                          f"未知事件类型: {etype!r}，允许 {EVENT_TYPES}", 422)

    phase = raw["phase"]
    if phase not in PHASES_BY_TYPE[etype]:
        raise RouterError("BAD_PHASE",
                          f"事件类型 {etype} 不允许相 {phase!r}", 422)

    seq = raw["seq"]
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
        raise RouterError("BAD_SEQ", "seq 必须是 >=1 的整数", 422)

    tenant = str(raw["tenant"]).strip()
    chain_id = str(raw["chain_id"]).strip()
    event_id = str(raw["event_id"]).strip()
    if not tenant or not chain_id or not event_id:
        raise RouterError("BAD_EVENT", "tenant/chain_id/event_id 不能为空串", 422)

    occurred_at = str(raw["occurred_at"])
    # 时间戳必须可解析（ISO-8601），避免垃圾数据进日志
    try:
        parse_ts(occurred_at)
    except Exception as exc:  # noqa: BLE001
        raise RouterError("BAD_TIMESTAMP",
                          f"occurred_at 不是合法 ISO-8601 时间: {exc}", 422)

    payload = raw.get("payload") or {}
    if not isinstance(payload, dict):
        raise RouterError("BAD_PAYLOAD", "payload 必须是对象", 422)

    return {
        "event_id": event_id,
        "tenant": tenant,
        "type": etype,
        "phase": phase,
        "chain_id": chain_id,
        "seq": seq,
        "occurred_at": occurred_at,
        "payload": payload,
    }


# ---------------------------------------------------------------------------
# 时间工具（统一 UTC、ISO-8601 'Z' 结尾，便于 SQLite 文本比较与展示）
# ---------------------------------------------------------------------------

from datetime import datetime, timezone  # noqa: E402


def parse_ts(s: str) -> datetime:
    """解析 ISO-8601；接受 'Z' 结尾，返回带时区的 datetime。"""
    s = s.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def to_ts(dt: datetime) -> str:
    dt = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
