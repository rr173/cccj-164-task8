"""告警路由引擎：连续水位 + 两阶段事件链 + 状态机。

核心准则（对应需求逐条落地）：

* **完整事件链且连续水位成立才触发**：事件先按 (租户, seq) 接收。若该 seq
  大于租户连续水位 next_seq，说明更早的事件还在路上——事件**挂起**
  （stream_gap 审计），不触发任何告警；水位连上时级联释放。
* **缺口补齐后补发或关闭**：释放时若链只有触发相 → 正常触发（告警标
  backfilled=1，通知 kind=fired）；若触发相与收口相同批释放、链在挂起期间
  已完整 → **静默关闭**（不落 OPEN 通知，chain_pending_closed 审计）。
* **滑动窗口去重**：同 租户+类型+chain 的 OPEN 在 window_seconds 内重复出现，
  仅累计 occurrence_count，通知记 deduped 不发出（窗口判定依据 notifications
  表，重启后仍然成立）。
* **确认与恢复竞争**：所有命令状态转移走 version 条件 CAS（单库 + 单把
  RLock 串行化），输家拿 409 ALERT_VERSION_CONFLICT，每条实际发生的转移一条
  审计，竞争结果可完整回放。
* **服务重启恢复**：journal 是事实来源，启动清空物化表按 jseq 全量重放，
  审计 dedup_key 唯一保证不重复落账。
* **同事件幂等**：event_id 唯一；重复投递原样返回既有结果，不二次折叠。
"""

from __future__ import annotations

import threading
import uuid
from datetime import timedelta
from typing import Any

from .models import (
    AUDIT, GAP, PHASE_OPEN, PHASE_RESOLVE, QUARANTINE, TAKEOVER,
    OPEN, ACKED, RECOVERED, SILENCED, CLOSED, ACTIVE_STATES,
    TRANSITIONS, RouterError,
    normalize_event, now_ts, parse_ts, to_ts,
    AUD_ALERT_FIRED, AUD_ALERT_DEDUPED, AUD_ALERT_ACKED, AUD_ALERT_RECOVERED,
    AUD_ALERT_CLOSED, AUD_ALERT_SILENCED, AUD_ALERT_UNSILENCED,
    AUD_ALERT_REOPENED, AUD_STREAM_GAP, AUD_WATERMARK_ADVANCE, AUD_CHAIN_HELD,
    AUD_CHAIN_PENDING_CLOSED, AUD_SILENCE_CREATED, AUD_SILENCE_REVOKED,
    AUD_SILENCE_EXPIRED, AUD_RECOVERED_TTL_CLOSED, AUD_RECOVERY_IGNORED,
)
from .store import Store

# 确定性 alert_id：同一 (tenant,type,chain_id) 跨重放/跨进程得到同一 id
_ALERT_NS = uuid.UUID("4f9f8c3a-1a2b-4c3d-9e8f-0a1b2c3d4e5f")

DEFAULT_DEDUP_WINDOWS = {
    QUARANTINE: 600,
    TAKEOVER: 1800,
    GAP: 300,
    AUDIT: 3600,
}

SEVERITY_BY_TYPE = {
    QUARANTINE: "critical",
    TAKEOVER: "info",
    GAP: "critical",
    AUDIT: "warning",
}

SUMMARIES = {
    QUARANTINE: "复制器隔离了一个无法准入的分段/批次",
    TAKEOVER: "灾备复制器发生进程纪元接管（滚动升级/故障切换）",
    GAP: "复制事件流检测到连续水位缺口（缺段/错序）",
    AUDIT: "复制器一致性审计产生结果记录",
}


def alert_id_of(tenant: str, etype: str, chain_id: str) -> str:
    return "al-" + uuid.uuid5(_ALERT_NS, f"{tenant}|{etype}|{chain_id}").hex[:16]


class _Chain:
    """内存中的一条事件链折叠态（启动时从 journal 重建）。"""

    __slots__ = ("chain_id", "etype", "open_evt", "resolve_evt", "alert_open",
                 "alert_resolved", "silent_closed", "consumed")

    def __init__(self, chain_id: str, etype: str):
        self.chain_id = chain_id
        self.etype = etype
        self.open_evt: dict[str, Any] | None = None
        self.resolve_evt: dict[str, Any] | None = None
        self.alert_open = False       # 是否已据此触发过 OPEN 告警
        self.alert_resolved = False   # 是否已据此发出过恢复转移
        self.silent_closed = False    # 链在连续水位外已完整，静默关闭
        # 静默关闭时已在挂起区的同链事件 id：它们属于被关闭的那一周期，
        # 释放时直接消费、不再触发；关闭之后才新到的 OPEN 才算新周期。
        self.consumed: set[str] = set()


class AlertRouter:
    def __init__(self, store: Store,
                 dedup_windows: dict[str, int] | None = None,
                 recovered_ttl_seconds: float = 3600,
                 clock=now_ts):
        self.store = store
        self.dedup_windows = {**DEFAULT_DEDUP_WINDOWS, **(dedup_windows or {})}
        self.recovered_ttl_seconds = recovered_ttl_seconds
        self._clock = clock  # 返回当前墙钟 ISO（测试可注入固定时钟）
        self._lock = threading.RLock()
        # (tenant, chain_id) -> _Chain
        self.chains: dict[tuple[str, str], _Chain] = {}
        # (tenant, seq) -> event：当前仍挂起（水位未到）的事件
        self.held: dict[tuple[str, int], dict[str, Any]] = {}
        self.rebuild()

    # ==================================================================
    # 重启恢复：清空物化、全量重放 journal
    # ==================================================================

    def rebuild(self) -> None:
        with self._lock, self.store.lock:
            self.store.reset_materialized()
            self.chains.clear()
            self.held.clear()
            for entry in self.store.iter_journal(0):
                body = self.store.loads(entry["body_json"])
                if entry["kind"] == "event":
                    self._admit_event(body, at=entry["ingested_at"],
                                      jseq=entry["jseq"], replay=True)
                else:
                    self._apply_command(body["command"], body, at=entry["ingested_at"],
                                        jseq=entry["jseq"], replay=True)
            # 恢复挂起索引（物化表已记录 held=1 的行）
            for row in self.store.held_events():
                self.held[(row["tenant"], row["seq"])] = {
                    "event_id": row["event_id"], "tenant": row["tenant"],
                    "type": row["type"], "phase": row["phase"],
                    "chain_id": row["chain_id"], "seq": row["seq"],
                    "occurred_at": row["occurred_at"],
                    "payload": self.store.loads(row["payload_json"]),
                }
            # 停机期间到期的静默/恢复 TTL：重启立即收口，不等第一个 tick
            self._tick(self._clock())

    # ==================================================================
    # 事件入口（HTTP/订阅器调用）
    # ==================================================================

    def ingest_event(self, raw: dict[str, Any]) -> dict[str, Any]:
        """投递一条复制器事件。重复 event_id 幂等返回。"""
        event = normalize_event(raw)
        with self._lock, self.store.lock:
            at = self._clock()
            jseq, fresh = self.store.append_event_journal(event, at)
            if not fresh:
                alert = self.store.get_alert_by_chain(
                    event["tenant"], event["type"], event["chain_id"])
                return {"event_id": event["event_id"], "idempotent_replay": True,
                        "jseq": jseq,
                        "alert_id": alert["alert_id"] if alert else None,
                        "status": alert["status"] if alert else None}
            result = self._admit_event(event, at=at, jseq=jseq, replay=False)
            self._tick(at)
            return result

    def ingest_batch(self, raws: list[dict[str, Any]]) -> list[dict[str, Any]]:
        # 先整体校验：任一事件非法，一批都不写（不留半截日志/物化）
        events = [normalize_event(raw) for raw in raws]
        out = []
        # 批量事件在同一把锁内逐条准入；批内序号自然衔接
        with self._lock, self.store.lock:
            at = self._clock()
            for event in events:
                jseq, fresh = self.store.append_event_journal(event, at)
                if not fresh:
                    alert = self.store.get_alert_by_chain(
                        event["tenant"], event["type"], event["chain_id"])
                    out.append({"event_id": event["event_id"],
                                "idempotent_replay": True, "jseq": jseq,
                                "alert_id": alert["alert_id"] if alert else None,
                                "status": alert["status"] if alert else None})
                else:
                    out.append(self._admit_event(event, at=at, jseq=jseq,
                                                replay=False))
            self._tick(at)
        return out

    # ------------------------------------------------------------------
    # 准入：水位判定 → 挂起 / 级联释放
    # ------------------------------------------------------------------

    def _admit_event(self, event: dict[str, Any], *, at: str, jseq: int,
                     replay: bool) -> dict[str, Any]:
        tenant = event["tenant"]
        seq = event["seq"]
        t = self.store.ensure_tenant(tenant)
        next_seq = int(t["next_seq"])

        # 同序号正文不同 = 分叉（复制器侧已强校验，这里是路由器的第二道闸）
        if self.store.has_seq(tenant, seq):
            # stream_events UNIQUE(tenant,seq) 已挡住；防御性报错
            raise RouterError("SEQ_CONFLICT",
                              f"租户 {tenant} 序号 {seq} 已有不同事件", 422)

        # 链身份一致性：同 chain_id 的类型不可漂移
        known_type = self._chain_type(event["tenant"], event["chain_id"])
        if known_type is not None and known_type != event["type"]:
            raise RouterError(
                "CHAIN_TYPE_CONFLICT",
                f"chain_id={event['chain_id']} 类型冲突："
                f"{known_type} != {event['type']}", 422)

        if seq > next_seq:
            # ---- 水位不连续：挂起，并对缺口只报一次 ----
            self.store.insert_stream_event(event, held=True)
            self.held[(tenant, seq)] = event
            self.store.add_audit(
                at, AUD_CHAIN_HELD,
                f"chain-held:{jseq}",
                {"tenant": tenant, "seq": seq, "chain_id": event["chain_id"],
                 "type": event["type"], "phase": event["phase"],
                 "waiting_for": next_seq},
                tenant=tenant)
            gap_key = f"stream-gap:{tenant}:{next_seq}"
            self.store.add_audit(
                at, AUD_STREAM_GAP, gap_key,
                {"tenant": tenant, "expected_seq": next_seq,
                 "received_seq": seq, "event_id": event["event_id"],
                 "missing": list(range(next_seq, seq))},
                tenant=tenant)
            return {"event_id": event["event_id"], "jseq": jseq,
                    "admitted": True, "held": True,
                    "watermark": next_seq - 1, "alerts": []}

        # seq <= next_seq：正常（恰为水位）或迟到重传。物化登记并折叠。
        self.store.insert_stream_event(event, held=False)
        released_alerts = self._fold(event, at=at, jseq=jseq, backfilled=False)
        alerts = list(released_alerts)

        # 水位推进：next_seq -> seq+1，并级联释放此前挂起的事件
        if seq == next_seq:
            new_watermark, cascaded = self._drain(tenant, seq + 1, at=at,
                                                  replay=replay, jseq=jseq)
            alerts.extend(cascaded)
            self.store.advance_watermark(tenant, new_watermark, event["event_id"])
            self.store.add_audit(
                at, AUD_WATERMARK_ADVANCE, f"wm:{tenant}:{new_watermark}",
                {"tenant": tenant, "watermark": new_watermark - 1,
                 "next_seq": new_watermark, "event_id": event["event_id"]},
                tenant=tenant)
            watermark = new_watermark - 1
        else:
            watermark = next_seq - 1

        return {"event_id": event["event_id"], "jseq": jseq,
                "admitted": True, "held": False, "watermark": watermark,
                "alerts": alerts}

    def _drain(self, tenant: str, start: int, *, at: str, replay: bool,
               jseq: int) -> tuple[int, list[dict[str, Any]]]:
        """从 start 起，只要下一个序号挂起中就连锁释放（缺口补齐级联）。"""
        nxt = start
        alerts: list[dict[str, Any]] = []
        while (tenant, nxt) in self.held:
            event = self.held.pop((tenant, nxt))
            self.store.release_stream_event(tenant, nxt)
            alerts.extend(self._fold(event, at=at, jseq=jseq, backfilled=True))
            nxt += 1
        return nxt, alerts

    def _held_resolve_of(self, tenant: str, chain_id: str) -> dict[str, Any] | None:
        """挂起区中同链的收口相（可能比当前 OPEN 序号更大，尚未释放）。"""
        for (tn, _sq), evt in self.held.items():
            if tn == tenant and evt["chain_id"] == chain_id \
                    and evt["phase"] == PHASE_RESOLVE:
                return evt
        return None

    # ==================================================================
    # 事件链折叠
    # ==================================================================

    def _chain_type(self, tenant: str, chain_id: str) -> str | None:
        ch = self.chains.get((tenant, chain_id))
        if ch:
            return ch.etype
        return self.store.chain_type_of_held(tenant, chain_id)

    def _fold(self, event: dict[str, Any], *, at: str, jseq: int,
              backfilled: bool) -> list[dict[str, Any]]:
        key = (event["tenant"], event["chain_id"])
        chain = self.chains.get(key)
        if chain is not None and event["event_id"] in chain.consumed:
            # 属于已静默关闭周期的挂起事件，释放时只推进水位，不再触发
            return []
        if chain is None:
            chain = _Chain(event["chain_id"], event["type"])
            self.chains[key] = chain

        if event["phase"] == PHASE_OPEN:
            # 同相重复（重传）：OPEN 相正文按 event_id 区分，允许多次，
            # 交给告警侧的滑动窗口判定
            chain.open_evt = event
            return self._on_open(chain, event, at=at, jseq=jseq,
                                 backfilled=backfilled)

        # RESOLVE
        chain.resolve_evt = event
        return self._on_resolve(chain, event, at=at, jseq=jseq,
                                backfilled=backfilled)

    # ------------------------------------------------------------------
    # 触发相
    # ------------------------------------------------------------------

    def _on_open(self, chain: _Chain, event: dict[str, Any], *, at: str,
                 jseq: int, backfilled: bool) -> list[dict[str, Any]]:
        tenant = event["tenant"]
        etype = event["type"]
        alert = self.store.get_alert_by_chain(tenant, etype, chain.chain_id)

        # 链从未在连续水位内触发过，且收口相已经存在（两种位置），并且
        # 此前未静默关闭过：
        #   ① 收口相先到、已折叠进内存链（resolve_evt，告警尚不存在）；
        #   ② 收口相仍在更高序号的挂起区，OPEN 此刻才补齐释放。
        # 两种都意味着异常在“连续水位之外”既发生又消除 → 静默关闭。
        # 已静默关闭过的链再来 OPEN 属于**新的异常周期**，往下正常触发。
        if not chain.alert_open and not chain.silent_closed:
            held_resolve = self._held_resolve_of(event["tenant"], chain.chain_id)
            if chain.resolve_evt is not None or held_resolve is not None:
                if held_resolve is not None and chain.resolve_evt is None:
                    chain.resolve_evt = held_resolve
                return self._silent_close_pending(chain, event, at=at, jseq=jseq)

        if chain.silent_closed:
            # 上一周期在水位外静默关闭；新 OPEN 开启新周期。清空旧收口，
            # 否则同周期的迟到 RESOLVE 会被旧 resolve 干扰。
            chain.silent_closed = False
            chain.alert_resolved = False
            chain.resolve_evt = None

        if alert is None or alert["status"] == CLOSED:
            return [self._fire_new(chain, event, at=at, jseq=jseq,
                                   backfilled=backfilled)]

        # 活动/已恢复告警再次收到 OPEN：重传 或 恢复后复发
        self.store.insert_alert_event(alert["alert_id"], event, backfilled)
        self.store.touch_alert(alert["alert_id"], event["event_id"], at,
                               increment=True)
        alert = self.store.get_alert(alert["alert_id"])
        chain.open_evt = event

        if alert["status"] == RECOVERED:
            # 异常复发：RECOVERED -> OPEN（恢复后 TTL 未到又坏了）
            new = self.store.cas_alert(
                alert["alert_id"], alert["version"],
                {"status": OPEN, "recovered_at": None,
                 "resolved_event_id": None, "opened_event_id": event["event_id"],
                 "updated_at": at, "silence_id": None})
            # 刚取出的版本，CAS 必中
            self.store.add_audit(
                at, AUD_ALERT_REOPENED, f"alert-reopened:{jseq}:{event['event_id']}",
                {"tenant": tenant, "type": etype,
                 "event_id": event["event_id"], "backfilled": backfilled},
                alert_id=new["alert_id"], tenant=tenant)
            self.store.add_notification(new["alert_id"], event["event_id"],
                                        "reopened", event["occurred_at"])
            return [new]

        # OPEN / ACKED / SILENCED 下的重复触发：滑动窗口去重
        return [self._retransmit(chain, alert, event, at=at)]

    def _fire_new(self, chain: _Chain, event: dict[str, Any], *, at: str,
                  jseq: int, backfilled: bool) -> dict[str, Any]:
        etype = event["type"]
        aid = alert_id_of(event["tenant"], etype, chain.chain_id)
        chain.alert_open = True

        # 静默命中？（精确度：tenant+type > tenant > 全局）
        silence = self._match_silence(event["tenant"], etype, at)
        status = SILENCED if silence else OPEN
        summary = str(event["payload"].get("summary") or SUMMARIES[etype])

        row = {
            "alert_id": aid, "tenant": event["tenant"], "type": etype,
            "chain_id": chain.chain_id, "status": status, "version": 1,
            "severity": str(event["payload"].get("severity")
                            or SEVERITY_BY_TYPE[etype]),
            "summary": summary, "backfilled": 1 if backfilled else 0,
            "occurrence_count": 1, "first_event_id": event["event_id"],
            "last_event_id": event["event_id"],
            "opened_event_id": event["event_id"], "resolved_event_id": None,
            "silence_id": silence["silence_id"] if silence else None,
            "opened_at": at, "updated_at": at, "acked_at": None,
            "acked_by": None, "recovered_at": None, "closed_at": None,
        }
        self.store.insert_alert(row)
        self.store.insert_alert_event(aid, event, backfilled)
        self.store.add_audit(
            at, AUD_ALERT_FIRED, f"alert-fired:{jseq}",
            {"tenant": event["tenant"], "type": etype,
             "chain_id": chain.chain_id, "event_id": event["event_id"],
             "backfilled": backfilled, "silenced": silence is not None,
             "silence_id": silence["silence_id"] if silence else None,
             "reason": event["payload"].get("reason")},
            alert_id=aid, tenant=event["tenant"],
            actor=("silence:" + silence["silence_id"]) if silence else "system")
        kind = "suppressed" if silence else "fired"
        self.store.add_notification(
            aid, event["event_id"], kind, event["occurred_at"],
            note=("silenced by " + silence["silence_id"]) if silence else "")
        return self.store.get_alert(aid)

    def _retransmit(self, chain: _Chain, alert: dict[str, Any],
                    event: dict[str, Any], *, at: str) -> dict[str, Any]:
        window = float(self.dedup_windows.get(event["type"], 600))
        since = to_ts(parse_ts(event["occurred_at"]) - timedelta(seconds=window))
        recent = self.store.notifications_since(alert["alert_id"], since)
        sent = [n for n in recent if n["kind"] in ("fired", "reopened", "resolved-suppressed")]
        if alert["status"] == SILENCED:
            # 静默中的重复一律抑制，不看窗口
            self.store.add_notification(alert["alert_id"], event["event_id"],
                                        "suppressed", event["occurred_at"],
                                        note="alert silenced")
            return self.store.get_alert(alert["alert_id"])
        if sent:
            self.store.add_notification(alert["alert_id"], event["event_id"],
                                        "deduped", event["occurred_at"],
                                        note=f"within {window:.0f}s window")
            self.store.add_audit(
                at, AUD_ALERT_DEDUPED,
                f"alert-deduped:{event['event_id']}",
                {"tenant": event["tenant"], "type": event["type"],
                 "chain_id": chain.chain_id, "window_seconds": window,
                 "occurrence_count": int(alert["occurrence_count"])},
                alert_id=alert["alert_id"], tenant=event["tenant"])
        else:
            self.store.add_notification(alert["alert_id"], event["event_id"],
                                        "fired", event["occurred_at"],
                                        note="window elapsed; re-notify")
        return self.store.get_alert(alert["alert_id"])

    def _silent_close_pending(self, chain: _Chain, open_event: dict[str, Any],
                              *, at: str, jseq: int) -> list[dict[str, Any]]:
        """补齐释放时链已在挂起期间完整（OPEN 与 RESOLVE 同批）。

        不落 OPEN 告警、不发通知：异常从未在连续水位内被观察到。
        只留一条 chain_pending_closed 审计；dedup 键用 OPEN 事件 id，
        重放时不重复落账。
        """
        resolve = chain.resolve_evt
        if resolve is None:
            # 理论不会发生（调用方已保证收口相存在），防御性兜底
            return []
        # 静默关闭这一周期：仍在挂起区的同链事件都属于该周期，
        # 释放时直接消费（只推进水位），不触发告警也不再静默关闭。
        for (tn, _sq), evt in list(self.held.items()):
            if tn == open_event["tenant"] and \
                    evt["chain_id"] == chain.chain_id:
                chain.consumed.add(evt["event_id"])
        self.store.add_audit(
            at, AUD_CHAIN_PENDING_CLOSED,
            f"pending-closed:{open_event['event_id']}",
            {"tenant": open_event["tenant"], "type": open_event["type"],
             "chain_id": chain.chain_id,
             "open_event_id": open_event["event_id"],
             "open_seq": open_event["seq"],
             "resolve_event_id": resolve["event_id"],
             "resolve_seq": resolve["seq"]},
            tenant=open_event["tenant"])
        chain.alert_open = True
        chain.alert_resolved = True
        chain.silent_closed = True
        return []

    # ------------------------------------------------------------------
    # 收口相
    # ------------------------------------------------------------------

    def _on_resolve(self, chain: _Chain, event: dict[str, Any], *, at: str,
                    jseq: int, backfilled: bool) -> list[dict[str, Any]]:
        tenant = event["tenant"]
        etype = event["type"]
        alert = self.store.get_alert_by_chain(tenant, etype, chain.chain_id)

        # OPEN 尚未释放/从未触发：
        #  - 若 OPEN 也在同批挂起且马上释放，_on_open 会走静默关闭；
        #  - 若 OPEN 永远不来，链停在“仅收口”的挂起/游离态，不产生告警。
        if alert is None:
            return []
        if alert["status"] == CLOSED:
            self.store.add_audit(
                at, AUD_RECOVERY_IGNORED, f"recovery-ignored:{event['event_id']}",
                {"tenant": tenant, "type": etype,
                 "chain_id": chain.chain_id, "event_id": event["event_id"],
                 "reason": "alert already closed"},
                alert_id=alert["alert_id"], tenant=tenant)
            return [alert]
        if chain.alert_resolved:
            return [alert]  # 收口相重传，幂等

        self.store.insert_alert_event(alert["alert_id"], event, backfilled)
        new = self.store.cas_alert(
            alert["alert_id"], alert["version"],
            {"status": RECOVERED, "recovered_at": at,
             "resolved_event_id": event["event_id"], "silence_id": None,
             "updated_at": at})
        if new is None:
            # 版本竞争输家：重读，另一条转移已发生；恢复交给赢家或稍后重试
            latest = self.store.get_alert(alert["alert_id"])
            if latest["status"] in (RECOVERED, CLOSED):
                return [latest]
            raise RouterError("ALERT_VERSION_CONFLICT",
                              "恢复与并发命令竞争失败，请重读版本后重试", 409,
                              {"alert_id": alert["alert_id"],
                               "current_status": latest["status"],
                               "version": latest["version"]})
        chain.alert_resolved = True
        self.store.add_audit(
            at, AUD_ALERT_RECOVERED, f"alert-recovered:{jseq}",
            {"tenant": tenant, "type": etype,
             "chain_id": chain.chain_id, "event_id": event["event_id"],
             "from_status": alert["status"], "backfilled": backfilled,
             "auto_close_after_seconds": self.recovered_ttl_seconds},
            alert_id=new["alert_id"], tenant=tenant)
        # 恢复通知本身不受滑动窗口约束（状态转移，必须可达）
        self.store.add_notification(new["alert_id"], event["event_id"],
                                    "resolved", event["occurred_at"])
        return [new]

    # ==================================================================
    # 静默
    # ==================================================================

    def _match_silence(self, tenant: str, etype: str, at: str):
        best = None
        for s in self.store.active_silences(at):
            if s["tenant"] not in (None, tenant):
                continue
            if s["type"] is not None and s["type"] != etype:
                continue
            if best is None:
                best = s
            else:
                # 精确度高的优先：tenant+type > tenant > 全局
                score = (1 if s["tenant"] else 0, 1 if s["type"] else 0)
                bscore = (1 if best["tenant"] else 0, 1 if best["type"] else 0)
                if score > bscore:
                    best = s
        return best

    def _silence_alert(self, alert_id: str, silence_id: str, *, at: str,
                       jseq: int, actor: str, dedup_tag: str | None = None) -> dict[str, Any]:
        alert = self._get_alert_or_404(alert_id)
        if alert["status"] == CLOSED:
            raise RouterError("ALERT_CLOSED", "告警已关闭，不能静默", 409)
        if alert["status"] == SILENCED:
            return alert
        new = self.store.cas_alert(
            alert_id, alert["version"],
            {"status": SILENCED, "silence_id": silence_id, "updated_at": at})
        self._conflict_check(new, alert_id)
        self.store.add_audit(
            at, AUD_ALERT_SILENCED,
            f"alert-silenced:{dedup_tag or jseq}:{alert_id}",
            {"silence_id": silence_id, "from_status": alert["status"]},
            alert_id=alert_id, tenant=alert["tenant"], actor=actor)
        return new

    def _unsilence_alert(self, alert_id: str, *, at: str, jseq: int,
                         actor: str, dedup_tag: str | None = None) -> dict[str, Any]:
        alert = self.store.get_alert(alert_id)
        if alert is None or alert["status"] != SILENCED:
            return alert
        # 静默前是 ACKED 还是 OPEN：静默不改变人工确认事实——
        # 已确认过的回到 ACKED，否则回到 OPEN
        target = ACKED if alert["acked_at"] else OPEN
        new = self.store.cas_alert(
            alert_id, alert["version"],
            {"status": target, "silence_id": None, "updated_at": at})
        self._conflict_check(new, alert_id)
        self.store.add_audit(
            at, AUD_ALERT_UNSILENCED,
            f"alert-unsilenced:{dedup_tag or jseq}:{alert_id}",
            {"to_status": target},
            alert_id=alert_id, tenant=alert["tenant"], actor=actor)
        return new

    # ==================================================================
    # 运维命令（先写 journal 再折叠；CAS 处理确认/恢复竞争）
    # ==================================================================

    def execute(self, command: str, body: dict[str, Any], *,
                actor: str = "operator",
                idem_key: str | None = None) -> dict[str, Any]:
        with self._lock, self.store.lock:
            at = self._clock()
            tenant = body.get("tenant")
            jseq, fresh, prev = self.store.append_command_journal(
                command, body, at, idem_key, tenant=tenant)
            if not fresh:
                # 同幂等键：稳定返回首次结果
                return {**prev, "idempotent_replay": True, "jseq": jseq}
            result = self._apply_command(command, body, at=at, jseq=jseq,
                                         replay=False, actor=actor)
            self.store.set_command_result(jseq, result)
            self._tick(at)
            return result

    def _apply_command(self, command: str, body: dict[str, Any], *, at: str,
                       jseq: int, replay: bool, actor: str = "operator"):
        method = getattr(self, f"_cmd_{command}", None)
        if method is None:
            raise RouterError("UNKNOWN_COMMAND", f"未知命令: {command}", 400)
        return method(body, at=at, jseq=jseq, replay=replay, actor=actor)

    def _get_alert_or_404(self, alert_id: str) -> dict[str, Any]:
        alert = self.store.get_alert(alert_id)
        if alert is None:
            raise RouterError("ALERT_NOT_FOUND", f"无此告警: {alert_id}", 404)
        return alert

    def _conflict_check(self, new: dict[str, Any] | None, alert_id: str) -> dict[str, Any]:
        if new is not None:
            return new
        latest = self.store.get_alert(alert_id)
        raise RouterError("ALERT_VERSION_CONFLICT",
                          "状态已被并发转移（确认/恢复竞争），请重读后重试", 409,
                          {"alert_id": alert_id,
                           "current_status": latest["status"] if latest else None,
                           "version": latest["version"] if latest else None})

    # ---- ack -----------------------------------------------------------
    def _cmd_ack(self, body: dict[str, Any], *, at: str, jseq: int,
                 replay: bool, actor: str) -> dict[str, Any]:
        alert_id = body.get("alert_id")
        version = body.get("version")
        actor = body.get("actor") or actor
        alert = self._get_alert_or_404(alert_id)
        if alert["status"] == ACKED:
            return {"alert_id": alert_id, "status": ACKED,
                    "idempotent_replay": True}
        if alert["status"] == CLOSED:
            raise RouterError("ALERT_CLOSED", "告警已关闭，不能确认", 409)
        if alert["status"] == RECOVERED:
            raise RouterError("ALERT_RECOVERED",
                              "告警已恢复，等待关闭（或直接关闭）", 409)
        if alert["status"] == SILENCED:
            raise RouterError("ALERT_SILENCED",
                              "告警静默中：先解除静默再确认", 409)
        if version is not None and int(version) != int(alert["version"]):
            raise RouterError("ALERT_VERSION_CONFLICT",
                              "版本不匹配（确认竞争输家）", 409,
                              {"alert_id": alert_id,
                               "current_status": alert["status"],
                               "version": alert["version"]})
        new = self.store.cas_alert(
            alert_id, int(version) if version is not None else alert["version"],
            {"status": ACKED, "acked_at": at, "acked_by": actor,
             "updated_at": at})
        new = self._conflict_check(new, alert_id)
        self.store.add_audit(
            at, AUD_ALERT_ACKED, f"alert-acked:{jseq}",
            {"from_status": alert["status"]},
            alert_id=alert_id, tenant=alert["tenant"], actor=actor)
        return new

    # ---- recover（人工声明恢复，等价于链收口） --------------------------
    def _cmd_recover(self, body: dict[str, Any], *, at: str, jseq: int,
                     replay: bool, actor: str) -> dict[str, Any]:
        alert_id = body.get("alert_id")
        version = body.get("version")
        actor = body.get("actor") or actor
        reason = body.get("reason") or "manual recover"
        alert = self._get_alert_or_404(alert_id)
        if alert["status"] == RECOVERED:
            return {"alert_id": alert_id, "status": RECOVERED,
                    "idempotent_replay": True}
        if alert["status"] == CLOSED:
            raise RouterError("ALERT_CLOSED", "告警已关闭", 409)
        if version is not None and int(version) != int(alert["version"]):
            latest = alert
            raise RouterError("ALERT_VERSION_CONFLICT",
                              "版本不匹配（恢复竞争输家）", 409,
                              {"alert_id": alert_id,
                               "current_status": latest["status"],
                               "version": latest["version"]})
        new = self.store.cas_alert(
            alert_id, int(version) if version is not None else alert["version"],
            {"status": RECOVERED, "recovered_at": at, "silence_id": None,
             "updated_at": at})
        new = self._conflict_check(new, alert_id)
        chain = self.chains.get((alert["tenant"], alert["chain_id"]))
        if chain:
            chain.alert_resolved = True
        self.store.add_audit(
            at, AUD_ALERT_RECOVERED, f"alert-recovered:{jseq}",
            {"from_status": alert["status"], "manual": True, "reason": reason},
            alert_id=alert_id, tenant=alert["tenant"], actor=actor)
        self.store.add_notification(alert_id, f"manual-recover-{jseq}",
                                    "resolved", at, note=reason)
        return new

    # ---- close ----------------------------------------------------------
    def _cmd_close(self, body: dict[str, Any], *, at: str, jseq: int,
                   replay: bool, actor: str) -> dict[str, Any]:
        alert_id = body.get("alert_id")
        actor = body.get("actor") or actor
        alert = self._get_alert_or_404(alert_id)
        if alert["status"] == CLOSED:
            return {**alert, "idempotent_replay": True}
        new = self.store.cas_alert(
            alert_id, alert["version"],
            {"status": CLOSED, "closed_at": at, "silence_id": None,
             "updated_at": at})
        new = self._conflict_check(new, alert_id)
        self.store.add_audit(
            at, AUD_ALERT_CLOSED, f"alert-closed:{jseq}",
            {"from_status": alert["status"], "manual": True},
            alert_id=alert_id, tenant=alert["tenant"], actor=actor)
        return new

    # ---- silence rule CR ------------------------------------------------
    def _cmd_create_silence(self, body: dict[str, Any], *, at: str, jseq: int,
                            replay: bool, actor: str) -> dict[str, Any]:
        sid = body.get("silence_id") or ("sil-" + uuid.uuid4().hex[:12])
        tenant = body.get("tenant")
        etype = body.get("type")
        if etype is not None and etype not in (QUARANTINE, TAKEOVER, GAP, AUDIT):
            raise RouterError("BAD_EVENT_TYPE", f"未知事件类型: {etype}", 422)
        starts = body.get("starts_at") or at
        ends = body.get("ends_at")
        if ends:
            if parse_ts(ends) < parse_ts(starts):
                raise RouterError("BAD_SILENCE_WINDOW",
                                  "ends_at 不能早于 starts_at", 422)
        actor = body.get("created_by") or actor
        row = {"silence_id": sid, "tenant": tenant, "type": etype,
               "reason": body.get("reason") or "", "created_by": actor,
               "starts_at": starts, "ends_at": ends, "revoked_at": None,
               "created_via": "command"}
        self.store.upsert_silence(row)
        self.store.add_audit(
            at, AUD_SILENCE_CREATED, f"silence-created:{jseq}",
            {"silence_id": sid, "tenant": tenant, "type": etype,
             "starts_at": starts, "ends_at": ends,
             "reason": row["reason"]}, tenant=tenant, actor=actor)

        # 立即作用于已存在的活动告警（同租户+类型口径）
        affected = []
        for a in self.store.list_alerts(status=OPEN, limit=10000) \
                + self.store.list_alerts(status=ACKED, limit=10000):
            if tenant not in (None, a["tenant"]):
                continue
            if etype is not None and etype != a["type"]:
                continue
            self._silence_alert(a["alert_id"], sid, at=at, jseq=jseq,
                                actor=f"silence:{sid}")
            affected.append(a["alert_id"])
        return {**row, "affected_alert_ids": affected}

    def _cmd_revoke_silence(self, body: dict[str, Any], *, at: str, jseq: int,
                            replay: bool, actor: str) -> dict[str, Any]:
        sid = body.get("silence_id")
        s = self.store.get_silence(sid)
        if s is None:
            raise RouterError("SILENCE_NOT_FOUND", f"无此静默规则: {sid}", 404)
        actor = body.get("actor") or actor
        if s["revoked_at"]:
            return {**s, "idempotent_replay": True}
        self.store.upsert_silence({**s, "revoked_at": at})
        # 解除被它静默的告警
        unsilenced = []
        for a in self.store.alerts_silenced_by(sid):
            self._unsilence_alert(a["alert_id"], at=at, jseq=jseq,
                                  actor=f"silence:{sid}")
            unsilenced.append(a["alert_id"])
        self.store.add_audit(
            at, AUD_SILENCE_REVOKED, f"silence-revoked:{jseq}",
            {"silence_id": sid, "unsilenced": unsilenced},
            tenant=s["tenant"], actor=actor)
        return {"silence_id": sid, "revoked_at": at,
                "unsilenced_alert_ids": unsilenced}

    # ---- 单条告警静默/解除（per-alert，走临时规则） ----------------------
    def _cmd_silence_alert(self, body: dict[str, Any], *, at: str, jseq: int,
                           replay: bool, actor: str) -> dict[str, Any]:
        alert_id = body.get("alert_id")
        alert = self._get_alert_or_404(alert_id)
        sid = body.get("silence_id") or f"sil-alert-{alert_id[:12]}"
        ends = body.get("ends_at")
        actor = body.get("actor") or actor
        if self.store.get_silence(sid) is None:
            self.store.upsert_silence({
                "silence_id": sid, "tenant": alert["tenant"],
                "type": alert["type"], "reason": body.get("reason")
                or "per-alert silence", "created_by": actor,
                "starts_at": at, "ends_at": ends, "revoked_at": None,
                "created_via": "alert-command"})
            self.store.add_audit(
                at, AUD_SILENCE_CREATED, f"silence-created:{jseq}",
                {"silence_id": sid, "tenant": alert["tenant"],
                 "type": alert["type"], "per_alert": alert_id,
                 "ends_at": ends},
                alert_id=alert_id, tenant=alert["tenant"], actor=actor)
        return self._silence_alert(alert_id, sid, at=at, jseq=jseq, actor=actor)

    def _cmd_unsilence_alert(self, body: dict[str, Any], *, at: str, jseq: int,
                             replay: bool, actor: str) -> dict[str, Any]:
        alert_id = body.get("alert_id")
        actor = body.get("actor") or actor
        alert = self._get_alert_or_404(alert_id)
        sid = alert.get("silence_id")
        new = self._unsilence_alert(alert_id, at=at, jseq=jseq, actor=actor)
        if sid and self.store.get_silence(sid) and \
                self.store.get_silence(sid)["created_via"] == "alert-command":
            s = self.store.get_silence(sid)
            self.store.upsert_silence({**s, "revoked_at": at})
        return new

    # ==================================================================
    # 定时收口：静默到期 + RECOVERED TTL
    # ==================================================================

    def _tick(self, at: str) -> dict[str, int]:
        expired = 0
        auto_closed = 0

        for s in self.store.expire_candidates(at):
            tag = f"tick:{s['silence_id']}"
            # 标记规则到期，并把仍被它静默的告警恢复到静默前状态
            unsilenced = []
            for a in self.store.alerts_silenced_by(s["silence_id"]):
                self._unsilence_alert(a["alert_id"], at=at, jseq=0,
                                      actor=f"silence:{s['silence_id']}",
                                      dedup_tag=tag)
                unsilenced.append(a["alert_id"])
            self.store.upsert_silence({**s, "revoked_at": at})
            self.store.add_audit(
                at, AUD_SILENCE_EXPIRED,
                f"silence-expired:{s['silence_id']}",
                {"silence_id": s["silence_id"], "unsilenced": unsilenced},
                tenant=s["tenant"], actor="system")
            expired += 1

        for a in self.store.recovered_candidates(at, self.recovered_ttl_seconds):
            new = self.store.cas_alert(
                a["alert_id"], a["version"],
                {"status": CLOSED, "closed_at": at, "updated_at": at})
            if new is None:
                continue
            self.store.add_audit(
                at, AUD_RECOVERED_TTL_CLOSED,
                f"recovered-ttl:{a['alert_id']}:{a['version']}",
                {"recovered_at": a["recovered_at"],
                 "ttl_seconds": self.recovered_ttl_seconds},
                alert_id=a["alert_id"], tenant=a["tenant"], actor="system")
            auto_closed += 1

        return {"silences_expired": expired, "recovered_auto_closed": auto_closed}

    # ==================================================================
    # 查询面
    # ==================================================================

    def list_alerts(self, **kw) -> list[dict[str, Any]]:
        with self._lock:
            return self.store.list_alerts(**kw)

    def get_alert_detail(self, alert_id: str) -> dict[str, Any]:
        with self._lock:
            alert = self._get_alert_or_404(alert_id)
            events = self.store.list_alert_events(alert_id)
            notifs = self.store.list_notifications(alert_id)
            audits = self.store.list_audit(alert_id=alert_id, limit=200,
                                           ascending=True)
            return {"alert": alert, "events": events,
                    "notifications": notifs, "audit": audits}

    def list_audit(self, **kw) -> list[dict[str, Any]]:
        with self._lock:
            return self.store.list_audit(**kw)

    def list_silences(self, include_revoked: bool = False) -> list[dict[str, Any]]:
        with self._lock:
            return self.store.list_silences(include_revoked)

    def pending_view(self) -> dict[str, Any]:
        """挂起视图：仍缺的水位、挂起事件、以及未触发的游离链。"""
        with self._lock:
            held_rows = self.store.held_events()
            by_tenant: dict[str, list[dict[str, Any]]] = {}
            for r in held_rows:
                by_tenant.setdefault(r["tenant"], []).append(r)
            tenants = []
            for tenant, rows in by_tenant.items():
                t = self.store.get_tenant(tenant)
                seqs = sorted(r["seq"] for r in rows)
                missing = []
                nxt = int(t["next_seq"])
                while nxt < min(seqs):
                    missing.append(nxt)
                    nxt += 1
                chains = sorted({r["chain_id"] for r in rows})
                tenants.append({"tenant": tenant,
                                "watermark": int(t["next_seq"]) - 1,
                                "next_seq": int(t["next_seq"]),
                                "missing_seqs": missing,
                                "held_count": len(rows),
                                "held_seqs": seqs,
                                "held_chains": chains})
            return {"tenants": sorted(tenants, key=lambda x: x["tenant"])}

    def watermarks(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.store.conn.execute(
                "SELECT t.*, ("
                "  SELECT COUNT(*) FROM stream_events s"
                "  WHERE s.tenant = t.tenant AND s.held = 1) AS held_count"
                " FROM tenants t ORDER BY t.tenant").fetchall()
            return [{"tenant": r["tenant"], "next_seq": int(r["next_seq"]),
                     "watermark": int(r["next_seq"]) - 1,
                     "watermark_event_id": r["watermark_event_id"],
                     "held_count": int(r["held_count"])} for r in rows]

    def stats(self) -> dict[str, Any]:
        with self._lock:
            counts = {}
            for st in (OPEN, ACKED, RECOVERED, SILENCED, CLOSED):
                r = self.store.conn.execute(
                    "SELECT COUNT(*) c FROM alerts WHERE status = ?",
                    (st,)).fetchone()
                counts[st.lower()] = int(r["c"])
            r = self.store.conn.execute("SELECT COUNT(*) c FROM journal").fetchone()
            held = self.store.conn.execute(
                "SELECT COUNT(*) c FROM stream_events WHERE held = 1").fetchone()
            gaps = self.store.conn.execute(
                "SELECT COUNT(*) c FROM audit_log WHERE kind = ?",
                (AUD_STREAM_GAP,)).fetchone()
            return {"alerts": counts, "journal_entries": int(r["c"]),
                    "held_events": int(held["c"]),
                    "stream_gaps": int(gaps["c"]),
                    "dedup_windows": dict(self.dedup_windows),
                    "recovered_ttl_seconds": self.recovered_ttl_seconds,
                    "max_jseq": self.store.max_jseq()}
