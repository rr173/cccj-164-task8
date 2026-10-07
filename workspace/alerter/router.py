"""告警路由引擎。

输入与闸门
==========

规范化事件先按 ``event_id`` 幂等登记，随后通过两道闸门才可能触发告警：

1. **连续水位**：事件在其租户流上带单调 ``seq``，只有序号恰好等于
   “已应用连续水位 + 1”的事件才会被处理；更靠后的事件停在库里等待缺口
   补齐。缺口本身被检测并审计（``watermark_gap_detected``），补齐后审计
   ``watermark_gap_filled`` 并继续放行被挡住的事件；
2. **完整事件链**：同 ``chain_id`` 的角色必须满足 :data:`models.CHAIN_RULES`
   （ISOLATION/GAP 需 BEGIN+WITNESS，TAKEOVER 需 BEGIN+END+WITNESS）。

聚合、去重与静默
================

- 同一「租户 + 类型」同时只有一条活动告警，后续同类链作为发生（occurrence）
  聚合进去；
- **滑动窗口去重**：窗口锚定“上次真正通知”的时刻，窗口内的新发生只记录、
  审计 ``alert_deduped``，不重复通知；被抑制的发生不滑动延长窗口；
- 触发时若命中生效的静默规则，告警以 SILENCED 建立（不通知）。

缺口补齐语义
============

- BEGIN 被 END 关闭时链仍未完整（如 TAKEOVER 的 WITNESS 还在缺口后）：
  链以 BORN_CLOSED 静默关闭，**不补发**；
- ISOLATION/GAP 已触发后 END 才到：链关闭，且该告警聚合的所有链都关闭时
  **自动恢复**（RESOLVED）；
- TAKEOVER 必须见到 END 才完整：触发时生命周期已闭合，通知一次后同事务
  自动恢复。

确认与恢复竞争
==============

每个状态转移都是 ``UPDATE ... WHERE status IN (...)`` 的条件更新，且与审计
记录在同一事务：确认与恢复并发时只有一个事务赢，全局只落一次状态、一条
审计；输家按既有状态幂等返回。进程重启后所有状态以存储为准重建（无内存
易失状态），静默到期在启动时立即 sweep，不依赖下一个请求。
"""

from __future__ import annotations

import threading
import time
import uuid
from typing import Any, Callable

from . import models
from .store import AlertStore


def _summary(alert_type: str, reason: str, chain_id: str) -> str:
    label = {
        models.ISOLATION: "复制器隔离",
        models.TAKEOVER: "灾备接管",
        models.GAP: "复制缺口",
    }.get(alert_type, alert_type)
    reason_part = f"（{reason}）" if reason else ""
    return f"{label}告警{reason_part}：{chain_id}"


class AlertRouter:
    def __init__(
        self,
        store: AlertStore,
        *,
        default_window_seconds: int = 300,
        window_seconds: dict[tuple[str, str], int] | None = None,
        notifier: Callable[[dict[str, Any]], None] | None = None,
        clock: Callable[[], float] | None = None,
    ):
        self.store = store
        self.default_window_seconds = default_window_seconds
        # 细粒度窗口：(tenant, alert_type) -> 秒
        self.window_seconds = window_seconds or {}
        self._notifier = notifier
        self._clock = clock or time.time
        # 进程内串行化接收路径；跨进程安全仍由 BEGIN IMMEDIATE + 条件更新保证
        self._lock = threading.RLock()

    def now(self) -> float:
        return float(self._clock())

    def _window_for(self, tenant: str, alert_type: str) -> int:
        return int(
            self.window_seconds.get((tenant, alert_type), self.default_window_seconds)
        )

    # ------------------------------------------------------------------
    # 生命周期 / 重启恢复
    # ------------------------------------------------------------------

    def recover_on_startup(self) -> dict[str, Any]:
        """服务重启恢复：所有状态以存储为准，立即收口到期静默与过期窗口。

        告警/链/去重窗口全部持久化，不存在内存易失状态；这里只做：
        ① 静默规则已到期/已失效但告警仍 SILENCED 的恢复；② 去重窗口清扫；
        ③ 留一条 router_recovered 审计（含连续水位与缺口现状）。
        """
        with self._lock, self.store.transaction() as conn:
            stats = {
                "silences_restored": self._sweep_silences_locked(conn, self.now()),
                "windows_pruned": self.store.prune_windows(self.now()),
                "tenants": [],
            }
            for tenant in self.store.known_tenants():
                stats["tenants"].append({
                    "tenant": tenant,
                    "contiguous_until": self.store.contiguous_until(tenant),
                    "open_gaps": self.store.list_gaps(tenant=tenant),
                    "pending_events": self._pending_count_locked(tenant),
                })
            self.store.audit(models.AUDIT_ROUTER_RECOVERED, stats)
        return stats

    def start(self) -> None:
        with self._lock, self.store.transaction() as conn:
            self.store.audit(models.AUDIT_ROUTER_STARTED, {
                "default_window_seconds": self.default_window_seconds,
            })
        self.recover_on_startup()

    def _pending_count_locked(self, tenant: str) -> int:
        row = self.store.conn.execute(
            "SELECT COUNT(*) AS c FROM events WHERE tenant=? AND applied=0",
            (tenant,),
        ).fetchone()
        return int(row["c"])

    # ------------------------------------------------------------------
    # 事件接收（幂等登记 → 水位闸门 → 链评估）
    # ------------------------------------------------------------------

    def ingest_event(self, raw_event: dict[str, Any]) -> dict[str, Any]:
        """接收单条规范化事件。返回处理结果（含通知是否发出）。"""
        ev = models.normalize_event(raw_event)
        notifications: list[dict[str, Any]] = []
        with self._lock, self.store.transaction() as conn:
            stored, duplicate = self.store.register_event(ev, self.now())
            result: dict[str, Any] = {
                "event_id": stored["event_id"],
                "tenant": stored["tenant"],
                "seq": stored["seq"],
                "duplicate": duplicate,
            }
            if duplicate:
                # 同事件幂等：同一 event_id 再投递，原结果语义上不重复触发
                result["outcome"] = "duplicate_ignored"
                result["applied"] = bool(stored["applied"])
                return result
            self.store.audit(models.AUDIT_EVENT_RECEIVED, {
                "event_id": stored["event_id"],
                "tenant": stored["tenant"],
                "event_type": stored["event_type"],
                "role": stored["role"],
                "chain_id": stored["chain_id"],
                "seq": stored["seq"],
                "reason": stored["reason"],
            })
            notifications = self._drain_tenant_locked(conn, stored["tenant"])
            result["watermark"] = self.store.contiguous_until(stored["tenant"])
            result["notifications"] = [
                {"alert_id": n["alert"]["id"], "alert_type": n["alert"]["alert_type"],
                 "tenant": n["alert"]["tenant"]}
                for n in notifications
            ]
        # 事务提交成功后才对外通知（绝不在回滚后误发）
        for note in notifications:
            self._deliver(note)
        return result

    def ingest_batch(self, raw_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """批量接收：按规范化后的 (tenant, seq/到达序) 顺序入流，统一开闸。"""
        if not isinstance(raw_events, list):
            raise models.AlertError("BAD_EVENT", "批量事件必须是数组", 400)
        events = [models.normalize_event(e) for e in raw_events]
        results: list[dict[str, Any]] = []
        notifications: list[dict[str, Any]] = []
        with self._lock, self.store.transaction() as conn:
            for ev in events:
                stored, duplicate = self.store.register_event(ev, self.now())
                if duplicate:
                    results.append({"event_id": stored["event_id"],
                                    "tenant": stored["tenant"], "seq": stored["seq"],
                                    "duplicate": True, "outcome": "duplicate_ignored",
                                    "applied": bool(stored["applied"])})
                else:
                    self.store.audit(models.AUDIT_EVENT_RECEIVED, {
                        "event_id": stored["event_id"], "tenant": stored["tenant"],
                        "event_type": stored["event_type"], "role": stored["role"],
                        "chain_id": stored["chain_id"], "seq": stored["seq"],
                        "reason": stored["reason"], "batch": True,
                    })
                    results.append({"event_id": stored["event_id"],
                                    "tenant": stored["tenant"], "seq": stored["seq"],
                                    "duplicate": False})
            for tenant in self.store.known_tenants():
                notifications.extend(self._drain_tenant_locked(conn, tenant))
            for r in results:
                if not r.get("duplicate"):
                    r["watermark"] = self.store.contiguous_until(r["tenant"])
                    r["notifications"] = [
                        {"alert_id": n["alert"]["id"],
                         "alert_type": n["alert"]["alert_type"]}
                        for n in notifications
                        if n["alert"]["tenant"] == r["tenant"]
                    ]
        for note in notifications:
            self._deliver(note)
        return results

    def _drain_tenant_locked(self, conn: sqlite3.Connection, tenant: str) -> list[dict[str, Any]]:  # type: ignore[name-defined]
        """连续水位闸门：按序号顺序放行所有“水位已连续到达”的事件。"""
        notifications: list[dict[str, Any]] = []
        while True:
            watermark = self.store.contiguous_until(tenant)
            due = self.store.next_due_event(tenant, watermark + 1)
            if due is None:
                # 下一个序号缺失：登记缺口（已登记不重复审计）；
                # 缺口本身不作为 GAP 告警触发——GAP 告警来自规范化 GAP 事件，
                # 缺口检测仅保证“连续水位不成立时不触发”并保持可观测。
                if self._exists_unapplied_after(tenant, watermark + 1):
                    if self.store.ensure_gap(tenant, watermark + 1, self.now(), {}):
                        self.store.audit(models.AUDIT_GAP_DETECTED, {
                            "tenant": tenant,
                            "missing_seq": watermark + 1,
                            "watermark": watermark,
                        })
                break
            notifications.extend(self._apply_event_locked(conn, due))
            self.store.mark_event_applied(due["event_id"], self.now())
            new_watermark = self.store.contiguous_until(tenant)
            filled_ids = self.store.fill_gaps_until(
                tenant, watermark, new_watermark, self.now(),
                f"连续水位恢复至 {new_watermark}，缺口区间补齐")
            if filled_ids:
                self.store.audit(models.AUDIT_GAP_FILLED, {
                    "tenant": tenant, "gap_record_ids": filled_ids,
                    "watermark": new_watermark,
                })
        return notifications

    def _exists_unapplied_after(self, tenant: str, seq: int) -> bool:
        row = self.store.conn.execute(
            "SELECT 1 FROM events WHERE tenant=? AND applied=0 AND seq >= ? LIMIT 1",
            (tenant, seq),
        ).fetchone()
        return row is not None

    # ------------------------------------------------------------------
    # 事件应用（链角色 → 完整性判定 → 触发/关闭/恢复）
    # ------------------------------------------------------------------

    def _apply_event_locked(self, conn: sqlite3.Connection, ev: dict[str, Any]) -> list[dict[str, Any]]:
        now = self.now()
        role = ev["role"]
        # AUDIT 见证必须挂到一条链上（BEGIN 可能还在缺口之后）
        if role == models.WITNESS:
            chain = self.store.ensure_chain(
                ev["chain_id"], ev["tenant"], None, now)
            self.store.chain_mark_role(ev["chain_id"], models.WITNESS, "", now)
        else:
            chain = self.store.ensure_chain(
                ev["chain_id"], ev["tenant"], ev["event_type"], now)
            self.store.chain_mark_role(
                ev["chain_id"], role, ev["reason"], now)

        chain = self.store.get_chain(ev["chain_id"])
        assert chain is not None
        notifications = self._evaluate_chain_locked(conn, chain, ev)
        # 本次事件刚把链绑定到告警后重读一次（绑定在评估内部完成）：
        # TAKEOVER 同批里 END 先到、WITNESS 后补齐的顺序下，恢复判定要基于最新行。
        fresh = self.store.get_chain(ev["chain_id"])
        if fresh and fresh["alert_id"] and ev["role"] == models.END:
            self._auto_resolve_if_all_closed_locked(conn, fresh["alert_id"], ev)
        return notifications

    def _roles_present(self, chain: dict[str, Any], alert_type: str) -> bool:
        needed = models.CHAIN_RULES[alert_type]
        have: set[str] = set()
        if chain["saw_begin"]:
            have.add(models.BEGIN)
        if chain["saw_end"]:
            have.add(models.END)
        if int(chain["witnesses"]) > 0:
            have.add(models.WITNESS)
        return needed.issubset(have)

    def _evaluate_chain_locked(self, conn, chain: dict[str, Any], ev: dict[str, Any]) -> list[dict[str, Any]]:
        # 已绑定告警的链：只有 END 到达可能触发自动恢复，
        # 其余角色（如晚到的重复见证）绝不再聚合一次发生。
        if chain["alert_id"]:
            if ev["role"] == models.END:
                self._auto_resolve_if_all_closed_locked(conn, chain["alert_id"], ev)
            return []
        if chain["status"] == models.CHAIN_BORN_CLOSED:
            return []  # 未触发即终态：补到的任何角色都不再补发
        alert_type = chain["event_type"]
        if not alert_type or not self._roles_present(chain, alert_type):
            return []  # 链不完整：等待缺口后的剩余角色
        # 完整事件链成立
        self.store.audit(models.AUDIT_CHAIN_COMPLETE, {
            "chain_id": chain["chain_id"], "tenant": chain["tenant"],
            "alert_type": alert_type, "status": chain["status"],
            "roles": {"begin": bool(chain["saw_begin"]),
                      "end": bool(chain["saw_end"]),
                      "witnesses": int(chain["witnesses"])},
        })
        if chain["status"] == models.CHAIN_CLOSED and alert_type in (
            models.ISOLATION, models.GAP
        ):
            # ISOLATION/GAP：END 先于链完整（WITNESS 还在缺口后）到达，
            # 缺口补齐时链已是终态——不补发，静默关闭。
            self.store.chain_mark_born_closed(chain["chain_id"], self.now())
            self.store.audit(models.AUDIT_CHAIN_BORN_CLOSED, {
                "chain_id": chain["chain_id"], "tenant": chain["tenant"],
                "alert_type": alert_type,
                "reason": models.BORN_CLOSED_REASON,
            })
            return []
        note = self._fire_chain_locked(conn, chain, ev)
        return [note] if note else []

    def _fire_chain_locked(self, conn, chain: dict[str, Any], ev: dict[str, Any]) -> dict[str, Any] | None:
        """链完整后的唯一触发路径：聚合 / 去重 / 静默 / 通知决策。"""
        now = self.now()
        tenant = chain["tenant"]
        alert_type = chain["event_type"]
        reason = chain["last_reason"] or ev["reason"]
        fingerprint = reason or "__generic__"
        window_seconds = self._window_for(tenant, alert_type)

        existing = self.store.find_active_alert(tenant, alert_type)
        # 滑动窗口：锚定上次真正通知（新告警/聚合发生共用一个判定）
        open_window = self.store.get_open_window(tenant, alert_type, fingerprint, now)

        # 静默规则在触发时匹配（规则期内新发生不通知，以 SILENCED 聚合）
        rule = self.store.match_silence_rule(tenant, alert_type, reason, now)

        if existing is None:
            initial_status = models.ST_SILENCED if rule else models.ST_FIRING
            alert_id = f"AL-{uuid.uuid4().hex[:16]}"
            alert = {
                "id": alert_id,
                "tenant": tenant,
                "alert_type": alert_type,
                "status": initial_status,
                "summary": _summary(alert_type, reason, chain["chain_id"]),
                # 发生计数统一由 add_occurrence 维护（本函数随后记第一次）
                "occurrence_count": 0,
                "last_chain_id": chain["chain_id"],
                "last_reason": reason,
                "created_at": now,
                "updated_at": now,
                "first_fired_at": now,
                "last_notified_at": None,
                "silence_rule_id": rule["id"] if rule else None,
                "pre_silence_state": None,
            }
            self.store.create_alert(alert)
        else:
            alert_id = existing["id"]

        self.store.chain_bind_alert(chain["chain_id"], alert_id, now)

        # 是否真正通知：静默不通知；滑动窗口命中不通知；其余通知并重新锚定窗口
        fresh_alert = self.store.get_alert(alert_id)
        assert fresh_alert is not None
        silenced = fresh_alert["status"] == models.ST_SILENCED
        should_notify = not silenced and open_window is None

        self.store.add_occurrence(
            alert_id, chain["chain_id"], ev["seq"], ev["event_id"],
            reason, now, notified=should_notify)

        if should_notify:
            self.store.anchor_window(
                tenant, alert_type, fingerprint, window_seconds, now)
            self.store.transition_alert(
                alert_id, models.ACTIVE_STATES, fresh_alert["status"], now,
                {"last_notified_at": now})
            self.store.audit(models.AUDIT_ALERT_FIRED, {
                "alert_id": alert_id, "tenant": tenant, "alert_type": alert_type,
                "chain_id": chain["chain_id"], "reason": reason,
                "fingerprint": fingerprint, "window_seconds": window_seconds,
                "new_alert": existing is None,
                "silence_rule_id": rule["id"] if rule else None,
            })
        else:
            why = "silence_rule" if silenced else "dedup_window"
            effective_rule_id = rule["id"] if rule else (
                fresh_alert["silence_rule_id"] if silenced else None)
            self.store.audit(models.AUDIT_ALERT_DEDUPED, {
                "alert_id": alert_id, "tenant": tenant, "alert_type": alert_type,
                "chain_id": chain["chain_id"], "reason": reason,
                "fingerprint": fingerprint,
                "suppressed_by": why,
                "silence_rule_id": effective_rule_id,
                "window_anchor_at": open_window["anchor_at"] if open_window else None,
                "window_expires_at": open_window["expires_at"] if open_window else None,
                "new_alert": existing is None,
            })

        alert_view = self.get_alert(alert_id)
        note = None
        if should_notify:
            note = {"alert": alert_view, "chain_id": chain["chain_id"],
                    "reason": reason, "at": now}

        # TAKEOVER 链触发时 END 必已存在（规则要求），生命周期已闭合：
        # 通知一次后同事务自动恢复；ISO/GAP 聚合的链全部关闭时也自动恢复。
        self._auto_resolve_if_all_closed_locked(conn, alert_id, ev)
        return note

    def _auto_resolve_if_all_closed_locked(self, conn, alert_id: str,
                                           ev: dict[str, Any]) -> None:
        alert = self.store.get_alert(alert_id)
        if alert is None or alert["status"] in models.TERMINAL_STATES:
            return
        open_chains = self.store.open_chain_count(alert_id)
        if open_chains != 0:
            return
        now = self.now()
        # 已确认的告警也随缺口补齐自动恢复：RESOLVED 是系统事实（连续水位恢复
        # 且链全部闭合），确认只表达“人已知晓”，不阻止事实态推进。
        won = self.store.transition_alert(
            alert_id, models.ACTIVE_STATES, models.ST_RESOLVED, now,
            {"resolved_at": now, "resolved_reason": models.AUTO_RESOLVE_REASON})
        if won:
            self.store.audit(models.AUDIT_ALERT_RESOLVED, {
                "alert_id": alert_id, "tenant": alert["tenant"],
                "alert_type": alert["alert_type"],
                "reason": models.AUTO_RESOLVE_REASON,
                "trigger_event_id": ev["event_id"],
                "trigger_seq": ev["seq"],
                "previous_status": alert["status"],
                "note": "缺口补齐/链终态到达后自动恢复",
            })

    # ------------------------------------------------------------------
    # 运维动作：确认 / 静默 / 恢复
    # ------------------------------------------------------------------

    def ack_alert(self, alert_id: str, by: str = "operator",
                  note: str = "") -> dict[str, Any]:
        with self._lock, self.store.transaction() as conn:
            alert = self.store.get_alert(alert_id)
            if alert is None:
                raise models.AlertError("NOT_FOUND", f"告警不存在: {alert_id}", 404)
            if alert["status"] in models.TERMINAL_STATES:
                return alert  # 终态幂等
            if alert["status"] == models.ST_ACKED:
                return alert  # 重复确认幂等
            if alert["status"] == models.ST_SILENCED:
                raise models.AlertError(
                    "ALERT_SILENCED",
                    f"告警 {alert_id} 处于静默中，请先解除静默再确认", 409,
                    details={"alert_id": alert_id, "silence_rule_id": alert["silence_rule_id"]})
            won = self.store.transition_alert(
                alert_id, (models.ST_FIRING,), models.ST_ACKED, self.now())
            if won:
                self.store.audit(models.AUDIT_ALERT_ACKED, {
                    "alert_id": alert_id, "tenant": alert["tenant"],
                    "alert_type": alert["alert_type"], "by": by, "note": note,
                })
            final = self.store.get_alert(alert_id)
            assert final is not None
            return final

    def unack_alert(self, alert_id: str, by: str = "operator") -> dict[str, Any]:
        with self._lock, self.store.transaction() as conn:
            alert = self.store.get_alert(alert_id)
            if alert is None:
                raise models.AlertError("NOT_FOUND", f"告警不存在: {alert_id}", 404)
            if alert["status"] in models.TERMINAL_STATES:
                raise models.AlertError(
                    "ALERT_TERMINAL", f"告警 {alert_id} 已终态，不能取消确认", 409)
            if alert["status"] != models.ST_ACKED:
                raise models.AlertError(
                    "INVALID_STATE", f"告警当前为 {alert['status']}，无需取消确认", 409)
            won = self.store.transition_alert(
                alert_id, (models.ST_ACKED,), models.ST_FIRING, self.now())
            if won:
                self.store.audit(models.AUDIT_ALERT_UNACKED, {
                    "alert_id": alert_id, "by": by})
            final = self.store.get_alert(alert_id)
            assert final is not None
            return final

    def silence_alert(self, alert_id: str, *, ttl_seconds: int | None = None,
                      note: str = "", by: str = "operator") -> dict[str, Any]:
        """静默单条告警：为它建立一条精准（类型+原因码）静默规则。"""
        with self._lock, self.store.transaction() as conn:
            alert = self.store.get_alert(alert_id)
            if alert is None:
                raise models.AlertError("NOT_FOUND", f"告警不存在: {alert_id}", 404)
            if alert["status"] in models.TERMINAL_STATES:
                raise models.AlertError(
                    "ALERT_TERMINAL", f"告警 {alert_id} 已终态，不能静默", 409)
            if alert["status"] == models.ST_SILENCED:
                return alert  # 幂等
            rule_id = f"SL-{uuid.uuid4().hex[:16]}"
            now = self.now()
            rule = {
                "id": rule_id,
                "tenant": alert["tenant"],
                "alert_type": alert["alert_type"],
                "reason": alert["last_reason"] or None,
                "note": note or f"静默告警 {alert_id}",
                "created_by": by,
                "ttl_seconds": ttl_seconds,
                "created_at": now,
                "expires_at": now + ttl_seconds if ttl_seconds else None,
            }
            self.store.create_silence_rule(rule)
            won = self.store.transition_alert(
                alert_id, (models.ST_FIRING, models.ST_ACKED),
                models.ST_SILENCED, now,
                {"silence_rule_id": rule_id,
                 "pre_silence_state": alert["status"]})
            if won:
                self.store.audit(models.AUDIT_ALERT_SILENCED, {
                    "alert_id": alert_id, "silence_rule_id": rule_id,
                    "ttl_seconds": ttl_seconds, "by": by, "note": note,
                    "previous_status": alert["status"],
                })
                self.store.audit(models.AUDIT_SILENCE_RULE_CREATED,
                                 {**rule, "ad_hoc": True})
            final = self.store.get_alert(alert_id)
            assert final is not None
            return final

    def unsilence_alert(self, alert_id: str, *, delete_rule: bool = False,
                        by: str = "operator") -> dict[str, Any]:
        with self._lock, self.store.transaction() as conn:
            alert = self.store.get_alert(alert_id)
            if alert is None:
                raise models.AlertError("NOT_FOUND", f"告警不存在: {alert_id}", 404)
            if alert["status"] != models.ST_SILENCED:
                if alert["status"] in models.TERMINAL_STATES:
                    return alert
                raise models.AlertError(
                    "INVALID_STATE", f"告警当前为 {alert['status']}，未处于静默", 409)
            target = alert["pre_silence_state"] or models.ST_FIRING
            rule_id = alert["silence_rule_id"]
            won = self.store.transition_alert(
                alert_id, (models.ST_SILENCED,), target, self.now(),
                {"silence_rule_id": None, "pre_silence_state": None})
            if won and rule_id and delete_rule:
                # 仅删除 ad-hoc 单告警规则；规则级静默由 /silences 管理
                self.store.delete_silence_rule_if_exists(rule_id)
            if won:
                self.store.audit(models.AUDIT_ALERT_UNSILENCED, {
                    "alert_id": alert_id, "restored_to": target,
                    "rule_id": rule_id, "rule_deleted": bool(won and delete_rule),
                    "by": by})
            final = self.store.get_alert(alert_id)
            assert final is not None
            return final

    def close_alert(self, alert_id: str, *, by: str = "operator",
                    note: str = "", reason_code: str = "MANUAL_CLOSE") -> dict[str, Any]:
        """人工恢复/关闭。与自动恢复并发时：终态幂等返回，绝不覆盖 RESOLVED。"""
        with self._lock, self.store.transaction() as conn:
            alert = self.store.get_alert(alert_id)
            if alert is None:
                raise models.AlertError("NOT_FOUND", f"告警不存在: {alert_id}", 404)
            if alert["status"] in models.TERMINAL_STATES:
                # 恢复竞争：自动 RESOLVED 与人工 CLOSED 同时到达时，
                # 先落盘的终态为准，后者幂等返回，不覆盖、不补审计。
                return alert
            now = self.now()
            won = self.store.transition_alert(
                alert_id, (models.ST_FIRING, models.ST_ACKED, models.ST_SILENCED),
                models.ST_CLOSED, now,
                {"closed_at": now, "resolved_at": now,
                 "resolved_reason": reason_code,
                 "silence_rule_id": None})
            if won:
                self.store.audit(models.AUDIT_ALERT_CLOSED, {
                    "alert_id": alert_id, "tenant": alert["tenant"],
                    "alert_type": alert["alert_type"], "by": by, "note": note,
                    "reason": reason_code, "previous_status": alert["status"],
                })
            final = self.store.get_alert(alert_id)
            assert final is not None
            return final

    # ------------------------------------------------------------------
    # 静默规则
    # ------------------------------------------------------------------

    def create_silence_rule(self, tenant: str, alert_type: str | None = None,
                           reason: str | None = None, *, ttl_seconds: int | None = None,
                           note: str = "", created_by: str = "operator",
                           silence_existing: bool = False) -> dict[str, Any]:
        if alert_type is not None and alert_type not in models.ALERT_TYPES:
            raise models.AlertError("BAD_SILENCE",
                                    f"alert_type 必须是 {models.ALERT_TYPES} 之一", 400)
        if ttl_seconds is not None and (not isinstance(ttl_seconds, int) or ttl_seconds <= 0):
            raise models.AlertError("BAD_SILENCE", "ttl_seconds 必须是正整数", 400)
        with self._lock, self.store.transaction() as conn:
            now = self.now()
            rule = {
                "id": f"SL-{uuid.uuid4().hex[:16]}",
                "tenant": tenant,
                "alert_type": alert_type,
                "reason": reason or None,
                "note": note,
                "created_by": created_by,
                "ttl_seconds": ttl_seconds,
                "created_at": now,
                "expires_at": now + ttl_seconds if ttl_seconds else None,
            }
            self.store.create_silence_rule(rule)
            self.store.audit(models.AUDIT_SILENCE_RULE_CREATED, rule)
            silenced = []
            if silence_existing:
                for alert in self.store.list_alerts(tenant=tenant, status=models.ST_FIRING):
                    if alert_type and alert["alert_type"] != alert_type:
                        continue
                    if reason and alert["last_reason"] != reason:
                        continue
                    if self.store.transition_alert(
                        alert["id"], (models.ST_FIRING, models.ST_ACKED),
                        models.ST_SILENCED, now,
                        {"silence_rule_id": rule["id"],
                         "pre_silence_state": alert["status"]}):
                        self.store.audit(models.AUDIT_ALERT_SILENCED, {
                            "alert_id": alert["id"], "silence_rule_id": rule["id"],
                            "by": created_by, "backfilled": True})
                        silenced.append(alert["id"])
            rule["silenced_existing"] = silenced
            return rule

    def delete_silence_rule(self, rule_id: str, *, by: str = "operator") -> dict[str, Any]:
        with self._lock, self.store.transaction() as conn:
            rule = self.store.get_silence_rule(rule_id)
            if rule is None:
                raise models.AlertError("NOT_FOUND", f"静默规则不存在: {rule_id}", 404)
            restored = []
            # 规则删除：被它静默的告警恢复到静默前状态
            for alert in self.store.alerts_silenced_by(rule_id):
                target = alert["pre_silence_state"] or models.ST_FIRING
                if self.store.transition_alert(
                    alert["id"], (models.ST_SILENCED,), target, self.now(),
                    {"silence_rule_id": None, "pre_silence_state": None}):
                    self.store.audit(models.AUDIT_ALERT_UNSILENCED, {
                        "alert_id": alert["id"], "restored_to": target,
                        "rule_id": rule_id, "rule_deleted": True, "by": by})
                    restored.append(alert["id"])
            self.store.delete_silence_rule_if_exists(rule_id)
            self.store.audit(models.AUDIT_SILENCE_RULE_DELETED, {
                "rule_id": rule_id, "restored_alerts": restored, "by": by})
            return {"deleted": True, "rule_id": rule_id, "restored_alerts": restored}

    # ------------------------------------------------------------------
    # 定时维护：静默到期 / 窗口清扫
    # ------------------------------------------------------------------

    def _sweep_silences_locked(self, conn, now: float) -> int:
        restored = 0
        candidates = (self.store.alerts_with_expired_silence(now)
                      + self.store.alerts_with_vanished_silence())
        seen: set[str] = set()
        for alert in candidates:
            if alert["id"] in seen:
                continue
            seen.add(alert["id"])
            target = alert["pre_silence_state"] or models.ST_FIRING
            if self.store.transition_alert(
                alert["id"], (models.ST_SILENCED,), target, now,
                {"silence_rule_id": None, "pre_silence_state": None}):
                self.store.audit(models.AUDIT_ALERT_UNSILENCED, {
                    "alert_id": alert["id"], "restored_to": target,
                    "reason": "SILENCE_EXPIRED", "swept": True})
                restored += 1
        return restored

    def sweep(self) -> dict[str, Any]:
        """主动收口：静默到期恢复（不依赖下一次请求）、去重窗口清扫。"""
        with self._lock, self.store.transaction() as conn:
            now = self.now()
            return {
                "silences_restored": self._sweep_silences_locked(conn, now),
                "windows_pruned": self.store.prune_windows(now),
            }

    # ------------------------------------------------------------------
    # 查询
    # ------------------------------------------------------------------

    def get_alert(self, alert_id: str, *, with_chains: bool = True) -> dict[str, Any] | None:
        alert = self.store.get_alert(alert_id)
        if alert is None:
            return None
        if with_chains:
            alert["chains"] = self.store.chains_for_alert(alert_id)
            alert["occurrences"] = self.store.occurrences_for_alert(alert_id)
        return alert

    def list_alerts(self, **params: Any) -> list[dict[str, Any]]:
        return self.store.list_alerts(**params)

    def list_chains(self, **params: Any) -> list[dict[str, Any]]:
        return self.store.list_chains(**params)

    def list_gaps(self, **params: Any) -> list[dict[str, Any]]:
        return self.store.list_gaps(**params)

    def list_audit(self, **params: Any) -> list[dict[str, Any]]:
        return self.store.list_audit(**params)

    def list_silence_rules(self, **params: Any) -> list[dict[str, Any]]:
        return self.store.list_silence_rules(**params)

    def watermarks(self) -> dict[str, Any]:
        tenants = {}
        for tenant in self.store.known_tenants():
            wm = self.store.contiguous_until(tenant)
            open_gaps = self.store.list_gaps(tenant=tenant)
            row = self.store.conn.execute(
                "SELECT COALESCE(MAX(seq),0) AS m, SUM(CASE WHEN applied=0 THEN 1 ELSE 0 END) AS p"
                " FROM events WHERE tenant=?",
                (tenant,),
            ).fetchone()
            tenants[tenant] = {
                "contiguous_until": wm,
                "max_seen_seq": int(row["m"]),
                "pending_events": int(row["p"] or 0),
                "watermark_contiguous": not open_gaps and wm == int(row["m"]),
                "open_gaps": open_gaps,
            }
        return {"tenants": tenants}

    def status(self) -> dict[str, Any]:
        alerts = self.store.list_alerts(limit=10_000)
        by_status: dict[str, int] = {}
        for a in alerts:
            by_status[a["status"]] = by_status.get(a["status"], 0) + 1
        wm = self.watermarks()
        now = self.now()
        return {
            "alerts": {"total": len(alerts), "by_status": by_status,
                       "active": sum(by_status.get(s, 0) for s in models.ACTIVE_STATES)},
            "chains": {"total": len(self.store.list_chains(limit=10_000))},
            "open_gaps": sum(len(v["open_gaps"]) for v in wm["tenants"].values()),
            "watermarks": wm,
            "active_silence_rules": len(self.store.list_silence_rules(active_only=True, now=now)),
            "server_time": now,
        }

    # ------------------------------------------------------------------
    # 通知出口
    # ------------------------------------------------------------------

    def _deliver(self, notification: dict[str, Any]) -> None:
        if self._notifier is None:
            return
        try:
            self._notifier(notification)
        except Exception:
            # 通知出口失败不能影响已提交的状态；审计轨迹已是事实来源
            pass
