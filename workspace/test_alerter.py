"""配额灾备异常告警路由器 —— 端到端测试。

覆盖：
- 完整事件链 + 连续水位双闸门（ISO/GAP/TAKEOVER）
- 链不完整不触发、缺口水位不触发、缺口补齐后补发/关闭
- 滑动窗口去重（锚定通知、抑制不滑动）
- 聚合（租户+类型一条活动告警，多链发生计数）
- 确认/恢复竞争（并发对撞只有一次转移、一条审计）
- 静默规则 / 单告警静默 / 到期 sweep / 删除恢复
- 服务重启恢复（持久化、状态保持、静默立即收口）
- 同事件幂等（event_id 重放、批量重放）
- 订阅器归一化（复制器审计/隔离 → 事件；确定性 event_id 游标）
- HTTP 端到端（真实线程服务器 + curl 语义）
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import time
import unittest
import urllib.request
from typing import Any

from alerter.models import (
    ISOLATION, TAKEOVER, GAP, AUDIT, BEGIN, END, WITNESS,
    ST_FIRING, ST_ACKED, ST_SILENCED, ST_RESOLVED, ST_CLOSED,
    CHAIN_OPEN, CHAIN_WITNESSED, CHAIN_CLOSED, CHAIN_BORN_CLOSED,
)
from alerter.store import AlertStore
from alerter.router import AlertRouter
from alerter.subscriber import Subscriber, _is_gap_reason, classify_kind, tenant_from_detail
from alerter.http_server import AlertServer, AlertHandler


# ----------------------------------------------------------------------
# 辅助
# ----------------------------------------------------------------------

class FakeClock:
    def __init__(self, t: float = 0.0):
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


def make_event(event_id: str, *, tenant: str = "t1", event_type: str = ISOLATION,
               role: str | None = BEGIN, chain_id: str = "c1", reason: str = "R",
               audit_ref: str | None = None, seq: int | None = None,
               payload: dict[str, Any] | None = None) -> dict[str, Any]:
    ev: dict[str, Any] = {
        "event_id": event_id,
        "tenant": tenant,
        "event_type": event_type,
        "chain_id": chain_id,
        "reason": reason,
    }
    if event_type == AUDIT:
        ev["role"] = WITNESS
        ev["audit_ref"] = audit_ref or f"ref-{event_id}"
    elif role is not None:
        ev["role"] = role
    if seq is not None:
        ev["seq"] = seq
    if payload is not None:
        ev["payload"] = payload
    return ev


def build_router(path: str = ":memory:", window: int = 300, clock=None,
                 capture: list | None = None) -> tuple[AlertRouter, AlertStore]:
    store = AlertStore(path)
    router = AlertRouter(store, default_window_seconds=window, clock=clock)
    if capture is not None:
        router._notifier = lambda n: capture.append(n)
    router.start()
    return router, store


def complete_isolation(router: AlertRouter, chain: str = "c1", reason: str = "R",
                       tenant: str = "t1", prefix: str = "e") -> dict[str, Any]:
    """发送 BEGIN + WITNESS 完整隔离链，返回触发的告警。"""
    router.ingest_event(make_event(f"{prefix}-b", tenant=tenant, chain_id=chain, reason=reason))
    router.ingest_event(make_event(f"{prefix}-w", tenant=tenant, event_type=AUDIT,
                                   chain_id=chain, reason=reason))
    return router.list_alerts(tenant=tenant, alert_type=ISOLATION)[0]


class RouterTestCase(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.notifications: list[dict[str, Any]] = []
        self.router, self.store = build_router(
            window=100, clock=self.clock, capture=self.notifications)

    def alert(self, alert_id: str) -> dict[str, Any]:
        a = self.router.get_alert(alert_id)
        assert a is not None
        return a

    # ------------------------------------------------------------------
    # 双闸门：完整链 + 连续水位
    # ------------------------------------------------------------------

    def test_incomplete_chain_does_not_fire(self):
        # 只有 BEGIN：链不完整，不触发
        self.router.ingest_event(make_event("b", chain_id="c1"))
        self.assertEqual(self.router.list_alerts(), [])
        # 只有 WITNESS：链连类型都没有，也不触发
        self.router.ingest_event(make_event("w", event_type=AUDIT, chain_id="c2"))
        self.assertEqual(self.router.list_alerts(), [])
        c1 = {c["chain_id"]: c for c in self.router.list_chains()}["c1"]
        self.assertEqual(c1["status"], CHAIN_OPEN)
        self.assertEqual(self.notifications, [])

    def test_complete_isolation_chain_fires(self):
        alert = complete_isolation(self.router)
        self.assertEqual(alert["status"], ST_FIRING)
        self.assertEqual(alert["occurrence_count"], 1)
        self.assertEqual(len(self.notifications), 1)
        kinds = [e["kind"] for e in self.router.list_audit(limit=100)]
        self.assertIn("alert_fired", kinds)
        self.assertIn("chain_complete", kinds)

    def test_takeover_requires_end(self):
        # TAKEOVER 规则需要 BEGIN + END + WITNESS：只有 BEGIN+WITNESS 不触发
        self.router.ingest_event(make_event("b", event_type=TAKEOVER,
                                            role=BEGIN, reason="OWNERSHIP_LOST"))
        self.router.ingest_event(make_event("w", event_type=AUDIT,
                                            reason="OWNERSHIP_LOST"))
        self.assertEqual(self.router.list_alerts(), [])
        # END 到达后完整：通知一次，同事务自动恢复（接管生命周期已闭合）
        self.router.ingest_event(make_event("e", event_type=TAKEOVER,
                                            role=END, reason="TAKEOVER_COMPLETE"))
        alerts = self.router.list_alerts(alert_type=TAKEOVER)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["status"], ST_RESOLVED)
        self.assertEqual(alerts[0]["resolved_reason"], "AUTO_RESOLVED_ON_CHAIN_END")
        self.assertEqual(len(self.notifications), 1)
        # 触发与恢复都有审计
        kinds = [e["kind"] for e in self.router.list_audit(limit=100)]
        self.assertEqual(kinds.count("alert_fired"), 1)
        self.assertEqual(kinds.count("alert_resolved"), 1)

    def test_watermark_gap_blocks_then_fills_and_fires(self):
        # seq1 BEGIN；seq3 先到（缺 seq2）—— seq3 必须停在水位之后，不触发
        self.router.ingest_event(make_event("a", seq=1, chain_id="c1"))
        self.router.ingest_event(make_event("c", event_type=AUDIT, seq=3,
                                            chain_id="c1", reason="R"))
        wm = self.router.watermarks()["tenants"]["t1"]
        self.assertEqual(wm["contiguous_until"], 1)
        self.assertFalse(wm["watermark_contiguous"])
        self.assertEqual(self.router.list_alerts(alert_type=ISOLATION), [])
        open_gaps = self.router.list_gaps()
        self.assertEqual([g["gap_from"] for g in open_gaps], [2])

        # 补齐 seq2（WITNESS）：连续水位推进到 3，链完整 → 触发
        self.router.ingest_event(make_event("b", event_type=AUDIT, seq=2,
                                            chain_id="c1", reason="R"))
        wm = self.router.watermarks()["tenants"]["t1"]
        self.assertEqual(wm["contiguous_until"], 3)
        self.assertTrue(wm["watermark_contiguous"])
        alert = self.router.list_alerts(alert_type=ISOLATION)[0]
        self.assertEqual(alert["status"], ST_FIRING)
        filled = {g["gap_from"]: g for g in self.router.list_gaps(include_filled=True)}
        self.assertIn(2, filled)
        self.assertIsNotNone(filled[2]["filled_at"])
        self.assertEqual(self.router.list_gaps(), [])
        kinds = [e["kind"] for e in self.router.list_audit(limit=100)]
        self.assertIn("watermark_gap_detected", kinds)
        self.assertIn("watermark_gap_filled", kinds)

    def test_watermark_gap_audit_only_once(self):
        # 多次有新事件但缺口不变，不应重复审计 gap_detected
        self.router.ingest_event(make_event("a", seq=1))
        self.router.ingest_event(make_event("b", event_type=AUDIT, seq=3, chain_id="x"))
        self.router.ingest_event(make_event("c", event_type=AUDIT, seq=4, chain_id="y"))
        kinds = [e["kind"] for e in self.router.list_audit(limit=100)]
        self.assertEqual(kinds.count("watermark_gap_detected"), 1)

    def test_born_closed_when_end_precedes_witness_behind_gap(self):
        # ISOLATION：BEGIN(1)、END(2) 连续到达但链不完整（缺 WITNESS）；
        # WITNESS(3) 补齐时链已 CLOSED → BORN_CLOSED，不补发
        self.router.ingest_event(make_event("b", seq=1, role=BEGIN))
        self.router.ingest_event(make_event("e", seq=2, role=END))
        self.assertEqual(self.router.list_alerts(), [])
        self.router.ingest_event(make_event("w", event_type=AUDIT, seq=3))
        self.assertEqual(self.router.list_alerts(), [])
        chain = {c["chain_id"]: c for c in self.router.list_chains()}["c1"]
        self.assertEqual(chain["status"], CHAIN_BORN_CLOSED)
        kinds = [e["kind"] for e in self.router.list_audit(limit=100)]
        self.assertIn("chain_born_closed", kinds)
        self.assertEqual(kinds.count("alert_fired"), 0)
        # 之后再来 BEGIN 也不复活
        self.router.ingest_event(make_event("b2", role=BEGIN, chain_id="c1"))
        self.assertEqual(self.router.list_alerts(), [])

    def test_late_end_resolves_existing_fired_alert(self):
        # BEGIN+WITNESS 先触发 FIRING，END 后到 → 自动恢复
        alert = complete_isolation(self.router)
        self.router.ingest_event(make_event("e", role=END))
        self.assertEqual(self.alert(alert["id"])["status"], ST_RESOLVED)

    # ------------------------------------------------------------------
    # 聚合 + 滑动窗口去重
    # ------------------------------------------------------------------

    def test_aggregation_one_active_alert_per_tenant_type(self):
        a1 = complete_isolation(self.router, chain="c1", prefix="1")
        a2 = complete_isolation(self.router, chain="c2", prefix="2")
        self.assertEqual(a1["id"], a2["id"])
        alert = self.alert(a1["id"])
        self.assertEqual(alert["occurrence_count"], 2)
        self.assertEqual(len(alert["chains"]), 2)
        # 另一租户独立告警
        other = complete_isolation(self.router, chain="c3", tenant="t2", prefix="3")
        self.assertNotEqual(other["id"], a1["id"])

    def test_sliding_window_dedup_suppresses_notification(self):
        a1 = complete_isolation(self.router, chain="c1", reason="DUP", prefix="1")
        a2 = complete_isolation(self.router, chain="c2", reason="DUP", prefix="2")
        self.assertEqual(a1["id"], a2["id"])
        self.assertEqual(len(self.notifications), 1)  # 第二次被窗口抑制
        occ = self.store.occurrences_for_alert(a1["id"])
        self.assertEqual([o["notified"] for o in occ], [1, 0])
        kinds = [e["kind"] for e in self.router.list_audit(limit=100)]
        ded = [e for e in self.router.list_audit(limit=100) if e["kind"] == "alert_deduped"]
        self.assertEqual(len(ded), 1)
        self.assertEqual(ded[0]["detail"]["suppressed_by"], "dedup_window")

    def test_window_does_not_slide_on_suppressed_occurrence(self):
        # 窗口 100s：t=0 通知；t=50 抑制（窗口不滑动，仍在 t=100 过期）；
        # t=101 的新链发生必须再次通知（若窗口被抑制事件滑动到 50 起算，
        # 此时本应仍被抑制——本用例同时锁死“抑制不滑动”的语义）。
        a1 = complete_isolation(self.router, chain="c1", reason="D", prefix="1")
        self.assertEqual(len(self.notifications), 1)
        self.clock.advance(50)
        complete_isolation(self.router, chain="c2", reason="D", prefix="2")
        self.assertEqual(len(self.notifications), 1)
        self.clock.advance(51)  # t=101：锚点 0 的窗口刚过期
        a3 = complete_isolation(self.router, chain="c3", reason="D", prefix="3")
        self.assertEqual(len(self.notifications), 2)
        # 旧活动告警已聚合 3 次；第二次通知重新锚定窗口
        self.assertEqual(a3["occurrence_count"], 3)

    def test_different_fingerprints_are_not_deduped(self):
        complete_isolation(self.router, chain="c1", reason="AAA", prefix="1")
        complete_isolation(self.router, chain="c2", reason="BBB", prefix="2")
        self.assertEqual(len(self.notifications), 2)

    # ------------------------------------------------------------------
    # 确认 / 静默 / 恢复
    # ------------------------------------------------------------------

    def test_ack_lifecycle(self):
        alert = complete_isolation(self.router)
        acked = self.router.ack_alert(alert["id"], by="u1", note="看一下")
        self.assertEqual(acked["status"], ST_ACKED)
        # 重复确认幂等
        self.assertEqual(self.router.ack_alert(alert["id"])["status"], ST_ACKED)
        # 取消确认
        self.assertEqual(self.router.unack_alert(alert["id"])["status"], ST_FIRING)
        kinds = [e["kind"] for e in self.router.list_audit(limit=100)]
        self.assertEqual(kinds.count("alert_acked"), 1)
        self.assertIn("alert_unacked", kinds)

    def test_ack_on_silenced_rejected(self):
        from alerter.models import AlertError
        alert = complete_isolation(self.router)
        self.router.silence_alert(alert["id"], ttl_seconds=60)
        with self.assertRaises(AlertError) as cm:
            self.router.ack_alert(alert["id"])
        self.assertEqual(cm.exception.reason, "ALERT_SILENCED")

    def test_silence_alert_with_ttl_and_sweep(self):
        alert = complete_isolation(self.router)
        silenced = self.router.silence_alert(alert["id"], ttl_seconds=60, by="u")
        self.assertEqual(silenced["status"], ST_SILENCED)
        self.assertEqual(silenced["pre_silence_state"], ST_FIRING)
        # 静默期内新发生被静默抑制
        complete_isolation(self.router, chain="c2", prefix="2")
        self.assertEqual(len(self.notifications), 1)
        # 未到期 sweep 不恢复
        self.clock.advance(30)
        self.assertEqual(self.router.sweep()["silences_restored"], 0)
        # 到期 sweep：主动恢复（不依赖请求）
        self.clock.advance(40)
        self.assertEqual(self.router.sweep()["silences_restored"], 1)
        self.assertEqual(self.alert(alert["id"])["status"], ST_FIRING)

    def test_silence_rule_matches_at_fire_time(self):
        rule = self.router.create_silence_rule(
            "t1", ISOLATION, "PLANNED", ttl_seconds=120, note="维护")
        alert = complete_isolation(self.router, reason="PLANNED")
        self.assertEqual(alert["status"], ST_SILENCED)
        self.assertEqual(alert["silence_rule_id"], rule["id"])
        self.assertEqual(self.notifications, [])
        # 不匹配原因码的不通知：按“租户+类型唯一活动告警”聚合进同一条
        # 静默告警（仅记录发生、审计 deduped），不另开 FIRING
        before = self.router.list_alerts(tenant="t1", status=ST_SILENCED)[0]
        complete_isolation(self.router, chain="c9", reason="OTHER", prefix="9")
        silenced = self.router.list_alerts(tenant="t1", status=ST_SILENCED)
        self.assertEqual(len(silenced), 1)
        self.assertEqual(silenced[0]["id"], before["id"])
        self.assertEqual(silenced[0]["occurrence_count"], 2)
        self.assertEqual(len(self.notifications), 0)

    def test_silence_rule_delete_restores_alerts(self):
        rule = self.router.create_silence_rule(
            "t1", ISOLATION, "R", ttl_seconds=120, silence_existing=False)
        alert = complete_isolation(self.router)
        self.assertEqual(alert["status"], ST_SILENCED)
        result = self.router.delete_silence_rule(rule["id"])
        self.assertEqual(result["restored_alerts"], [alert["id"]])
        self.assertEqual(self.alert(alert["id"])["status"], ST_FIRING)

    def test_manual_resolve_is_terminal_and_idempotent(self):
        alert = complete_isolation(self.router)
        closed = self.router.close_alert(alert["id"], note="已处置")
        self.assertEqual(closed["status"], ST_CLOSED)
        # 终态上再次关闭/确认不产生新状态
        again = self.router.close_alert(alert["id"])
        self.assertEqual(again["status"], ST_CLOSED)
        self.assertEqual(
            self.router.list_alerts(status=ST_CLOSED)[0]["resolved_reason"],
            "MANUAL_CLOSE")

    def test_auto_resolve_does_not_fire_while_chains_still_open(self):
        # 一条告警聚合两条链；只关闭一条时不恢复，两条都关闭才恢复
        a1 = complete_isolation(self.router, chain="c1", prefix="1")
        complete_isolation(self.router, chain="c2", prefix="2")
        self.router.ingest_event(make_event("e1", role=END, chain_id="c1"))
        self.assertEqual(self.alert(a1["id"])["status"], ST_FIRING)
        self.router.ingest_event(make_event("e2", role=END, chain_id="c2"))
        self.assertEqual(self.alert(a1["id"])["status"], ST_RESOLVED)

    def test_auto_resolve_overrides_ack_when_all_closed(self):
        alert = complete_isolation(self.router)
        self.router.ack_alert(alert["id"])
        self.router.ingest_event(make_event("e", role=END))
        self.assertEqual(self.alert(alert["id"])["status"], ST_RESOLVED)

    def test_ack_and_resolve_race_single_transition(self):
        # 屏障让两个事务在同一刻对撞：ack 赢则 ACKED，close 赢则 CLOSED，
        # 但全局只能落一次“从 FIRING 出发”的转移、一条对应审计。
        alert = complete_isolation(self.router)
        barrier = threading.Barrier(2)
        outcomes: list[tuple[str, str]] = []

        def ack():
            barrier.wait()
            outcomes.append(("ack", self.router.ack_alert(alert["id"])["status"]))

        def close():
            barrier.wait()
            outcomes.append(("close", self.router.close_alert(alert["id"])["status"]))

        t1 = threading.Thread(target=ack)
        t2 = threading.Thread(target=close)
        t1.start(); t2.start(); t1.join(); t2.join()

        statuses = {s for _, s in outcomes}
        final = self.alert(alert["id"])["status"]
        # 输家看到的是终态/赢家状态：两个结果状态一致（都是权威终态视图）
        self.assertEqual(statuses, {final})
        self.assertIn(final, (ST_ACKED, ST_CLOSED))
        kinds = [e["kind"] for e in self.router.list_audit(limit=100)]
        if final == ST_CLOSED:
            self.assertEqual(kinds.count("alert_closed"), 1)
            self.assertNotIn("alert_acked", kinds)
        else:
            self.assertEqual(kinds.count("alert_acked"), 1)
            self.assertNotIn("alert_closed", kinds)

    def test_two_chain_end_concurrent_resolves_once(self):
        # 两条链的 END 并发到达：只能自动恢复一次、一条 resolved 审计
        a1 = complete_isolation(self.router, chain="c1", prefix="1")
        complete_isolation(self.router, chain="c2", prefix="2")
        barrier = threading.Barrier(2)

        def end_c1():
            barrier.wait()
            self.router.ingest_event(make_event("e1", role=END, chain_id="c1"))

        def end_c2():
            barrier.wait()
            self.router.ingest_event(make_event("e2", role=END, chain_id="c2"))

        t1 = threading.Thread(target=end_c1)
        t2 = threading.Thread(target=end_c2)
        t1.start(); t2.start(); t1.join(); t2.join()
        self.assertEqual(self.alert(a1["id"])["status"], ST_RESOLVED)
        kinds = [e["kind"] for e in self.router.list_audit(limit=100)]
        self.assertEqual(kinds.count("alert_resolved"), 1)

    # ------------------------------------------------------------------
    # 幂等
    # ------------------------------------------------------------------

    def test_same_event_id_is_idempotent(self):
        ev = make_event("same", chain_id="c1")
        r1 = self.router.ingest_event(ev)
        r2 = self.router.ingest_event(ev)
        self.assertFalse(r1["duplicate"])
        self.assertTrue(r2["duplicate"])
        self.assertEqual(r1["seq"], r2["seq"])
        # 已应用事件重放不重复
        witness = make_event("same-w", event_type=AUDIT, chain_id="c1")
        self.router.ingest_event(witness)
        self.router.ingest_event(dict(witness))
        self.assertEqual(len(self.router.list_alerts()), 1)
        self.assertEqual(self.router.list_alerts()[0]["occurrence_count"], 1)
        kinds = [e["kind"] for e in self.router.list_audit(limit=100)]
        self.assertEqual(kinds.count("event_received"), 2)  # 重复不再写登记审计

    def test_batch_idempotent_replay(self):
        events = [make_event("b1", chain_id="c1"),
                  make_event("w1", event_type=AUDIT, chain_id="c1")]
        r1 = self.router.ingest_batch(events)
        r2 = self.router.ingest_batch(events)
        self.assertTrue(all(not x["duplicate"] for x in r1))
        self.assertTrue(all(x["duplicate"] for x in r2))
        self.assertEqual(len(self.router.list_alerts()), 1)

    # ------------------------------------------------------------------
    # 重启恢复
    # ------------------------------------------------------------------

    def test_restart_preserves_state_and_recovers_expired_silence(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.addCleanup(os.unlink, path)
        try:
            store = AlertStore(path)
            router = AlertRouter(store, default_window_seconds=300,
                                 clock=FakeClock(1000.0))
            router.start()
            alert = complete_isolation(router, prefix="p")
            router.silence_alert(alert["id"], ttl_seconds=60)
            # 停机前已用自动序号 1(BEGIN)、2(WITNESS)；显式 seq4 跨过缺口 seq3
            router.ingest_event(make_event("gap4", seq=4, chain_id="late"))
            store.close()

            # 新进程从存储重建：静默已在停机期间到期 → 立即恢复
            store2 = AlertStore(path)
            clock2 = FakeClock(1100.0)
            router2 = AlertRouter(store2, default_window_seconds=300, clock=clock2)
            stats = router2.recover_on_startup()
            self.assertEqual(stats["silences_restored"], 1)
            self.assertEqual(router2.get_alert(alert["id"])["status"], ST_FIRING)
            wm = router2.watermarks()["tenants"]["t1"]
            self.assertEqual(wm["contiguous_until"], 2)
            self.assertFalse(wm["watermark_contiguous"])
            # 补齐显式缺口 seq3（与 late 无关的见证）：水位推进到 4，late 放行
            router2.ingest_event(make_event("fill3", event_type=AUDIT,
                                            seq=3, chain_id="x3", reason="R"))
            self.assertEqual(
                router2.watermarks()["tenants"]["t1"]["contiguous_until"], 4)
            store2.close()
        finally:
            pass

    def test_restart_does_not_refire_or_lose_alert(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.addCleanup(os.unlink, path)
        store = AlertStore(path)
        router = AlertRouter(store, clock=FakeClock(10.0))
        router.start()
        alert = complete_isolation(router, prefix="z")
        store.close()

        store2 = AlertStore(path)
        captured: list = []
        router2 = AlertRouter(store2, clock=FakeClock(20.0))
        router2._notifier = lambda n: captured.append(n)
        router2.start()
        self.assertEqual(router2.get_alert(alert["id"])["status"], ST_FIRING)
        self.assertEqual(captured, [])  # 重启不重发通知
        store2.close()

    # ------------------------------------------------------------------
    # 输入校验
    # ------------------------------------------------------------------

    def test_invalid_events_rejected(self):
        from alerter.models import AlertError
        with self.assertRaises(AlertError):
            self.router.ingest_event({"event_id": "x"})  # 缺 tenant
        with self.assertRaises(AlertError):
            self.router.ingest_event({"event_id": "x", "tenant": "t",
                                      "event_type": "BOGUS", "chain_id": "c"})
        with self.assertRaises(AlertError):
            self.router.ingest_event({"event_id": "x", "tenant": "t",
                                      "event_type": AUDIT, "chain_id": "c"})  # 缺 ref

    def test_explicit_seq_conflict_rejected(self):
        from alerter.models import AlertError
        self.router.ingest_event(make_event("a", seq=1))
        with self.assertRaises(AlertError):
            self.router.ingest_event(make_event("b", seq=1, chain_id="other"))

    # ------------------------------------------------------------------
    # 状态机非法转移
    # ------------------------------------------------------------------

    def test_invalid_transitions(self):
        from alerter.models import AlertError
        alert = complete_isolation(self.router)
        self.router.close_alert(alert["id"])
        with self.assertRaises(AlertError):
            self.router.silence_alert(alert["id"])
        with self.assertRaises(AlertError):
            self.router.unack_alert(alert["id"])


# ----------------------------------------------------------------------
# 订阅器归一化
# ----------------------------------------------------------------------

class SubscriberTestCase(unittest.TestCase):
    def test_reason_classification(self):
        self.assertTrue(_is_gap_reason("SEGMENT_INDEX_MISMATCH"))
        self.assertTrue(_is_gap_reason("LAG_OVER_LIMIT"))
        self.assertFalse(_is_gap_reason("ENVELOPE_DIGEST_MISMATCH"))
        self.assertEqual(classify_kind("segment_quarantined",
                                       {"reason": "SEGMENT_INDEX_MISMATCH"}), GAP)
        self.assertEqual(classify_kind("segment_quarantined",
                                       {"reason": "BODY_CONFLICT"}), ISOLATION)
        self.assertEqual(classify_kind("ownership_lost", {}), TAKEOVER)
        self.assertIsNone(classify_kind("segment_confirmed", {}))
        self.assertEqual(tenant_from_detail({"tenant": "acct-7"}), "acct-7")
        self.assertEqual(tenant_from_detail({}), "platform")

    def test_poll_translates_replica_facts(self):
        router, store = build_router()
        audit_db = [
            {"id": 1, "at": 100.0, "kind": "segment_confirmed",
             "detail": {"segment_index": 1}},
            {"id": 2, "at": 101.0, "kind": "segment_quarantined",
             "detail": {"quarantine_id": 11, "reason": "BODY_CONFLICT",
                        "segment_index": 2, "tenant": "t1"}},
            {"id": 3, "at": 102.0, "kind": "ownership_lost",
             "detail": {"lost_epoch": 5, "current_epoch": 6}},
        ]
        quarantine = [
            {"id": 11, "reason": "BODY_CONFLICT", "segment_index": 2,
             "resolved_at": None},
        ]

        def fetcher(path: str):
            if path.startswith("/ops/audit-tail"):
                return {"entries": list(audit_db)}
            return {"quarantine": list(quarantine)}

        sub = Subscriber(router, "http://replica", fetcher=fetcher)
        result = sub.poll_once()
        self.assertEqual(result["new_audit_entries"], 3)
        # BODY_CONFLICT 隔离：BEGIN+WITNESS 完整 → ISOLATION FIRING；
        # ownership_lost 只有 BEGIN+WITNESS（TAKEOVER 还缺 END）→ 不触发
        alerts = router.list_alerts()
        self.assertEqual([(a["alert_type"], a["status"]) for a in alerts],
                         [(ISOLATION, ST_FIRING)])
        chains = {c["chain_id"]: c for c in router.list_chains()}
        self.assertIn("quarantine:11", chains)
        self.assertIn("takeover:epoch-5", chains)
        self.assertEqual(chains["takeover:epoch-5"]["status"], CHAIN_OPEN)

        # 第二轮：复制器重启（replicator_started epoch 6）→ 接管链 END 补齐；
        # 隔离记录 resolved → ISO 链自动恢复；全部确定性 event_id 幂等
        audit_db.append({"id": 4, "at": 103.0, "kind": "replicator_started",
                         "detail": {"epoch": 6}})
        quarantine[0]["resolved_at"] = 104.0
        quarantine[0]["resolution"] = "健康分段已确认"
        result2 = sub.poll_once()
        self.assertEqual(result2["new_audit_entries"], 1)
        statuses = {a["alert_type"]: a["status"] for a in router.list_alerts()}
        self.assertEqual(statuses[ISOLATION], ST_RESOLVED)
        self.assertEqual(statuses[TAKEOVER], ST_RESOLVED)

        # 第三轮：无新审计，不产生任何事件（游标 + 确定性 id 幂等）
        result3 = sub.poll_once()
        self.assertEqual(result3["events_sent"], 0)

    def test_subscriber_cursor_persists_across_restart(self):
        router, store = build_router()
        audit_db = [{"id": 7, "at": 1.0, "kind": "ownership_lost",
                     "detail": {"lost_epoch": 1, "current_epoch": 2}}]

        def fetcher(path):
            return {"entries": list(audit_db)} if "audit-tail" in path else {"quarantine": []}

        sub = Subscriber(router, "http://r", fetcher=fetcher)
        sub.poll_once()
        self.assertEqual(int(store.get_meta("subscriber:audit_cursor")), 7)
        # 新订阅器实例读同一存储：游标恢复，旧审计不再消费
        sub2 = Subscriber(router, "http://r", fetcher=fetcher)
        self.assertEqual(sub2.cursor, 7)
        self.assertEqual(sub2.poll_once()["new_audit_entries"], 0)


# ----------------------------------------------------------------------
# HTTP 端到端
# ----------------------------------------------------------------------

class HttpTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.router, cls.store = build_router()
        cls.server = AlertServer(("127.0.0.1", 0), AlertHandler, cls.router)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _req(self, method: str, path: str, body=None):
        url = f"http://127.0.0.1:{self.port}{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode())

    def test_full_lifecycle_over_http(self):
        # 发送完整隔离链
        s1, _ = self._req("POST", "/api/events",
                          make_event("h-b", tenant="http-t", chain_id="hc"))
        self.assertEqual(s1, 202)
        s2, r2 = self._req("POST", "/api/events",
                           make_event("h-w", tenant="http-t", event_type=AUDIT, chain_id="hc"))
        self.assertEqual(s2, 202)
        # 同事件重放
        s2b, r2b = self._req("POST", "/api/events",
                             make_event("h-w", tenant="http-t", event_type=AUDIT, chain_id="hc"))
        self.assertTrue(r2b["duplicate"])

        s3, lst = self._req("GET", "/api/alerts?tenant=http-t&status=FIRING")
        self.assertEqual(s3, 200)
        self.assertEqual(len(lst["alerts"]), 1)
        aid = lst["alerts"][0]["id"]

        s4, detail = self._req("GET", f"/api/alerts/{aid}")
        self.assertEqual(s4, 200)
        self.assertEqual(len(detail["chains"]), 1)
        self.assertEqual(len(detail["occurrences"]), 1)

        self.assertEqual(self._req("POST", f"/api/alerts/{aid}/ack", {"by": "curl"})[0], 200)
        self.assertEqual(self._req("POST", f"/api/alerts/{aid}/silence",
                                   {"ttl_seconds": 60})[1]["status"], ST_SILENCED)
        self.assertEqual(self._req("POST", f"/api/alerts/{aid}/unsilence",
                                   {"delete_rule": True})[1]["status"], ST_ACKED)
        s5, resolved = self._req("POST", f"/api/alerts/{aid}/resolve", {"note": "done"})
        self.assertEqual(s5, 200)
        self.assertEqual(resolved["status"], ST_CLOSED)

        # 审计轨迹记录了每一次转移
        _, audit = self._req("GET", "/api/audit?limit=100")
        kinds = {e["kind"] for e in audit["entries"]}
        for required in ("alert_fired", "alert_acked", "alert_silenced",
                         "alert_unsilenced", "alert_closed"):
            self.assertIn(required, kinds)

        # 水位/缺口/页面
        self.assertEqual(self._req("GET", "/api/watermarks")[0], 200)
        self.assertEqual(self._req("GET", "/ops/status")[0], 200)
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/", timeout=5) as resp:
            page = resp.read().decode()
        self.assertIn("告警路由器", page)

    def test_silence_rule_over_http(self):
        code, rule = self._req("POST", "/api/silences", {
            "tenant": "sil-t", "alert_type": GAP, "ttl_seconds": 30,
            "reason": "SEGMENT_INDEX_MISMATCH", "note": "n", "silence_existing": True})
        self.assertEqual(code, 201)
        _, lst = self._req("GET", "/api/silences?tenant=sil-t")
        self.assertTrue(any(r["id"] == rule["id"] for r in lst["rules"]))
        code, deleted = self._req("DELETE", f"/api/silences/{rule['id']}")
        self.assertEqual(code, 200)
        self.assertEqual(deleted["deleted"], True)

    def test_batch_and_errors(self):
        events = [make_event("b-b", tenant="batch", chain_id="bc1"),
                  make_event("b-w", tenant="batch", event_type=AUDIT, chain_id="bc1")]
        code, body = self._req("POST", "/api/events/batch", {"events": events})
        self.assertEqual(code, 202)
        self.assertEqual(len(body["results"]), 2)
        code, err = self._req("POST", "/api/events", {"event_id": "bad"})
        self.assertEqual(code, 400)
        self.assertEqual(err["error"], "BAD_EVENT")
        code, err = self._req("GET", "/api/alerts/NOPE")
        self.assertEqual(code, 404)


if __name__ == "__main__":
    unittest.main(verbosity=2)
