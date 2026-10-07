"""告警路由器端到端测试（真实 SQLite，临时文件）。

覆盖：
  1. 连续水位正常触发 + 完整链恢复
  2. 水位缺口挂起 → 补齐后补发（backfilled）
  3. 缺口期间链已完整（OPEN+RESOLVE 同批补齐）→ 静默关闭，不发告警
  4. 滑动窗口去重 + 窗口过后重新通知
  5. 确认/恢复 CAS 竞争（并发线程，输赢确定、审计完整）
  6. journal 重放的服务重启恢复（告警/水位/挂起/静默/审计全等价）
  7. 同事件幂等（event_id 重投不二次折叠）
  8. 静默规则（全局/租户+类型、到期自动解除、撤销）
  9. RECOVERED TTL 自动关闭（确定性时钟）
 10. 乱序：RESOLVE 先到、OPEN 后补齐
 11. 每状态转移恰好一条审计
"""

from __future__ import annotations

import os
import tempfile
import threading
import unittest
from datetime import timedelta

from qrouter.engine import AlertRouter
from qrouter.models import (
    AUDIT, GAP, QUARANTINE, TAKEOVER,
    PHASE_OPEN, PHASE_RESOLVE, OPEN, ACKED, RECOVERED, SILENCED, CLOSED,
    RouterError, to_ts,
)
from qrouter.store import Store


def _iso(offset_seconds: float = 0.0) -> str:
    from datetime import datetime, timezone
    base = datetime(2026, 10, 7, 12, 0, 0, tzinfo=timezone.utc) \
        + timedelta(seconds=offset_seconds)
    return to_ts(base)


def ev(event_id, tenant, etype, phase, chain, seq, at=None, **payload):
    return {"event_id": event_id, "tenant": tenant, "type": etype,
            "phase": phase, "chain_id": chain, "seq": seq,
            "occurred_at": at or _iso(seq * 10), "payload": payload}


class RouterTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        # 可推进的假墙钟：ingested_at/命令时间/tick 判定都走它
        self.now = [_iso(10000.0)]
        self.clock = lambda: self.now[0]
        self.store = Store(self.tmp.name)
        self.router = AlertRouter(self.store, recovered_ttl_seconds=3600,
                                  clock=self.clock)

    def advance(self, seconds: float):
        from qrouter.models import parse_ts, to_ts
        from datetime import timedelta
        self.now[0] = to_ts(parse_ts(self.now[0]) + timedelta(seconds=seconds))

    def tearDown(self):
        self.store.close()
        os.unlink(self.tmp.name)
        for ext in ("-wal", "-shm"):
            p = self.tmp.name + ext
            if os.path.exists(p):
                os.unlink(p)

    def reopen(self, ttl: float = 3600) -> AlertRouter:
        """模拟服务重启：同一 DB 文件，新建 Router（全量重放 journal）。"""
        self.store.close()
        self.store = Store(self.tmp.name)
        self.router = AlertRouter(self.store, recovered_ttl_seconds=ttl,
                                  clock=self.clock)
        return self.router

    def audit_kinds(self, alert_id=None):
        rows = self.store.list_audit(limit=1000, alert_id=alert_id,
                                     ascending=True)
        return [r["kind"] for r in rows]


class TestBasicChain(RouterTestBase):
    def test_contiguous_open_resolve_fires_and_recovers(self):
        r1 = self.router.ingest_event(
            ev("e1", "t1", QUARANTINE, PHASE_OPEN, "seg-1", 1,
               reason="EVENT_HASH_BROKEN"))
        self.assertFalse(r1["held"])
        aid = r1["alerts"][0]["alert_id"]
        self.assertEqual(r1["alerts"][0]["status"], OPEN)

        detail = self.router.get_alert_detail(aid)
        self.assertEqual(len(detail["events"]), 1)
        self.assertEqual([n["kind"] for n in detail["notifications"]], ["fired"])

        r2 = self.router.ingest_event(
            ev("e2", "t1", QUARANTINE, PHASE_RESOLVE, "seg-1", 2))
        self.assertEqual(r2["alerts"][0]["status"], RECOVERED)
        kinds = self.audit_kinds(aid)
        self.assertEqual(kinds, ["alert_fired", "alert_recovered"])

    def test_type_phase_validation(self):
        bad = {"event_id": "x", "tenant": "t", "type": "NOPE",
               "phase": PHASE_OPEN, "chain_id": "c", "seq": 1,
               "occurred_at": _iso()}
        with self.assertRaises(RouterError) as cx:
            self.router.ingest_event(bad)
        self.assertEqual(cx.exception.status, 422)

        bad2 = ev("y", "t", QUARANTINE, "BOGUS", "c", 1)
        with self.assertRaises(RouterError):
            self.router.ingest_event(bad2)

    def test_chain_type_conflict(self):
        self.router.ingest_event(ev("a", "t", GAP, PHASE_OPEN, "c", 1))
        with self.assertRaises(RouterError) as cx:
            self.router.ingest_event(ev("b", "t", AUDIT, PHASE_OPEN, "c", 2))
        self.assertEqual(cx.exception.reason, "CHAIN_TYPE_CONFLICT")


class TestWatermark(RouterTestBase):
    def test_gap_holds_then_backfills(self):
        # 直接来 seq 3：1,2 缺失，挂起，不触发
        r = self.router.ingest_event(
            ev("late", "t", QUARANTINE, PHASE_OPEN, "seg-9", 3))
        self.assertTrue(r["held"])
        self.assertEqual(r["alerts"], [])
        self.assertEqual(self.router.list_alerts(), [])
        # 缺口审计 + 挂起审计已记录
        kinds = self.audit_kinds()
        self.assertIn("stream_gap", kinds)
        self.assertIn("chain_held", kinds)

        # 补齐 seq 1：释放 1（新链 seg-8 触发），仍在等 2
        r1 = self.router.ingest_event(
            ev("s1", "t", GAP, PHASE_OPEN, "seg-8", 1))
        self.assertEqual(r1["watermark"], 1)
        self.assertEqual(len(r1["alerts"]), 1)

        # 补齐 seq 2：级联释放 seq 3（seg-9）→ 补发告警，标 backfilled
        r2 = self.router.ingest_event(
            ev("s2", "t", AUDIT, PHASE_OPEN, "run-1", 2))
        self.assertEqual(r2["watermark"], 3)
        backfilled = [a for a in r2["alerts"] if a["chain_id"] == "seg-9"]
        self.assertEqual(len(backfilled), 1)
        self.assertEqual(backfilled[0]["status"], OPEN)
        self.assertEqual(backfilled[0]["backfilled"], 1)

        pending = self.router.pending_view()
        self.assertEqual(pending["tenants"], [])  # 全部释放
        wm = {w["tenant"]: w for w in self.router.watermarks()}
        self.assertEqual(wm["t"]["next_seq"], 4)
        self.assertEqual(wm["t"]["held_count"], 0)

    def test_open_and_resolve_in_same_fill_batch_silent_close(self):
        # seq3(RESOLVE of c), seq4(OPEN of c2) 先到挂起
        self.router.ingest_event(ev("r", "t", GAP, PHASE_RESOLVE, "c", 3))
        self.router.ingest_event(ev("o4", "t", AUDIT, PHASE_OPEN, "c2", 4))
        # 补齐 1(OPEN c) 2(RESOLVE c)：c 的 OPEN+RESOLVE 同批释放 → 静默关闭
        batch = [
            ev("o1", "t", GAP, PHASE_OPEN, "c", 1),
            ev("r2", "t", GAP, PHASE_RESOLVE, "c", 2),
        ]
        res = self.router.ingest_batch(batch)
        # 没有任何告警来自链 c
        for r in res:
            for a in r["alerts"]:
                self.assertNotEqual(a["chain_id"], "c")
        self.assertEqual(
            self.store.get_alert_by_chain("t", GAP, "c"), None)
        kinds = self.audit_kinds()
        self.assertIn("chain_pending_closed", kinds)
        # 链 c2 的 OPEN(seq4) 也在同批级联释放 → 正常补发
        a2 = self.store.get_alert_by_chain("t", AUDIT, "c2")
        self.assertIsNotNone(a2)
        self.assertEqual(a2["backfilled"], 1)
        notifs = self.store.list_notifications(a2["alert_id"])
        self.assertTrue(any(n["kind"] == "fired" for n in notifs))

    def test_resolve_only_held_never_fires_without_open(self):
        # 只收到 RESOLVE（OPEN 永远不来）：不产生告警
        self.router.ingest_event(
            ev("rr", "t", QUARANTINE, PHASE_RESOLVE, "ghost", 5))
        self.assertEqual(self.router.list_alerts(), [])
        # 补齐 1..4 后 seq5 释放，仍无 OPEN，无告警
        self.router.ingest_batch([
            ev(f"p{i}", "t", TAKEOVER, PHASE_OPEN, f"other{i}", i)
            for i in range(1, 5)])
        self.assertEqual(
            self.store.get_alert_by_chain("t", QUARANTINE, "ghost"), None)

    def test_recurrence_after_silent_close_starts_new_cycle(self):
        # seq2(RESOLVE)、seq3(OPEN 第一周期) 先挂起；seq1(OPEN) 补齐后
        # 级联释放 1,2,3：第一周期 OPEN+RESOLVE 在水位外完整 → 静默关闭；
        # seq4 再来 OPEN → 新异常周期正常触发；seq5 RESOLVE → 正常恢复。
        self.router.ingest_batch([
            ev("z-r", "t2", GAP, PHASE_RESOLVE, "z", 2),
            ev("z-o2", "t2", GAP, PHASE_OPEN, "z", 3),
        ])
        self.router.ingest_event(ev("z-o", "t2", GAP, PHASE_OPEN, "z", 1))
        # 第一周期静默关闭，无告警
        self.assertIsNone(
            self.store.get_alert_by_chain("t2", GAP, "z"))
        # 新周期 OPEN（seq4）→ 触发；RESOLVE（seq5）→ 恢复
        r4 = self.router.ingest_event(
            ev("z-o3", "t2", GAP, PHASE_OPEN, "z", 4))
        self.assertEqual(r4["alerts"][0]["status"], OPEN)
        self.assertEqual(r4["alerts"][0]["backfilled"], 0)
        r5 = self.router.ingest_event(
            ev("z-r2", "t2", GAP, PHASE_RESOLVE, "z", 5))
        self.assertEqual(r5["alerts"][0]["status"], RECOVERED)

    def test_watermark_independent_per_tenant(self):
        self.router.ingest_event(ev("a9", "A", GAP, PHASE_OPEN, "g", 9))
        r = self.router.ingest_event(ev("b1", "B", GAP, PHASE_OPEN, "g2", 1))
        # B 不受 A 的缺口影响
        self.assertFalse(r["held"])
        self.assertEqual(r["alerts"][0]["status"], OPEN)


class TestDedupWindow(RouterTestBase):
    def test_retransmit_deduped_within_window(self):
        self.router.ingest_event(ev("o1", "t", QUARANTINE, PHASE_OPEN, "seg", 1))
        # GAP 窗口默认 300s；QUARANTINE 600s。seq2 在窗口内重发
        self.router.ingest_event(
            ev("o2", "t", QUARANTINE, PHASE_OPEN, "seg", 2, _iso(100)))
        alerts = self.router.list_alerts()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["occurrence_count"], 2)
        kinds = self.audit_kinds(alerts[0]["alert_id"])
        self.assertIn("alert_deduped", kinds)
        notifs = self.store.list_notifications(alerts[0]["alert_id"])
        self.assertEqual([n["kind"] for n in notifs], ["fired", "deduped"])

    def test_notify_again_after_window(self):
        self.router.ingest_event(ev("o1", "t", GAP, PHASE_OPEN, "g", 1))
        aid = self.router.list_alerts()[0]["alert_id"]
        # GAP 默认窗口 300s；600s 后再来 OPEN → 重新 fired
        self.router.ingest_event(
            ev("o2", "t", GAP, PHASE_OPEN, "g", 2, _iso(600)))
        notifs = self.store.list_notifications(aid)
        self.assertEqual([n["kind"] for n in notifs], ["fired", "fired"])


class TestIdempotency(RouterTestBase):
    def test_same_event_id_is_idempotent(self):
        e = ev("same-id", "t", GAP, PHASE_OPEN, "g", 1)
        r1 = self.router.ingest_event(e)
        r2 = self.router.ingest_event(e)
        self.assertTrue(r2["idempotent_replay"])
        self.assertEqual(r1["jseq"], r2["jseq"])
        alerts = self.router.list_alerts()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["occurrence_count"], 1)
        # 审计里 fired 只出现一次
        self.assertEqual(self.audit_kinds(alerts[0]["alert_id"]),
                         ["alert_fired"])

    def test_command_idempotency_key(self):
        self.router.ingest_event(ev("e", "t", GAP, PHASE_OPEN, "g", 1))
        aid = self.router.list_alerts()[0]["alert_id"]
        a1 = self.router.execute("ack", {"alert_id": aid, "actor": "u"},
                                 idem_key="ack-1")
        self.assertEqual(a1["status"], ACKED)
        a2 = self.router.execute("ack", {"alert_id": aid, "actor": "u"},
                                 idem_key="ack-1")
        self.assertTrue(a2.get("idempotent_replay"))
        self.assertEqual(self.audit_kinds(aid).count("alert_acked"), 1)


class TestAckRecoverRace(RouterTestBase):
    def test_concurrent_ack_and_event_recover_one_winner(self):
        res = {}
        self.router.ingest_event(ev("e", "t", GAP, PHASE_OPEN, "g", 1))
        alert = self.router.list_alerts()[0]
        aid, version = alert["alert_id"], alert["version"]
        barrier = threading.Barrier(2)

        def do_ack():
            barrier.wait()
            try:
                res["ack"] = self.router.execute(
                    "ack", {"alert_id": aid, "version": version, "actor": "a"})
            except RouterError as exc:
                res["ack_err"] = exc.reason

        def do_recover():
            barrier.wait()
            try:
                res["rec"] = self.router.ingest_event(
                    ev("er", "t", GAP, PHASE_RESOLVE, "g", 2))
            except RouterError as exc:
                res["rec_err"] = exc.reason

        t1 = threading.Thread(target=do_ack)
        t2 = threading.Thread(target=do_recover)
        t1.start(); t2.start(); t1.join(); t2.join()

        final = self.store.get_alert(aid)
        # 终态确定：要么 ACKED 要么 RECOVERED；输家得到 409 或冲突标记
        self.assertIn(final["status"], (ACKED, RECOVERED))
        if final["status"] == ACKED:
            # 恢复事件在 ACKED 之后仍应推进到 RECOVERED（事件收口不认输）
            self.assertIsNotNone(res.get("rec"))
            final = self.store.get_alert(aid)
            self.assertEqual(final["status"], RECOVERED)
        # 每条实际发生的转移一条审计，且只有一个赢家的首转移
        kinds = self.audit_kinds(aid)
        self.assertEqual(kinds.count("alert_acked"),
                         1 if "alert_acked" in kinds else 0)
        self.assertGreaterEqual(kinds.count("alert_recovered"), 1)

    def test_stale_version_ack_rejected(self):
        self.router.ingest_event(ev("e", "t", GAP, PHASE_OPEN, "g", 1))
        aid = self.router.list_alerts()[0]["alert_id"]
        self.router.execute("ack", {"alert_id": aid})
        with self.assertRaises(RouterError) as cx:
            self.router.execute("recover", {"alert_id": aid, "version": 1})
        self.assertEqual(cx.exception.reason, "ALERT_VERSION_CONFLICT")

    def test_close_terminal_blocks_ack(self):
        self.router.ingest_event(ev("e", "t", GAP, PHASE_OPEN, "g", 1))
        aid = self.router.list_alerts()[0]["alert_id"]
        self.router.execute("close", {"alert_id": aid})
        with self.assertRaises(RouterError):
            self.router.execute("ack", {"alert_id": aid})

    def test_reopen_after_recovery(self):
        self.router.ingest_event(ev("o", "t", GAP, PHASE_OPEN, "g", 1))
        self.router.ingest_event(ev("r", "t", GAP, PHASE_RESOLVE, "g", 2))
        # TTL 未到、异常复发
        self.router.ingest_event(
            ev("o2", "t", GAP, PHASE_OPEN, "g", 3, _iso(500)))
        alert = self.store.get_alert_by_chain("t", GAP, "g")
        self.assertEqual(alert["status"], OPEN)
        kinds = self.audit_kinds(alert["alert_id"])
        self.assertIn("alert_reopened", kinds)


class TestSilence(RouterTestBase):
    def test_global_silence_suppresses_new_alert(self):
        self.router.execute("create_silence",
                            {"reason": "freeze", "silence_id": "s1"})
        r = self.router.ingest_event(ev("e", "t", GAP, PHASE_OPEN, "g", 1))
        self.assertEqual(r["alerts"][0]["status"], SILENCED)
        aid = r["alerts"][0]["alert_id"]
        notifs = self.store.list_notifications(aid)
        self.assertEqual([n["kind"] for n in notifs], ["suppressed"])
        # 静默中不能确认
        with self.assertRaises(RouterError) as cx:
            self.router.execute("ack", {"alert_id": aid})
        self.assertEqual(cx.exception.reason, "ALERT_SILENCED")

    def test_tenant_type_scoped_silence(self):
        # 只静默 t/GAP；t/QUARANTINE 与 t2/GAP 不受影响
        self.router.execute("create_silence",
                            {"tenant": "t", "type": GAP,
                             "reason": "gap window", "silence_id": "s2"})
        r_gap = self.router.ingest_event(ev("g", "t", GAP, PHASE_OPEN, "g", 1))
        r_q = self.router.ingest_event(
            ev("q", "t", QUARANTINE, PHASE_OPEN, "q", 2))
        r_other = self.router.ingest_event(
            ev("g2", "t2", GAP, PHASE_OPEN, "g2", 1))
        self.assertEqual(r_gap["alerts"][0]["status"], SILENCED)
        self.assertEqual(r_q["alerts"][0]["status"], OPEN)
        self.assertEqual(r_other["alerts"][0]["status"], OPEN)

    def test_rule_applies_to_existing_alerts_and_revoke_restores(self):
        self.router.ingest_event(ev("g", "t", GAP, PHASE_OPEN, "g", 1))
        aid = self.router.list_alerts()[0]["alert_id"]
        self.router.execute("ack", {"alert_id": aid, "actor": "u"})
        self.router.execute("create_silence",
                            {"tenant": "t", "silence_id": "s3"})
        self.assertEqual(self.store.get_alert(aid)["status"], SILENCED)
        # 撤销规则 → 曾 ACKED 的回到 ACKED（确认事实不丢）
        self.router.execute("revoke_silence", {"silence_id": "s3"})
        self.assertEqual(self.store.get_alert(aid)["status"], ACKED)

    def test_silence_expiry_restores_open(self):
        # 静默从“现在”起 100s 后到期
        from qrouter.models import parse_ts, to_ts
        from datetime import timedelta
        end = to_ts(parse_ts(self.now[0]) + timedelta(seconds=100))
        self.router.execute("create_silence", {
            "silence_id": "s4", "ends_at": end})
        self.router.ingest_event(
            ev("g", "t", GAP, PHASE_OPEN, "g", 1, self.now[0]))
        aid = self.router.list_alerts()[0]["alert_id"]
        self.assertEqual(self.store.get_alert(aid)["status"], SILENCED)
        # 推进墙钟到到期后；下一次事件携带的 tick 会收口
        self.advance(200)
        self.router.ingest_event(
            ev("unrelated", "t2", TAKEOVER, PHASE_OPEN, "tk", 1, self.now[0]))
        self.assertEqual(self.store.get_alert(aid)["status"], OPEN)
        self.assertIn("silence_expired", self.audit_kinds())
        self.assertIn("alert_unsilenced", self.audit_kinds(aid))


class TestRestartRecovery(RouterTestBase):
    def _snapshot(self):
        return {
            "alerts": [
                {k: a[k] for k in (
                    "alert_id", "tenant", "type", "chain_id", "status",
                    "version", "occurrence_count", "backfilled",
                    "opened_event_id", "resolved_event_id", "silence_id")}
                for a in self.store.list_alerts(limit=10000)],
            "tenants": self.router.watermarks(),
            "silences": [
                {k: s[k] for k in (
                    "silence_id", "tenant", "type", "revoked_at")}
                for s in self.store.list_silences(True)],
            "audit": sorted(
                (r["kind"], r["dedup_key"]) for r in
                self.store.list_audit(limit=10000)),
        }

    def test_rebuild_materialized_state_equivalent(self):
        # 制造丰富状态：活动/确认/恢复/静默/挂起/缺口
        self.router.ingest_event(ev("a1", "t1", GAP, PHASE_OPEN, "g1", 1))
        self.router.ingest_event(
            ev("a2", "t1", GAP, PHASE_RESOLVE, "g1", 2))  # RECOVERED
        self.router.ingest_event(
            ev("b1", "t1", QUARANTINE, PHASE_OPEN, "q1", 3))
        qid = self.store.get_alert_by_chain("t1", QUARANTINE, "q1")["alert_id"]
        self.router.execute("ack", {"alert_id": qid, "actor": "ops"})
        self.router.execute("create_silence",
                            {"tenant": "t2", "silence_id": "sx", "reason": "w"})
        self.router.ingest_event(
            ev("c9", "t2", GAP, PHASE_OPEN, "g9", 9))  # 挂起中重启
        before = self._snapshot()

        self.reopen()
        after = self._snapshot()
        self.assertEqual(before, after)

        # 重启后继续补齐挂起缺口：链正常补发，水位推进
        self.router.ingest_batch([
            ev(f"c{i}", "t2", AUDIT, PHASE_OPEN, f"h{i}", i)
            for i in range(1, 9)])
        g9 = self.store.get_alert_by_chain("t2", GAP, "g9")
        self.assertIsNotNone(g9)
        self.assertEqual(g9["backfilled"], 1)
        self.assertEqual(
            {w["tenant"]: w["next_seq"] for w in self.router.watermarks()}["t2"],
            10)

    def test_replay_audit_not_duplicated(self):
        self.router.ingest_event(ev("a", "t", GAP, PHASE_OPEN, "g", 1))
        self.router.ingest_event(ev("b", "t", GAP, PHASE_RESOLVE, "g", 2))
        n_before = len(self.store.list_audit(limit=10000))
        self.reopen()
        n_after = len(self.store.list_audit(limit=10000))
        self.assertEqual(n_before, n_after)


class TestRecoveredTTL(RouterTestBase):
    def test_recovered_auto_closes_after_ttl_on_tick(self):
        self.router = AlertRouter(self.store, recovered_ttl_seconds=60,
                                  clock=self.clock)
        self.router.ingest_event(ev("o", "t", GAP, PHASE_OPEN, "g", 1))
        self.router.ingest_event(ev("r", "t", GAP, PHASE_RESOLVE, "g", 2))
        aid = self.store.get_alert_by_chain("t", GAP, "g")["alert_id"]
        # 30s 后 tick：未到 TTL
        self.advance(30)
        self.router._tick(self.now[0])
        self.assertEqual(self.store.get_alert(aid)["status"], RECOVERED)
        # 80s 后 tick：自动关闭
        self.advance(50)
        self.router._tick(self.now[0])
        self.assertEqual(self.store.get_alert(aid)["status"], CLOSED)
        self.assertIn("recovered_ttl_closed", self.audit_kinds(aid))

    def test_restart_closes_expired_recovered_immediately(self):
        # TTL 60s；恢复后推进墙钟 200s 再重启 → 启动 tick 立即关闭
        self.router = AlertRouter(self.store, recovered_ttl_seconds=60,
                                  clock=self.clock)
        self.router.ingest_event(ev("o", "t", GAP, PHASE_OPEN, "g", 1))
        self.router.ingest_event(ev("r", "t", GAP, PHASE_RESOLVE, "g", 2))
        aid = self.store.get_alert_by_chain("t", GAP, "g")["alert_id"]
        self.assertEqual(self.store.get_alert(aid)["status"], RECOVERED)
        self.advance(200)
        self.reopen(ttl=60)
        self.assertEqual(self.store.get_alert(aid)["status"], CLOSED)
        self.assertIn("recovered_ttl_closed", self.audit_kinds(aid))


class TestAuditCompleteness(RouterTestBase):
    def test_every_transition_has_exactly_one_audit(self):
        self.router.ingest_event(ev("o", "t", QUARANTINE, PHASE_OPEN, "q", 1))
        aid = self.store.get_alert_by_chain("t", QUARANTINE, "q")["alert_id"]
        self.assertEqual(self.audit_kinds(aid), ["alert_fired"])
        self.router.execute("ack", {"alert_id": aid})
        self.assertEqual(self.audit_kinds(aid),
                         ["alert_fired", "alert_acked"])
        self.router.ingest_event(
            ev("r", "t", QUARANTINE, PHASE_RESOLVE, "q", 2))
        self.assertEqual(self.audit_kinds(aid),
                         ["alert_fired", "alert_acked", "alert_recovered"])
        self.router.execute("close", {"alert_id": aid})
        self.assertEqual(self.audit_kinds(aid),
                         ["alert_fired", "alert_acked", "alert_recovered",
                          "alert_closed"])


class TestBatchAtomicValidation(RouterTestBase):
    def test_invalid_batch_rejected_entirely(self):
        good = ev("g", "t", GAP, PHASE_OPEN, "g", 1)
        bad = {"event_id": "bad", "tenant": "t", "type": "WAT",
               "phase": PHASE_OPEN, "chain_id": "x", "seq": 2,
               "occurred_at": _iso()}
        with self.assertRaises(RouterError):
            self.router.ingest_batch([good, bad])
        self.assertEqual(self.router.list_alerts(), [])
        self.assertEqual(self.store.max_jseq(), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
