"""真实 HTTP 双端到端测试：启动 qrouter HTTP 服务 + 模拟复制器接口。

- qrouter 用真实 ThreadingHTTPServer + 临时 SQLite；
- 用一个极简的假复制器 HTTP 服务提供 /ops/audit-tail、/ops/quarantine、
  /ops/status，验证订阅器的四类事件映射与轮询幂等；
- 验证全部运维接口：确认（CAS 竞争）、静默、恢复、查询、批量原子、重启。
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from qrouter.engine import AlertRouter
from qrouter.http_server import create_server
from qrouter.store import Store
from qrouter.subscriber import ReplicaSubscriber


def _request(method, url, body=None, headers=None, expect_error=False):
    data = None
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    if body is not None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        payload = json.loads(exc.read().decode("utf-8"))
        if expect_error:
            return exc.code, payload
        raise AssertionError(f"{method} {url} -> {exc.code}: {payload}")


# ---------------------------------------------------------------------------
# 假复制器
# ---------------------------------------------------------------------------

class FakeReplicaState:
    def __init__(self):
        self.lock = threading.Lock()
        self.audit_entries = []   # {id, at, kind, detail_json}
        self.quarantine = []
        self.status = {"watermark_contiguous": True, "epoch": 1,
                       "confirmed_index": 0, "last_error": None}
        self._audit_seq = 0

    def add_audit(self, kind, detail, at=None):
        with self.lock:
            self._audit_seq += 1
            self.audit_entries.append({
                "id": self._audit_seq, "at": at or time.time(),
                "kind": kind, "detail_json": json.dumps(detail)})
            return self._audit_seq

    def add_quarantine(self, rid, reason, resolved_at=None,
                       resolution=None, epoch=None, segment_index=None):
        with self.lock:
            self.quarantine.append({
                "id": rid, "reason": reason, "segment_index": segment_index,
                "epoch": epoch, "resolved_at": resolved_at,
                "resolution": resolution, "source": "poll-test"})


class _FakeReplicaHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # noqa: A003
        pass

    def _send(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        st = self.server.state  # type: ignore
        if self.path.startswith("/ops/audit-tail"):
            with st.lock:
                return self._send(200, {"entries": list(st.audit_entries)})
        if self.path.startswith("/ops/quarantine"):
            with st.lock:
                return self._send(200, {"records": list(st.quarantine)})
        if self.path.startswith("/ops/status"):
            with st.lock:
                return self._send(200, dict(st.status))
        self._send(404, {"error": "not_found"})


# ---------------------------------------------------------------------------
# 测试
# ---------------------------------------------------------------------------

class HttpEndToEndTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.db_path = self.tmp.name
        self.store = Store(self.db_path)
        self.router = AlertRouter(self.store, recovered_ttl_seconds=3600)
        self.httpd = create_server("127.0.0.1", 0, self.router)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever,
                                       daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.port}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=3)
        self.store.close()
        os.unlink(self.db_path)
        for ext in ("-wal", "-shm"):
            p = self.db_path + ext
            if os.path.exists(p):
                os.unlink(p)

    def test_event_to_ack_recover_close_lifecycle(self):
        evt = {"event_id": "h1", "tenant": "ten-x", "type": "QUARANTINE",
               "phase": "OPEN", "chain_id": "seg-7", "seq": 1,
               "occurred_at": "2026-10-07T10:00:00Z",
               "payload": {"reason": "CHAIN_DIGEST_BROKEN"}}
        code, r = _request("POST", self.base + "/api/events", evt)
        self.assertEqual(code, 202)
        self.assertFalse(r["held"])
        aid = r["alerts"][0]["alert_id"]

        # 查询
        _, lst = _request("GET", self.base + "/api/alerts?tenant=ten-x")
        self.assertEqual(len(lst["alerts"]), 1)
        _, detail = _request("GET", self.base + "/api/alerts/" + aid)
        self.assertEqual(detail["alert"]["status"], "OPEN")

        # 旧版本确认 → 409
        code, err = _request(
            "POST", f"{self.base}/api/alerts/{aid}/ack?version=99",
            {"actor": "ops"}, expect_error=True)
        self.assertEqual(code, 409)
        self.assertEqual(err["error"], "ALERT_VERSION_CONFLICT")

        # 正确版本确认
        code, acked = _request(
            "POST", f"{self.base}/api/alerts/{aid}/ack?version=1",
            {"actor": "ops"})
        self.assertEqual(acked["status"], "ACKED")
        self.assertEqual(acked["version"], 2)

        # 链收口事件 → RECOVERED
        res_evt = dict(evt, event_id="h2", phase="RESOLVE", seq=2,
                       occurred_at="2026-10-07T10:05:00Z")
        code, r = _request("POST", self.base + "/api/events", res_evt)
        self.assertEqual(r["alerts"][0]["status"], "RECOVERED")

        # 关闭
        code, closed = _request(
            "POST", f"{self.base}/api/alerts/{aid}/close", {})
        self.assertEqual(closed["status"], "CLOSED")

        # 审计完整
        _, aud = _request(
            "GET", self.base + "/api/audit?alert_id=" + aid)
        kinds = [e["kind"] for e in reversed(aud["entries"])]
        self.assertEqual(
            kinds, ["alert_fired", "alert_acked", "alert_recovered",
                    "alert_closed"])

    def test_idempotent_event_replay(self):
        evt = {"event_id": "idem-1", "tenant": "ti", "type": "GAP",
               "phase": "OPEN", "chain_id": "g", "seq": 1,
               "occurred_at": "2026-10-07T10:00:00Z", "payload": {}}
        _request("POST", self.base + "/api/events", evt)
        code, r2 = _request("POST", self.base + "/api/events", evt)
        self.assertTrue(r2["idempotent_replay"])
        _, lst = _request("GET", self.base + "/api/alerts?tenant=ti")
        self.assertEqual(len(lst["alerts"]), 1)
        self.assertEqual(lst["alerts"][0]["occurrence_count"], 1)

    def test_batch_invalid_atomic(self):
        good = {"event_id": "b1", "tenant": "tb", "type": "GAP",
                "phase": "OPEN", "chain_id": "g", "seq": 1,
                "occurred_at": "2026-10-07T10:00:00Z", "payload": {}}
        bad = {"event_id": "b2", "tenant": "tb", "type": "BOGUS",
               "phase": "OPEN", "chain_id": "g2", "seq": 2,
               "occurred_at": "2026-10-07T10:01:00Z", "payload": {}}
        code, err = _request(
            "POST", self.base + "/api/events/batch",
            {"events": [good, bad]}, expect_error=True)
        self.assertEqual(code, 422)
        _, stats = _request("GET", self.base + "/api/stats")
        self.assertEqual(stats["journal_entries"], 0)

    def test_gap_held_backfill_and_pending_view(self):
        # seq 5 先到 → 挂起
        late = {"event_id": "late", "tenant": "tg", "type": "GAP",
                "phase": "OPEN", "chain_id": "g5", "seq": 5,
                "occurred_at": "2026-10-07T10:00:00Z", "payload": {}}
        code, r = _request("POST", self.base + "/api/events", late)
        self.assertTrue(r["held"])
        _, pending = _request("GET", self.base + "/api/pending")
        self.assertEqual(pending["tenants"][0]["missing_seqs"], [1, 2, 3, 4])

        # 批量补齐 1..5
        evts = [{
            "event_id": f"f{i}", "tenant": "tg", "type": "AUDIT",
            "phase": "OPEN", "chain_id": f"c{i}", "seq": i,
            "occurred_at": f"2026-10-07T10:0{i}:00Z", "payload": {}}
            for i in range(1, 5)]
        code, r = _request("POST", self.base + "/api/events/batch",
                           {"events": evts})
        self.assertEqual(code, 202)
        # g5（seq5 挂起）被级联补发
        g5 = [a for a in
              self.router.store.list_alerts(tenant="tg", limit=100)
              if a["chain_id"] == "g5"][0]
        self.assertEqual(g5["backfilled"], 1)
        _, pending = _request("GET", self.base + "/api/pending")
        self.assertEqual(pending["tenants"], [])

    def test_silence_rule_create_and_revoke(self):
        # 先有活动告警
        evt = {"event_id": "s1", "tenant": "ts", "type": "QUARANTINE",
               "phase": "OPEN", "chain_id": "q", "seq": 1,
               "occurred_at": "2026-10-07T10:00:00Z", "payload": {}}
        _, r = _request("POST", self.base + "/api/events", evt)
        aid = r["alerts"][0]["alert_id"]
        # 建租户级静默规则：现有告警立即被静默
        code, s = _request("POST", self.base + "/api/silences",
                           {"silence_id": "rule-1", "tenant": "ts",
                            "reason": "maintenance"})
        self.assertEqual(code, 201)
        self.assertEqual(self.store.get_alert(aid)["status"], "SILENCED")
        # 撤销 → 回到 OPEN（未确认过）
        code, r2 = _request(
            "POST", self.base + "/api/silences/rule-1/revoke", {})
        self.assertEqual(r2["unsilenced_alert_ids"], [aid])
        self.assertEqual(self.store.get_alert(aid)["status"], "OPEN")
        # 幂等：重复撤销返回原结果
        code, r3 = _request(
            "POST", self.base + "/api/silences/rule-1/revoke", {}, )
        self.assertTrue(r3.get("idempotent_replay"))

    def test_ops_page_served(self):
        with urllib.request.urlopen(self.base + "/", timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("text/html", resp.headers["Content-Type"])
            html = resp.read().decode()
        self.assertIn("告警路由器", html)


class SubscriberEndToEndTest(unittest.TestCase):
    """qrouter 订阅假复制器：四类事件映射与轮询幂等。"""

    def setUp(self):
        # 假复制器
        self.replica_state = FakeReplicaState()
        self.replica = ThreadingHTTPServer(
            ("127.0.0.1", 0), _FakeReplicaHandler)
        self.replica.state = self.replica_state  # type: ignore
        self.rport = self.replica.server_address[1]
        self.rthread = threading.Thread(target=self.replica.serve_forever,
                                        daemon=True)
        self.rthread.start()

        # qrouter（不启动 HTTP，只测订阅器 → 引擎）
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.db_path = self.tmp.name
        self.store = Store(self.db_path)
        self.router = AlertRouter(self.store)
        self.sub = ReplicaSubscriber(
            self.router, f"http://127.0.0.1:{self.rport}",
            tenant="dr-site-A", poll_interval=1,
            log=lambda *_a, **_k: None)

    def tearDown(self):
        self.replica.shutdown()
        self.replica.server_close()
        self.rthread.join(timeout=3)
        self.store.close()
        os.unlink(self.db_path)

    def test_poll_maps_quarantine_takeover_gap_and_resolve(self):
        # 1) 复制器发生隔离
        self.replica_state.add_audit("segment_quarantined", {
            "reason": "EVENT_HASH_BROKEN", "source": "poll",
            "segment_index": 42})
        self.replica_state.add_quarantine(
            7, "EVENT_HASH_BROKEN", segment_index=42)
        self.sub.poll_once()
        alerts = self.store.list_alerts(etype="QUARANTINE")
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["status"], "OPEN")
        chain = alerts[0]["chain_id"]
        self.assertEqual(chain, "quar-seg-42")

        # 2) 复制器重启接管（epoch 提升）→ TAKEOVER 链瞬时完整 → RECOVERED
        self.replica_state.add_audit("replicator_started", {"epoch": 3})
        self.replica_state.status["epoch"] = 3
        self.sub.poll_once()
        tk = self.store.list_alerts(etype="TAKEOVER")
        self.assertEqual(len(tk), 1)
        self.assertEqual(tk[0]["status"], "RECOVERED")

        # 3) 缺口出现：状态显示不连续
        self.replica_state.status["watermark_contiguous"] = False
        self.replica_state.status["confirmed_index"] = 40
        self.sub.poll_once()
        gaps = self.store.list_alerts(etype="GAP")
        self.assertEqual(len(gaps), 1)
        self.assertEqual(gaps[0]["status"], "OPEN")

        # 4) 缺口恢复连续 → 同链 RESOLVE
        self.replica_state.status["watermark_contiguous"] = True
        self.replica_state.status["confirmed_index"] = 43
        # 隔离也被消除
        self.replica_state.quarantine[0]["resolved_at"] = time.time()
        self.replica_state.quarantine[0]["resolution"] = "gap filled"
        self.sub.poll_once()
        self.assertEqual(
            self.store.get_alert_by_chain("dr-site-A", "GAP",
                                          "watermark-gap")["status"],
            "RECOVERED")
        self.assertEqual(
            self.store.get_alert_by_chain("dr-site-A", "QUARANTINE",
                                          "quar-seg-42")["status"],
            "RECOVERED")

        # 5) 再轮询多次：幂等，不产生新告警/重复事件
        before = len(self.store.list_alerts(limit=1000))
        for _ in range(3):
            self.sub.poll_once()
        after = len(self.store.list_alerts(limit=1000))
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main(verbosity=2)
