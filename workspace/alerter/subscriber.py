"""订阅复制器的审计轨迹与隔离记录，归一化为告警事件。

复制器（``replica``）本身不推送“告警事件”，它只暴露两类事实：

- ``GET /ops/audit-tail``：只追加审计轨迹（segment_quarantined / ownership_lost /
  replicator_started …），自增 id、跨重启稳定；
- ``GET /ops/quarantine?include_resolved=1``：隔离记录及 ``resolved_at`` 消除时间。

订阅器把这些事实**翻译**成路由器的规范化事件：

| 复制器事实 | 合成事件 |
|---|---|
| ``segment_quarantined``（缺口类原因） | GAP BEGIN + AUDIT 见证 |
| ``segment_quarantined``（其余原因） | ISOLATION BEGIN + AUDIT 见证 |
| 隔离记录出现 ``resolved_at`` | 对应类型 END + AUDIT 见证（关闭/恢复链路） |
| ``ownership_lost`` | TAKEOVER BEGIN + AUDIT 见证 |
| ``replicator_started``（存在开放接管链） | TAKEOVER END + AUDIT 见证（新实例接管完成） |

``event_id`` 由源记录 id 确定性派生（如 ``seg-q:{audit_id}:begin``），因此
重复轮询/重启后重放只会命中同事件幂等，绝不重复触发；seq 不显式携带，
由路由器按租户稠密分配，保证连续水位不因“订阅器换页”出现人工缺口。
"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Callable

from . import models

# 复制器原因码 → 是否属于“缺口”类（对照 replica/verifier.py 的准入失败原因）
GAP_REASONS = frozenset({
    "SEGMENT_INDEX_MISMATCH",   # 错序/缺段：异常缺口阻挡前进
    "SEQ_NOT_CONTIGUOUS",
    "CHAIN_DIGEST_BROKEN",      # 断链本质也是“这段水位不可用”，按缺口感知
    "EVENT_HASH_BROKEN",
    "EVENT_CROSS_CHAIN_BROKEN",
})
# 滞后超限隔离本质上是“复制缺口过大”，按 GAP 而非一般隔离
GAP_REASON_PREFIXES = ("LAG_",)

DEFAULT_TENANT = "platform"


def _http_json(url: str, timeout: float = 5.0) -> Any:
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _is_gap_reason(reason: str) -> bool:
    return reason in GAP_REASONS or any(reason.startswith(p) for p in GAP_REASON_PREFIXES)


def tenant_from_detail(detail: dict[str, Any], default: str = DEFAULT_TENANT) -> str:
    """从复制器审计明细提取租户：显式 tenant 优先，否则落到平台级租户。"""
    for key in ("tenant", "tenant_id"):
        val = detail.get(key)
        if isinstance(val, str) and val:
            return val
    payload = detail.get("payload") if isinstance(detail.get("payload"), dict) else None
    if payload:
        for key in ("tenant", "tenant_id"):
            val = payload.get(key)
            if isinstance(val, str) and val:
                return val
    return default


def classify_kind(kind: str, detail: dict[str, Any]) -> str | None:
    """审计 kind → 告警事件类型；与告警无关的 kind 返回 None。"""
    if kind == "segment_quarantined":
        return models.GAP if _is_gap_reason(str(detail.get("reason") or "")) else models.ISOLATION
    if kind == "ownership_lost":
        return models.TAKEOVER
    if kind == "replicator_started":
        return models.TAKEOVER
    return None


class Subscriber:
    """轮询复制器并把归一化事件投递给 :class:`~alerter.router.AlertRouter`。"""

    def __init__(
        self,
        router,
        replica_url: str,
        *,
        poll_interval: float = 1.0,
        request_timeout: float = 5.0,
        default_tenant: str = DEFAULT_TENANT,
        fetcher: Callable[[str], Any] | None = None,
        clock: Callable[[], float] | None = None,
    ):
        self.router = router
        self.store = router.store
        self.replica_url = replica_url.rstrip("/")
        self.poll_interval = poll_interval
        self.request_timeout = request_timeout
        self.default_tenant = default_tenant
        self._fetcher = fetcher
        self._clock = clock or time.time
        self._stop = threading.Event()
        self.thread: threading.Thread | None = None
        self.last_poll_at: float | None = None
        self.last_error: str | None = None
        # 已处理到的审计 id 与已发出 END 的隔离 id（也持久化在 meta，重启不重放）
        self.cursor = int(self.store.get_meta("subscriber:audit_cursor", 0) or 0)
        self._resolved_seen: set[int] = set(
            self.store.get_meta("subscriber:resolved_quarantine", []) or []
        )

    # ------------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------------

    def _fetch(self, path: str) -> Any:
        if self._fetcher is not None:
            return self._fetcher(path)
        return _http_json(f"{self.replica_url}{path}", timeout=self.request_timeout)

    def _fetch_audit_tail(self) -> list[dict[str, Any]]:
        # 复制器 audit-tail 默认按 id 倒序；这里拉较大窗口后自行按 id 升序处理
        body = self._fetch("/ops/audit-tail?limit=500")
        entries = body.get("entries", body) if isinstance(body, dict) else body
        if not isinstance(entries, list):
            return []
        return sorted(
            (e for e in entries if isinstance(e, dict) and "id" in e),
            key=lambda e: int(e["id"]),
        )

    def _fetch_quarantine(self) -> list[dict[str, Any]]:
        body = self._fetch("/ops/quarantine?include_resolved=1")
        # 复制器返回 {"records": [...]}；兼容裸数组/旧键名
        if isinstance(body, dict):
            rows = body.get("records", body.get("quarantine", []))
        else:
            rows = body
        return rows if isinstance(rows, list) else []

    # ------------------------------------------------------------------
    # 归一化
    # ------------------------------------------------------------------

    def _chain_id_for(self, kind: str, entry_id: int, detail: dict[str, Any]) -> str:
        if kind == "ownership_lost":
            epoch = detail.get("lost_epoch")
            return f"takeover:epoch-{epoch}" if epoch is not None else f"takeover:{entry_id}"
        if kind == "replicator_started":
            # 闭合的是上一纪元失主链；与 _events_for_audit_entry 保持一致
            epoch = detail.get("epoch")
            if epoch is not None and int(epoch) >= 1:
                prior = f"takeover:epoch-{int(epoch) - 1}"
                if self._chain_exists(prior):
                    return prior
                return f"takeover:epoch-{epoch}"
            return f"takeover:{entry_id}"
        # segment_quarantined：同一 quarantine 记录（含 resolved END）共享链
        qid = detail.get("quarantine_id")
        if qid is not None:
            return f"quarantine:{qid}"
        seg = detail.get("segment_index")
        return f"quarantine:audit-{entry_id}:seg-{seg}"

    def _chain_exists(self, chain_id: str) -> bool:
        return self.store.get_chain(chain_id) is not None

    def _events_for_audit_entry(self, entry: dict[str, Any]) -> list[dict[str, Any]]:
        kind = str(entry.get("kind") or "")
        detail = entry.get("detail") if isinstance(entry.get("detail"), dict) else {}
        eid = int(entry["id"])
        alert_type = classify_kind(kind, detail)
        if alert_type is None:
            return []
        tenant = tenant_from_detail(detail, self.default_tenant)
        chain_id = self._chain_id_for(kind, eid, detail)
        reason = str(detail.get("reason") or "")
        at = float(entry.get("at") or self._clock())

        if kind == "replicator_started":
            # 新实例的 epoch 是接管后的纪元；它闭合的是“上一纪元失主”那条链。
            # 优先用权威纪元-1，找不到再回退当前值。
            epoch = detail.get("epoch")
            if epoch is not None and int(epoch) >= 1:
                chain_id = f"takeover:epoch-{int(epoch) - 1}"
                if not self._chain_exists(chain_id):
                    chain_id = f"takeover:epoch-{epoch}"
            else:
                chain_id = f"takeover:{entry_id}"
            return [{
                "event_id": f"repl-start:{eid}:end",
                "tenant": tenant, "event_type": models.TAKEOVER,
                "role": models.END, "chain_id": chain_id,
                "reason": "TAKEOVER_COMPLETE",
                "payload": detail, "occurred_at": at,
            }, {
                "event_id": f"repl-start:{eid}:witness",
                "tenant": tenant, "event_type": models.AUDIT,
                "role": models.WITNESS, "chain_id": chain_id,
                "reason": "replicator_started", "audit_ref": str(eid),
                "payload": detail, "occurred_at": at,
            }]

        if kind == "ownership_lost":
            return [{
                "event_id": f"own-lost:{eid}:begin",
                "tenant": tenant, "event_type": models.TAKEOVER,
                "role": models.BEGIN, "chain_id": chain_id,
                "reason": "OWNERSHIP_LOST", "payload": detail, "occurred_at": at,
            }, {
                "event_id": f"own-lost:{eid}:witness",
                "tenant": tenant, "event_type": models.AUDIT,
                "role": models.WITNESS, "chain_id": chain_id,
                "reason": "ownership_lost", "audit_ref": str(eid),
                "payload": detail, "occurred_at": at,
            }]

        # segment_quarantined → GAP / ISOLATION BEGIN + 见证
        return [{
            "event_id": f"seg-q:{eid}:begin",
            "tenant": tenant, "event_type": alert_type,
            "role": models.BEGIN, "chain_id": chain_id,
            "reason": reason, "payload": detail, "occurred_at": at,
        }, {
            "event_id": f"seg-q:{eid}:witness",
            "tenant": tenant, "event_type": models.AUDIT,
            "role": models.WITNESS, "chain_id": chain_id,
            "reason": reason, "audit_ref": str(eid),
            "payload": detail, "occurred_at": at,
        }]

    def _events_for_resolved_quarantine(self, row: dict[str, Any],
                                        chains_by_id: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
        qid = int(row["id"])
        reason = str(row.get("reason") or "")
        alert_type = models.GAP if _is_gap_reason(reason) else models.ISOLATION
        chain_id = f"quarantine:{qid}"
        # 租户必须与 BEGIN 时的链一致（审计明细可能带 tenant，隔离表自身不带）
        tenant = self.default_tenant
        if chain_id in chains_by_id:
            tenant = chains_by_id[chain_id].get("tenant", tenant)
        at = float(row.get("resolved_at") or self._clock())
        payload = {"quarantine_id": qid, "reason": reason,
                   "segment_index": row.get("segment_index"),
                   "resolution": row.get("resolution")}
        return [{
            "event_id": f"seg-q-resolve:{qid}:end",
            "tenant": tenant, "event_type": alert_type,
            "role": models.END, "chain_id": chain_id,
            "reason": reason, "payload": payload, "occurred_at": at,
        }, {
            "event_id": f"seg-q-resolve:{qid}:witness",
            "tenant": tenant, "event_type": models.AUDIT,
            "role": models.WITNESS, "chain_id": chain_id,
            "reason": "quarantine_resolved", "audit_ref": f"quarantine-{qid}",
            "payload": payload, "occurred_at": at,
        }]

    # ------------------------------------------------------------------
    # 轮询
    # ------------------------------------------------------------------

    def poll_once(self) -> dict[str, Any]:
        """一轮订阅：拉新增审计 → 拉隔离消除 → 批量投递。"""
        batch: list[dict[str, Any]] = []
        entries = self._fetch_audit_tail()
        new_entries = [e for e in entries if int(e["id"]) > self.cursor]
        # 开放的接管链：新实例 replicator_started 才被视为对应链的 END
        open_takeover_chains = {
            c["chain_id"] for c in self.router.list_chains(limit=10_000)
            if c["event_type"] == models.TAKEOVER
            and c["status"] in (models.CHAIN_OPEN, models.CHAIN_WITNESSED)
        }
        max_id = self.cursor
        # 同一轮里 ownership_lost 与 replicator_started 可能前后脚到达
        # （轮询窗口一次性覆盖）：本批新出现的失主链也算“有起点的接管”
        for entry in new_entries:
            kind = str(entry.get("kind") or "")
            detail = entry.get("detail") if isinstance(entry.get("detail"), dict) else {}
            if kind == "ownership_lost":
                open_takeover_chains.add(
                    self._chain_id_for(kind, int(entry["id"]), detail))
        for entry in new_entries:
            eid = int(entry["id"])
            max_id = max(max_id, eid)
            kind = str(entry.get("kind") or "")
            detail = entry.get("detail") if isinstance(entry.get("detail"), dict) else {}
            if kind == "replicator_started":
                chain_id = self._chain_id_for(kind, eid, detail)
                if chain_id not in open_takeover_chains:
                    continue  # 没有失主起点的普通启动不是一次接管
            batch.extend(self._events_for_audit_entry(entry))

        # 隔离消除（resolved_at）：为尚未发送过 END 的记录补发关闭事件。
        # 租户必须沿用链建立时的租户（隔离表行本身不带 tenant）。
        chains_by_id = {c["chain_id"]: c for c in self.router.list_chains(limit=10_000)}
        resolved_to_send: list[dict[str, Any]] = []
        resolved_ids: list[int] = []
        try:
            for row in self._fetch_quarantine():
                qid = int(row["id"])
                if row.get("resolved_at") and qid not in self._resolved_seen:
                    resolved_to_send.extend(
                        self._events_for_resolved_quarantine(row, chains_by_id))
                    resolved_ids.append(qid)
        except Exception:
            resolved_to_send = []
            resolved_ids = []  # 消除检测失败不阻塞审计轨迹消费

        if resolved_to_send:
            batch.extend(resolved_to_send)

        results: list[dict[str, Any]] = []
        if batch:
            results = self.router.ingest_batch(batch)
        self._resolved_seen.update(resolved_ids)

        if max_id > self.cursor:
            self.cursor = max_id
        self._persist_cursor()
        self.last_poll_at = self._clock()
        self.last_error = None
        return {
            "new_audit_entries": len(new_entries),
            "resolved_quarantines": len(resolved_to_send) // 2,
            "events_sent": len(batch),
            "cursor": self.cursor,
            "results": results,
            "polled_at": self.last_poll_at,
        }

    def _persist_cursor(self) -> None:
        self.store.set_meta("subscriber:audit_cursor", self.cursor)
        self.store.set_meta("subscriber:resolved_quarantine", sorted(self._resolved_seen))

    # ------------------------------------------------------------------
    # 后台循环
    # ------------------------------------------------------------------

    def start(self) -> None:
        if self.thread is not None:
            return
        self._stop.clear()
        self.thread = threading.Thread(target=self._loop, name="alert-subscriber", daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.wait(self.poll_interval):
            try:
                self.poll_once()
            except Exception as exc:  # 订阅线程不能死
                self.last_error = f"{type(exc).__name__}: {exc}"

    def status(self) -> dict[str, Any]:
        return {
            "replica_url": self.replica_url,
            "running": self.thread is not None and self.thread.is_alive(),
            "audit_cursor": self.cursor,
            "last_poll_at": self.last_poll_at,
            "last_error": self.last_error,
            "poll_interval": self.poll_interval,
        }
