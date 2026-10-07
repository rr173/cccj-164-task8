"""复制器订阅适配器：把 replica 的运维信号翻译成路由器四类事件。

复制器没有主动推送，本适配器以**审计轨迹为有序事实源**做轮询订阅：

    GET /ops/audit-tail  → 全局有序的运行事件（含 segment_quarantined /
                           ownership_lost / segment_confirmed / 纪元变更 …）
    GET /ops/quarantine  → 隔离记录（含 resolved_at 消除标记）
    GET /ops/status      → 纪元、连续水位、落后隔离状态

映射规则（tenant 固定为复制器实例名，多实例可用 --subscriber-name 区分）：

    segment_quarantined / ownership_lost        QUARANTINE OPEN
    隔离记录 resolved_at 被标记                  QUARANTINE RESOLVE
    replicator_started（epoch 提升）             TAKEOVER OPEN/RESOLVE
    状态轮询发现 watermark 不连续                 GAP OPEN
    watermark 恢复连续 / 缺口段确认              GAP RESOLVE
    全量 /ops/audit 完成                         AUDIT OPEN（自收口 RESOLVE）

轮询游标存 kv 表（最后处理的复制器审计 id 与隔离快照指纹），重复轮询因
event_id 幂等不会产生重复告警；重启后从游标继续。
"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from typing import Any

from .models import (
    AUDIT, GAP, QUARANTINE, TAKEOVER,
    PHASE_OPEN, PHASE_RESOLVE, now_ts,
)

# 复制器审计 kind → 路由器事件类型
KIND_QUARANTINE = {"segment_quarantined", "ownership_lost"}
KIND_TAKEOVER = {"replicator_started"}
# 这些 kind 表示水位/缺口相关动作
KIND_GAP_OPEN_HINTS = {"segment_quarantined"}
KIND_GAP_CLOSE_HINTS = {"segment_confirmed"}

KIND_AUDIT_RUN = {"full_audit"}  # 若复制器以后写该 kind


class ReplicaSubscriber:
    def __init__(self, router, base_url: str, *, tenant: str = "dr-site-1",
                 poll_interval: float = 2.0, timeout: float = 5.0,
                 kv_prefix: str = "subscriber", log=print):
        self.router = router
        self.base_url = base_url.rstrip("/")
        self.tenant = tenant
        self.poll_interval = poll_interval
        self.timeout = timeout
        self.kv_audit_cursor = f"{kv_prefix}:{tenant}:audit_id"
        self.kv_quar_seen = f"{kv_prefix}:{tenant}:quarantine"
        self.kv_epoch = f"{kv_prefix}:{tenant}:epoch"
        self.log = log
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_status: dict[str, Any] = {}

    # ------------------------------------------------------------------
    def _get_json(self, path: str) -> dict[str, Any]:
        req = urllib.request.Request(self.base_url + path,
                                     headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))

    # ------------------------------------------------------------------
    def _next_seq(self) -> int:
        """本租户事件序号：直接用内存连续水位，保证连续无缝。"""
        wm = self.router.watermarks()
        for w in wm:
            if w["tenant"] == self.tenant:
                return int(w["next_seq"])
        return 1

    def _emit(self, etype: str, phase: str, chain_id: str, occurred_at: str,
              payload: dict[str, Any], event_id: str | None = None) -> dict[str, Any]:
        seq = self._next_seq()
        event_id = event_id or f"{self.tenant}:{etype}:{chain_id}:{phase}:{seq}"
        return self.router.ingest_event({
            "event_id": event_id,
            "tenant": self.tenant,
            "type": etype,
            "phase": phase,
            "chain_id": chain_id,
            "seq": seq,
            "occurred_at": occurred_at,
            "payload": payload,
        })

    # ------------------------------------------------------------------
    # 单轮拉取（也可独立调用做测试/手动同步）
    # ------------------------------------------------------------------

    def poll_once(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        try:
            results.extend(self._poll_audit_tail())
            results.extend(self._poll_quarantine())
            results.extend(self._poll_status())
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            self.log(f"[subscriber] 轮询 {self.base_url} 失败: {exc}")
        return results

    def _poll_audit_tail(self) -> list[dict[str, Any]]:
        """跟进审计轨迹：新出现的 kind 翻译成对应事件。"""
        out = []
        # 拉最近 200 条，按 id 升序处理，游标之前的跳过
        data = self._get_json("/ops/audit-tail")
        entries = sorted(data.get("entries", []), key=lambda e: int(e["id"]))
        cursor_raw = self.router.store.get_kv(self.kv_audit_cursor)
        cursor = int(cursor_raw) if cursor_raw else 0
        max_id = cursor
        for e in entries:
            aid = int(e["id"])
            if aid <= cursor:
                continue
            max_id = max(max_id, aid)
            kind = e["kind"]
            at = self._epoch_to_iso(e.get("at"))
            detail = e.get("detail")
            if detail is None:
                # 复制器 /ops/audit-tail 返回 detail_json（JSON 字符串）
                raw = e.get("detail_json")
                detail = json.loads(raw) if raw else {}
            out.extend(self._map_audit_kind(aid, kind, at, detail))
        if max_id > cursor:
            self.router.store.set_kv(self.kv_audit_cursor, str(max_id))
        return out

    def _map_audit_kind(self, audit_id: int, kind: str, at: str,
                        detail: dict[str, Any]) -> list[dict[str, Any]]:
        out = []
        if kind in KIND_QUARANTINE:
            # 隔离事件：链 id 用复制器侧的稳定标识（segment 序号或失主纪元）
            target = detail.get("segment_index")
            if kind == "ownership_lost":
                chain = f"ownership-{detail.get('epoch') or audit_id}"
                summary = "复制器纪元失主：旧实例写入被围栏拒绝"
            else:
                chain = f"quar-seg-{target if target is not None else audit_id}"
                summary = f"分段隔离: {detail.get('reason')}"
            out.append(self._emit(
                QUARANTINE, PHASE_OPEN, chain, at,
                {"reason": detail.get("reason", kind),
                 "source": detail.get("source", "replicator"),
                 "segment_index": target,
                 "detail": detail, "summary": summary,
                 "upstream_audit_id": audit_id},
                event_id=f"{self.tenant}:q-open:{kind}:{audit_id}"))

        elif kind in KIND_TAKEOVER:
            epoch = detail.get("epoch") or detail.get("takeover_epoch") or audit_id
            chain = f"takeover-epoch-{epoch}"
            # 标记该 epoch 已由审计轨迹覆盖，状态轮询兜底不再补发
            try:
                self.router.store.set_kv(self.kv_prefix_audit_epoch(),
                                         str(epoch))
            except (TypeError, ValueError):
                pass
            # 接管在复制器语义里是“瞬时完成”的动作：发 OPEN 后立即发 RESOLVE，
            # 事件链完整，告警记录这次接管并随即进入 RECOVERED（保留可观测痕迹）
            out.append(self._emit(
                TAKEOVER, PHASE_OPEN, chain, at,
                {"epoch": epoch, "summary": f"复制器纪元提升接管: epoch={epoch}",
                 "detail": detail, "upstream_audit_id": audit_id},
                event_id=f"{self.tenant}:tk-open:{audit_id}"))
            out.append(self._emit(
                TAKEOVER, PHASE_RESOLVE, chain, at,
                {"epoch": epoch, "summary": "接管完成，新实例持有写入所有权",
                 "upstream_audit_id": audit_id},
                event_id=f"{self.tenant}:tk-resolve:{audit_id}"))

        elif kind in KIND_AUDIT_RUN:
            chain = f"audit-run-{audit_id}"
            ok = bool(detail.get("ok", True))
            out.append(self._emit(
                AUDIT, PHASE_OPEN, chain, at,
                {"ok": ok, "summary": detail.get("summary", "一致性审计完成"),
                 "detail": detail, "upstream_audit_id": audit_id},
                event_id=f"{self.tenant}:au-open:{audit_id}"))
            # 审计是一次“结果记录”，链在产生时即完整（自收口）
            out.append(self._emit(
                AUDIT, PHASE_RESOLVE, chain, at,
                {"ok": ok, "upstream_audit_id": audit_id},
                event_id=f"{self.tenant}:au-resolve:{audit_id}"))
        return out

    def _poll_quarantine(self) -> list[dict[str, Any]]:
        """隔离表消除标记 → QUARANTINE RESOLVE。"""
        out = []
        data = self._get_json("/ops/quarantine?include_resolved=1")
        records = data.get("records", [])
        seen_raw = self.router.store.get_kv(self.kv_quar_seen)
        seen: dict[str, dict[str, Any]] = json.loads(seen_raw) if seen_raw else {}
        changed = False
        for r in records:
            rid = str(r["id"])
            resolved_at = r.get("resolved_at")
            prev = seen.get(rid)
            # 新隔离的 OPEN 已由审计轨迹发出；这里只补 RESOLVE 与游标对齐
            if resolved_at and not (prev and prev.get("resolved_at")):
                target = r.get("segment_index")
                if r.get("reason") == "OWNERSHIP_LOST":
                    chain = f"ownership-{r.get('epoch') or rid}"
                else:
                    chain = f"quar-seg-{target if target is not None else rid}"
                out.append(self._emit(
                    QUARANTINE, PHASE_RESOLVE, chain,
                    self._epoch_to_iso(resolved_at),
                    {"resolution": r.get("resolution") or "缺口补齐后隔离自动消除",
                     "reason": r.get("reason"),
                     "summary": "隔离已消除",
                     "upstream_quarantine_id": rid},
                    event_id=f"{self.tenant}:q-resolve:{rid}"))
            seen[rid] = {"resolved_at": resolved_at,
                         "reason": r.get("reason")}
            changed = True
        if changed:
            self.router.store.set_kv(self.kv_quar_seen, json.dumps(seen,
                                                                   ensure_ascii=False))
        return out

    def _poll_status(self) -> list[dict[str, Any]]:
        """状态轮询：检测/消除 GAP（连续水位不成立）。

        epoch 接管以**审计轨迹**为权威来源；这里只做兜底：当审计轨迹
        不可用/漏发时才补发，并以 kv 中“已通过审计见过的 epoch 上界”
        去重，避免与审计轨迹重复。
        """
        out = []
        try:
            status = self._get_json("/ops/status")
        except Exception:  # noqa: BLE001
            return out
        self._last_status = status
        contiguous = bool(status.get("watermark_contiguous", True))
        epoch = status.get("authoritative_epoch") or status.get("epoch")
        confirmed = status.get("confirmed_index")

        seen_epoch_raw = self.router.store.get_kv(self.kv_epoch)
        audit_epoch_raw = self.router.store.get_kv(
            f"{self.kv_prefix_audit_epoch()}")
        seen_epoch = int(seen_epoch_raw) if seen_epoch_raw is not None else None
        audit_epoch = int(audit_epoch_raw) if audit_epoch_raw is not None else None

        if epoch is not None:
            # 记录审计轨迹已覆盖到的 epoch（_map_audit_kind 处理接管时写）
            if seen_epoch is None:
                # 首次启动：以当前 epoch 为基线，不补发历史接管
                self.router.store.set_kv(self.kv_epoch, str(epoch))
                seen_epoch = epoch
            elif int(epoch) > seen_epoch:
                already_via_audit = audit_epoch is not None \
                    and audit_epoch >= int(epoch)
                if not already_via_audit:
                    chain = f"takeover-epoch-{epoch}"
                    at = now_ts()
                    out.append(self._emit(
                        TAKEOVER, PHASE_OPEN, chain, at,
                        {"epoch": epoch, "via": "status-poll",
                         "summary": f"状态轮询发现纪元接管: epoch={epoch}"},
                        event_id=f"{self.tenant}:tk-status-open:{epoch}"))
                    out.append(self._emit(
                        TAKEOVER, PHASE_RESOLVE, chain, at,
                        {"epoch": epoch, "via": "status-poll"},
                        event_id=f"{self.tenant}:tk-status-resolve:{epoch}"))
                self.router.store.set_kv(self.kv_epoch, str(epoch))

        # GAP 链按“当前连续水位缺口”一条，恢复后同链 RESOLVE
        chain = "watermark-gap"
        gap_open_seen = self.router.store.get_kv(
            f"{self.kv_audit_cursor}:gap-open") == "1"
        if not contiguous and not gap_open_seen:
            out.append(self._emit(
                GAP, PHASE_OPEN, chain, now_ts(),
                {"confirmed_index": confirmed,
                 "summary": "复制器连续水位不成立（存在缺口/错序）",
                 "last_error": status.get("last_error")},
                event_id=f"{self.tenant}:gap-open:{confirmed}"))
            self.router.store.set_kv(f"{self.kv_audit_cursor}:gap-open", "1")
        elif contiguous and gap_open_seen:
            out.append(self._emit(
                GAP, PHASE_RESOLVE, chain, now_ts(),
                {"confirmed_index": confirmed,
                 "summary": "缺口已补齐，连续水位恢复"},
                event_id=f"{self.tenant}:gap-resolve:{confirmed}"))
            self.router.store.set_kv(f"{self.kv_audit_cursor}:gap-open", "0")
        return out

    def kv_prefix_audit_epoch(self) -> str:
        return f"subscriber:{self.tenant}:audit-seen-epoch"

    @staticmethod
    def _epoch_to_iso(value: Any) -> str:
        """复制器审计 at 是 epoch 秒（float）；转 ISO。"""
        if value is None:
            return now_ts()
        if isinstance(value, str):
            return value
        import datetime as _dt
        return _dt.datetime.fromtimestamp(float(value), _dt.timezone.utc) \
            .strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    # ------------------------------------------------------------------
    def start(self) -> None:
        if self._thread:
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="replica-subscriber", daemon=True)
        self._thread.start()
        self.log(f"[subscriber] 已启动：{self.base_url} 每 {self.poll_interval}s 轮询")

    def _run(self) -> None:
        while not self._stop.wait(self.poll_interval):
            try:
                self.poll_once()
            except Exception as exc:  # noqa: BLE001
                self.log(f"[subscriber] 轮询异常: {exc!r}")

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None
