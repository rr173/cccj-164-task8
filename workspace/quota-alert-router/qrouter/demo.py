"""演示数据：覆盖触发、缺口挂起/补发/静默关闭、重传去重、静默与恢复全流程。

``seed_demo`` 直接写引擎（离线建库）；``push_demo_events`` 通过 HTTP 注入
到运行实例。
"""

from __future__ import annotations

import json
import urllib.request

from .models import (
    AUDIT, GAP, QUARANTINE, TAKEOVER,
    PHASE_OPEN, PHASE_RESOLVE, to_ts,
)
from datetime import datetime, timedelta, timezone


def _iso(minutes_from_now: float) -> str:
    base = datetime.now(timezone.utc) + timedelta(minutes=minutes_from_now)
    return to_ts(base)


def demo_events() -> list[dict]:
    """构造一组确定的演示事件。序号刻意制造两个缺口场景。"""
    events = []

    def ev(eid, tenant, etype, phase, chain, seq, at, **payload):
        events.append({"event_id": eid, "tenant": tenant, "type": etype,
                       "phase": phase, "chain_id": chain, "seq": seq,
                       "occurred_at": at, "payload": payload})

    # 租户 t-a：完整链（隔离 OPEN→RESOLVE）+ 窗口内重传
    ev("a-q1-open", "t-a", QUARANTINE, PHASE_OPEN, "seg-101", 1, _iso(0),
       reason="EVENT_HASH_BROKEN", segment_index=101,
       summary="分段 101 事件哈希链断裂，已隔离")
    ev("a-q1-open-rexmit", "t-a", QUARANTINE, PHASE_OPEN, "seg-101", 2, _iso(0.01),
       reason="EVENT_HASH_BROKEN", segment_index=101,
       summary="分段 101 隔离（上游重传）")
    ev("a-q1-resolve", "t-a", QUARANTINE, PHASE_RESOLVE, "seg-101", 3, _iso(0.02),
       resolution="主站重发正确分段，隔离消除")

    # 租户 t-a：接管链（瞬时 OPEN/RESOLVE，活动期极短）
    ev("a-tk-open", "t-a", TAKEOVER, PHASE_OPEN, "epoch-7", 4, _iso(0.03),
       epoch=7, summary="滚动升级：新实例提升 epoch=7")
    ev("a-tk-resolve", "t-a", TAKEOVER, PHASE_RESOLVE,
       "epoch-7", 5, _iso(0.04), epoch=7, summary="接管完成")

    # 租户 t-b：先到 seq 4（缺 1..3），全部挂起；随后补齐 1..5
    # OPEN(1) 与 RESOLVE(2) 在补齐同批释放 → 静默关闭，无告警
    ev("b-gap-resolve-early", "t-b", GAP, PHASE_RESOLVE, "gap-1", 2, _iso(0),
       summary="（乱序）缺口恢复事件先到")
    ev("b-audit-open", "t-b", AUDIT, PHASE_OPEN, "run-55", 4, _iso(0.01),
       ok=False, summary="（乱序）一致性审计发现偏差")
    ev("b-gap-open", "t-b", GAP, PHASE_OPEN, "gap-1", 1, _iso(0.02),
       missing=[3, 4], summary="水位缺口 seq 3-4")
    ev("b-audit-missing", "t-b", AUDIT, PHASE_RESOLVE, "run-55", 3, _iso(0.03),
       ok=False, summary="审计链收口")
    ev("b-audit-open-2", "t-b", AUDIT, PHASE_OPEN, "run-55", 5, _iso(0.04),
       ok=False, summary="审计再次发现偏差（缺口补齐后补发的活动告警）")

    # 租户 t-c：隔离 OPEN 后长时间不恢复（用于演示确认/静默）
    ev("c-q-open", "t-c", QUARANTINE, PHASE_OPEN, "seg-209", 1, _iso(0),
       reason="LAG_OVER_LIMIT", segment_index=209,
       summary="复制落后超阈值，进入 LAG_OVER_LIMIT 隔离")
    ev("c-q-open-rexmit2", "t-c", QUARANTINE, PHASE_OPEN, "seg-209", 2,
       _iso(0.5), reason="LAG_OVER_LIMIT", segment_index=209,
       summary="仍在隔离中（超过去重窗口后的再次通知）")
    return events


def seed_demo(router) -> dict:
    results = router.ingest_batch(demo_events())
    return {"ingested": len(results), "results": results}


def push_demo_events(base_url: str) -> None:
    base_url = base_url.rstrip("/")
    payload = json.dumps({"events": demo_events()}, ensure_ascii=False).encode()
    req = urllib.request.Request(
        base_url + "/api/events/batch", data=payload,
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read().decode())
    print(json.dumps(data, ensure_ascii=False, indent=2))
