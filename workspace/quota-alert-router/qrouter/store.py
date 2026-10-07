"""告警路由器持久化层（SQLite，事件溯源）。

事实来源是只追加的 ``journal``：每条入站事件、每条运维命令都先在一个事务里
落 journal（``jseq`` 全局自增），再由引擎折叠成各张物化表。重启恢复时清空
物化表、按 jseq 完整重放，内存状态与磁盘逐条等价——和复制器「磁盘重放==线上
截面」同一思路。

表布局：

    journal         事件/命令统一日志（jseq 有序，事件幂等键、命令幂等键唯一）
    alerts          告警聚合视图（按 租户+类型+chain 一条），version 乐观锁
    alert_events    进入告警链的全部事件（触发/收口/重传，保序）
    notifications   每次触发尝试（含被滑动窗口/静默抑制的），重启后窗口去重的依据
    stream_events   已接收的全部租户事件（含被水位挂起的），重建链与水位用
    tenants         租户连续水位 next_seq / 当前水位 event_id
    audit_log       只追加审计轨迹；dedup_key 唯一保证重放不重复落审计
    silences        静默规则物化（创建/撤销均来自 journal 命令）
    kv              订阅游标等杂项
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS journal (
    jseq            INTEGER PRIMARY KEY AUTOINCREMENT,
    kind            TEXT NOT NULL,              -- 'event' | 'command'
    event_id        TEXT,                       -- kind=event：幂等键
    cmd_key         TEXT,                       -- kind=command：幂等键（可空）
    tenant          TEXT,
    body_json       TEXT NOT NULL,
    ingested_at     TEXT NOT NULL,
    result_json     TEXT                        -- 命令首次执行结果（幂等重放回放）
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_journal_event
    ON journal(event_id) WHERE event_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_journal_cmd
    ON journal(cmd_key) WHERE cmd_key IS NOT NULL;

CREATE TABLE IF NOT EXISTS alerts (
    alert_id        TEXT PRIMARY KEY,
    tenant          TEXT NOT NULL,
    type            TEXT NOT NULL,
    chain_id        TEXT NOT NULL,
    status          TEXT NOT NULL,
    version         INTEGER NOT NULL DEFAULT 1,
    severity        TEXT NOT NULL DEFAULT 'warning',
    summary         TEXT NOT NULL DEFAULT '',
    backfilled      INTEGER NOT NULL DEFAULT 0, -- 是否由挂起事件补发
    occurrence_count INTEGER NOT NULL DEFAULT 1,
    first_event_id  TEXT NOT NULL,
    last_event_id   TEXT NOT NULL,
    opened_event_id TEXT,                       -- 最近一次 OPEN 事件
    resolved_event_id TEXT,
    silence_id      TEXT,
    opened_at       TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    acked_at        TEXT,
    acked_by        TEXT,
    recovered_at    TEXT,
    closed_at       TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_tenant ON alerts(tenant);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_fingerprint
    ON alerts(tenant, type, chain_id);

CREATE TABLE IF NOT EXISTS alert_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id        TEXT NOT NULL,
    event_id        TEXT NOT NULL UNIQUE,
    phase           TEXT NOT NULL,
    seq             INTEGER NOT NULL,
    occurred_at     TEXT NOT NULL,
    backfilled      INTEGER NOT NULL DEFAULT 0,
    payload_json    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS notifications (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id        TEXT NOT NULL,
    event_id        TEXT NOT NULL,
    kind            TEXT NOT NULL,              -- 'fired' | 'deduped' | 'suppressed' | 'resolved' | 'reopened'
    occurred_at     TEXT NOT NULL,
    note            TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS stream_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant          TEXT NOT NULL,
    seq             INTEGER NOT NULL,
    event_id        TEXT NOT NULL UNIQUE,
    type            TEXT NOT NULL,
    phase           TEXT NOT NULL,
    chain_id        TEXT NOT NULL,
    occurred_at     TEXT NOT NULL,
    held            INTEGER NOT NULL DEFAULT 1, -- 1=水位未连挂起；0=已释放
    payload_json    TEXT NOT NULL,
    UNIQUE(tenant, seq)
);
CREATE INDEX IF NOT EXISTS idx_stream_held ON stream_events(tenant, held);

CREATE TABLE IF NOT EXISTS tenants (
    tenant          TEXT PRIMARY KEY,
    next_seq        INTEGER NOT NULL DEFAULT 1, -- 连续水位：下一个期望序号
    watermark_event_id TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    at              TEXT NOT NULL,
    kind            TEXT NOT NULL,
    alert_id        TEXT,
    tenant          TEXT,
    actor           TEXT NOT NULL DEFAULT 'system',
    dedup_key       TEXT NOT NULL UNIQUE,
    detail_json     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_alert ON audit_log(alert_id);
CREATE INDEX IF NOT EXISTS idx_audit_tenant_kind ON audit_log(tenant, kind);

CREATE TABLE IF NOT EXISTS silences (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    silence_id      TEXT NOT NULL UNIQUE,
    tenant          TEXT,                       -- NULL=全局（全部租户）
    type            TEXT,                       -- NULL=该租户全部类型
    reason          TEXT NOT NULL DEFAULT '',
    created_by      TEXT NOT NULL DEFAULT 'operator',
    starts_at       TEXT NOT NULL,
    ends_at         TEXT,                       -- NULL=持续到人工撤销
    revoked_at      TEXT,
    created_via     TEXT NOT NULL DEFAULT 'command'
);
CREATE INDEX IF NOT EXISTS idx_silences_match ON silences(tenant, type);

CREATE TABLE IF NOT EXISTS kv (
    k               TEXT PRIMARY KEY,
    v               TEXT NOT NULL
);
"""

MATERIALIZED_TABLES = (
    "alerts", "alert_events", "notifications",
    "stream_events", "tenants", "audit_log", "silences",
)


class Store:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.RLock()
        first = not os.path.exists(path)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=FULL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(SCHEMA)
        self.conn.commit()
        self.first_time = first

    @property
    def lock(self) -> threading.RLock:
        return self._lock

    # ------------------------------------------------------------------
    # 基础工具
    # ------------------------------------------------------------------

    def transaction(self):
        return self.conn  # with self.conn: 即 BEGIN/COMMIT，异常回滚

    @staticmethod
    def dumps(obj: Any) -> str:
        return json.dumps(obj, ensure_ascii=False, sort_keys=True)

    @staticmethod
    def loads(s: str | None) -> Any:
        return json.loads(s) if s else None

    def max_jseq(self) -> int:
        r = self.conn.execute("SELECT COALESCE(MAX(jseq),0) FROM journal").fetchone()
        return int(r[0])

    def iter_journal(self, after_jseq: int = 0):
        rows = self.conn.execute(
            "SELECT * FROM journal WHERE jseq > ? ORDER BY jseq",
            (after_jseq,),
        )
        for r in rows:
            yield dict(r)

    def reset_materialized(self) -> None:
        """重放前清空全部物化表（journal 是事实来源，永不清除）。"""
        with self.conn:
            for t in MATERIALIZED_TABLES:
                self.conn.execute(f"DELETE FROM {t}")
            self.conn.execute("DELETE FROM sqlite_sequence WHERE name IN "
                              "('alerts','alert_events','notifications',"
                              "'stream_events','audit_log')")

    # ------------------------------------------------------------------
    # journal
    # ------------------------------------------------------------------

    def append_event_journal(self, event: dict[str, Any], ingested_at: str) -> tuple[int, bool]:
        """追加事件日志。返回 (jseq, 首次写入?)；event_id 重复返回既有行。"""
        with self.conn:
            row = self.conn.execute(
                "SELECT jseq FROM journal WHERE event_id = ?",
                (event["event_id"],),
            ).fetchone()
            if row:
                return int(row["jseq"]), False
            cur = self.conn.execute(
                "INSERT INTO journal (kind, event_id, tenant, body_json, ingested_at)"
                " VALUES ('event', ?, ?, ?, ?)",
                (event["event_id"], event["tenant"], self.dumps(event), ingested_at),
            )
            return int(cur.lastrowid), True

    def append_command_journal(self, command: str, body: dict[str, Any],
                               ingested_at: str, idem_key: str | None,
                               tenant: str | None = None) -> tuple[int, bool, dict | None]:
        """追加命令日志。返回 (jseq, 首次?, 首次执行结果)。

        带 idem_key 且重复：回放首次结果；无 key：每次都是新命令。
        """
        payload = {"command": command, **body}
        with self.conn:
            if idem_key:
                row = self.conn.execute(
                    "SELECT jseq, result_json FROM journal WHERE cmd_key = ?",
                    (idem_key,),
                ).fetchone()
                if row:
                    return int(row["jseq"]), False, self.loads(row["result_json"])
            cur = self.conn.execute(
                "INSERT INTO journal (kind, cmd_key, tenant, body_json, ingested_at)"
                " VALUES ('command', ?, ?, ?, ?)",
                (idem_key, tenant, self.dumps(payload), ingested_at),
            )
            return int(cur.lastrowid), True, None

    def set_command_result(self, jseq: int, result: dict[str, Any]) -> None:
        with self.conn:
            self.conn.execute("UPDATE journal SET result_json = ? WHERE jseq = ?",
                              (self.dumps(result), jseq))

    # ------------------------------------------------------------------
    # tenants / stream
    # ------------------------------------------------------------------

    def get_tenant(self, tenant: str) -> dict[str, Any] | None:
        r = self.conn.execute("SELECT * FROM tenants WHERE tenant = ?",
                              (tenant,)).fetchone()
        return dict(r) if r else None

    def ensure_tenant(self, tenant: str) -> dict[str, Any]:
        with self.conn:
            row = self.conn.execute("SELECT * FROM tenants WHERE tenant = ?",
                                    (tenant,)).fetchone()
            if not row:
                self.conn.execute(
                    "INSERT INTO tenants (tenant, next_seq) VALUES (?, 1)", (tenant,))
                row = self.conn.execute("SELECT * FROM tenants WHERE tenant = ?",
                                        (tenant,)).fetchone()
            return dict(row)

    def advance_watermark(self, tenant: str, next_seq: int, event_id: str) -> None:
        with self.conn:
            self.conn.execute(
                "UPDATE tenants SET next_seq = ?, watermark_event_id = ?"
                " WHERE tenant = ?", (next_seq, event_id, tenant))

    def insert_stream_event(self, event: dict[str, Any], held: bool) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT INTO stream_events"
                " (tenant, seq, event_id, type, phase, chain_id, occurred_at,"
                "  held, payload_json)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (event["tenant"], event["seq"], event["event_id"], event["type"],
                 event["phase"], event["chain_id"], event["occurred_at"],
                 1 if held else 0, self.dumps(event["payload"])),
            )

    def release_stream_event(self, tenant: str, seq: int) -> None:
        with self.conn:
            self.conn.execute(
                "UPDATE stream_events SET held = 0 WHERE tenant = ? AND seq = ?",
                (tenant, seq))

    def has_seq(self, tenant: str, seq: int) -> bool:
        r = self.conn.execute(
            "SELECT 1 FROM stream_events WHERE tenant = ? AND seq = ? LIMIT 1",
            (tenant, seq)).fetchone()
        return r is not None

    def held_events(self, tenant: str | None = None) -> list[dict[str, Any]]:
        if tenant:
            rows = self.conn.execute(
                "SELECT * FROM stream_events WHERE held = 1 AND tenant = ?"
                " ORDER BY seq", (tenant,))
        else:
            rows = self.conn.execute(
                "SELECT * FROM stream_events WHERE held = 1 ORDER BY tenant, seq")
        return [dict(r) for r in rows]

    def chain_type_of_held(self, tenant: str, chain_id: str) -> str | None:
        r = self.conn.execute(
            "SELECT type FROM stream_events WHERE tenant = ? AND chain_id = ? LIMIT 1",
            (tenant, chain_id)).fetchone()
        return r["type"] if r else None

    # ------------------------------------------------------------------
    # alerts
    # ------------------------------------------------------------------

    def get_alert(self, alert_id: str) -> dict[str, Any] | None:
        r = self.conn.execute("SELECT * FROM alerts WHERE alert_id = ?",
                              (alert_id,)).fetchone()
        return dict(r) if r else None

    def get_alert_by_chain(self, tenant: str, etype: str,
                           chain_id: str) -> dict[str, Any] | None:
        r = self.conn.execute(
            "SELECT * FROM alerts WHERE tenant = ? AND type = ? AND chain_id = ?",
            (tenant, etype, chain_id)).fetchone()
        return dict(r) if r else None

    def insert_alert(self, a: dict[str, Any]) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT INTO alerts (alert_id, tenant, type, chain_id, status, version,"
                " severity, summary, backfilled, occurrence_count, first_event_id,"
                " last_event_id, opened_event_id, resolved_event_id, silence_id,"
                " opened_at, updated_at, acked_at, acked_by, recovered_at, closed_at)"
                " VALUES (:alert_id,:tenant,:type,:chain_id,:status,:version,"
                "  :severity,:summary,:backfilled,:occurrence_count,:first_event_id,"
                "  :last_event_id,:opened_event_id,:resolved_event_id,:silence_id,"
                "  :opened_at,:updated_at,:acked_at,:acked_by,:recovered_at,:closed_at)",
                a)

    def update_alert(self, alert_id: str, fields: dict[str, Any]) -> None:
        if not fields:
            return
        cols = ", ".join(f"{k} = :{k}" for k in fields)
        with self.conn:
            self.conn.execute(
                f"UPDATE alerts SET {cols} WHERE alert_id = :alert_id",
                {**fields, "alert_id": alert_id})

    def cas_alert(self, alert_id: str, expected_version: int,
                  fields: dict[str, Any]) -> dict[str, Any] | None:
        """乐观条件更新：仅当 version 未变才成功，version +1。

        返回更新后的最新行；版本冲突（确认/恢复竞争的输家）返回 None。
        """
        fields = {**fields, "version": expected_version + 1}
        cols = ", ".join(f"{k} = :{k}" for k in fields)
        with self.conn:
            cur = self.conn.execute(
                f"UPDATE alerts SET {cols}"
                " WHERE alert_id = :alert_id AND version = :expected_version",
                {**fields, "alert_id": alert_id,
                 "expected_version": expected_version})
            if cur.rowcount == 0:
                return None
            row = self.conn.execute("SELECT * FROM alerts WHERE alert_id = ?",
                                    (alert_id,)).fetchone()
            return dict(row)

    def touch_alert(self, alert_id: str, event_id: str, updated_at: str,
                    increment: bool = True) -> None:
        sql = ("UPDATE alerts SET last_event_id = :e, updated_at = :u"
               + (", occurrence_count = occurrence_count + 1" if increment else "")
               + " WHERE alert_id = :a")
        with self.conn:
            self.conn.execute(sql, {"e": event_id, "u": updated_at, "a": alert_id})

    def insert_alert_event(self, alert_id: str, event: dict[str, Any],
                           backfilled: bool) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT OR IGNORE INTO alert_events"
                " (alert_id, event_id, phase, seq, occurred_at, backfilled,"
                "  payload_json)"
                " VALUES (?,?,?,?,?,?,?)",
                (alert_id, event["event_id"], event["phase"], event["seq"],
                 event["occurred_at"], 1 if backfilled else 0,
                 self.dumps(event["payload"])))

    def list_alert_events(self, alert_id: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM alert_events WHERE alert_id = ? ORDER BY seq, id",
            (alert_id,))
        return [dict(r) for r in rows]

    def list_alerts(self, tenant: str | None = None, etype: str | None = None,
                    status: str | None = None, limit: int = 500) -> list[dict[str, Any]]:
        sql = "SELECT * FROM alerts WHERE 1=1"
        args: list[Any] = []
        if tenant:
            sql += " AND tenant = ?"; args.append(tenant)
        if etype:
            sql += " AND type = ?"; args.append(etype)
        if status:
            sql += " AND status = ?"; args.append(status)
        sql += " ORDER BY updated_at DESC LIMIT ?"
        args.append(limit)
        return [dict(r) for r in self.conn.execute(sql, args)]

    # ------------------------------------------------------------------
    # notifications（也是滑动窗口去重的事实来源，重启后窗口仍然成立）
    # ------------------------------------------------------------------

    def add_notification(self, alert_id: str, event_id: str, kind: str,
                         occurred_at: str, note: str = "") -> None:
        with self.conn:
            self.conn.execute(
                "INSERT INTO notifications (alert_id, event_id, kind, occurred_at, note)"
                " VALUES (?,?,?,?,?)",
                (alert_id, event_id, kind, occurred_at, note))

    def notifications_since(self, alert_id: str, since_iso: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM notifications WHERE alert_id = ? AND occurred_at >= ?"
            " ORDER BY occurred_at", (alert_id, since_iso))
        return [dict(r) for r in rows]

    def list_notifications(self, alert_id: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM notifications WHERE alert_id = ? ORDER BY id",
            (alert_id,))
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # audit（append-only；dedup_key 唯一 => 重放绝不重复落审计）
    # ------------------------------------------------------------------

    def add_audit(self, at: str, kind: str, dedup_key: str,
                  detail: dict[str, Any], actor: str = "system",
                  alert_id: str | None = None,
                  tenant: str | None = None) -> bool:
        """幂等追加审计。dedup_key 已存在则忽略（重放/重复触发安全）。"""
        with self.conn:
            cur = self.conn.execute(
                "INSERT OR IGNORE INTO audit_log"
                " (at, kind, alert_id, tenant, actor, dedup_key, detail_json)"
                " VALUES (?,?,?,?,?,?,?)",
                (at, kind, alert_id, tenant, actor, dedup_key,
                 self.dumps(detail)))
            return cur.rowcount > 0

    def list_audit(self, limit: int = 100, kind: str | None = None,
                   alert_id: str | None = None, tenant: str | None = None,
                   after_id: int = 0, ascending: bool = False) -> list[dict[str, Any]]:
        where = ["id > ?"]
        args: list[Any] = [after_id]
        if kind:
            where.append("kind = ?"); args.append(kind)
        if alert_id:
            where.append("alert_id = ?"); args.append(alert_id)
        if tenant:
            where.append("tenant = ?"); args.append(tenant)
        sql = "SELECT * FROM audit_log WHERE " + " AND ".join(where)
        sql += " ORDER BY id " + ("ASC" if ascending else "DESC") + " LIMIT ?"
        args.append(limit)
        return [dict(r) for r in self.conn.execute(sql, args)]

    # ------------------------------------------------------------------
    # silences
    # ------------------------------------------------------------------

    def upsert_silence(self, s: dict[str, Any]) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT INTO silences (silence_id, tenant, type, reason, created_by,"
                "  starts_at, ends_at, revoked_at, created_via)"
                " VALUES (:silence_id,:tenant,:type,:reason,:created_by,"
                "  :starts_at,:ends_at,:revoked_at,:created_via)"
                " ON CONFLICT(silence_id) DO UPDATE SET"
                "  tenant=excluded.tenant, type=excluded.type, reason=excluded.reason,"
                "  created_by=excluded.created_by, starts_at=excluded.starts_at,"
                "  ends_at=excluded.ends_at, revoked_at=excluded.revoked_at",
                s)

    def get_silence(self, silence_id: str) -> dict[str, Any] | None:
        r = self.conn.execute("SELECT * FROM silences WHERE silence_id = ?",
                              (silence_id,)).fetchone()
        return dict(r) if r else None

    def list_silences(self, include_revoked: bool = False) -> list[dict[str, Any]]:
        sql = "SELECT * FROM silences"
        if not include_revoked:
            sql += " WHERE revoked_at IS NULL"
        sql += " ORDER BY id DESC"
        return [dict(r) for r in self.conn.execute(sql)]

    def active_silences(self, at_iso: str) -> list[dict[str, Any]]:
        """在 at 时刻有效（已开始、未撤销、未到期）的静默规则，按精确度升序。"""
        rows = self.conn.execute(
            "SELECT * FROM silences WHERE revoked_at IS NULL"
            " AND starts_at <= ? AND (ends_at IS NULL OR ends_at > ?)"
            " ORDER BY (tenant IS NOT NULL) DESC, (type IS NOT NULL) DESC, id",
            (at_iso, at_iso))
        return [dict(r) for r in rows]

    def expire_candidates(self, at_iso: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM silences WHERE revoked_at IS NULL"
            " AND ends_at IS NOT NULL AND ends_at <= ?", (at_iso,))
        return [dict(r) for r in rows]

    def alerts_silenced_by(self, silence_id: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM alerts WHERE status = 'SILENCED' AND silence_id = ?",
            (silence_id,))
        return [dict(r) for r in rows]

    def recovered_candidates(self, at_iso: str, ttl_seconds: float) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM alerts WHERE status = 'RECOVERED' AND recovered_at IS NOT NULL",
        )
        out = []
        for r in rows:
            from .models import parse_ts
            age = (parse_ts(at_iso) - parse_ts(r["recovered_at"])).total_seconds()
            if age >= ttl_seconds:
                out.append(dict(r))
        return out

    # ------------------------------------------------------------------
    # kv
    # ------------------------------------------------------------------

    def get_kv(self, k: str) -> str | None:
        r = self.conn.execute("SELECT v FROM kv WHERE k = ?", (k,)).fetchone()
        return r["v"] if r else None

    def set_kv(self, k: str, v: str) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT INTO kv (k, v) VALUES (?,?)"
                " ON CONFLICT(k) DO UPDATE SET v = excluded.v", (k, v))

    def close(self) -> None:
        self.conn.close()
