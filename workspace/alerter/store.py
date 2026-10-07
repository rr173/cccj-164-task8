"""告警路由器的 SQLite 持久化层。

一切状态转移都在 **BEGIN IMMEDIATE 事务** 内完成，并在**同一事务**写入
``audit_log``——确认与恢复并发相撞时，条件 UPDATE（``WHERE state IN (...)``）
保证全局只有一个赢家、只落一次状态、一条审计；输家看到既有终态后幂等返回。

表布局
======

| 表 | 内容 |
|---|---|
| ``meta`` | KV：每租户水位序号分配/连续水位、订阅游标、去重窗口参数 |
| ``events`` | 规范化事件原文（event_id 幂等键）、租户内水位序号、是否已应用 |
| ``gaps`` | 每租户连续水位缺口区间（检测/补齐时间） |
| ``chains`` | 异常事件链：角色集合、状态、是否已绑定告警 |
| ``alerts`` | 按租户+类型聚合的告警及状态机（活动键部分唯一索引） |
| ``alert_chains`` | 告警聚合了哪些链（一条告警可含多次同类异常） |
| ``alert_occurrences`` | 每次链触发的发生记录（是否已通知） |
| ``dedup_windows`` | 滑动去重窗口（锚定上次通知时间） |
| ``silence_rules`` | 静默规则（租户/类型/原因码 + TTL） |
| ``audit_log`` | 只追加审计轨迹：事件登记、缺口、每次状态转移 |
"""

from __future__ import annotations

import contextlib
import json
import sqlite3
import threading
import time
from typing import Any, Iterator

from . import models

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    event_id    TEXT PRIMARY KEY,
    tenant      TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    role        TEXT NOT NULL,
    chain_id    TEXT NOT NULL,
    seq         INTEGER NOT NULL,
    reason      TEXT NOT NULL DEFAULT '',
    payload_json TEXT NOT NULL DEFAULT '{}',
    audit_ref   TEXT,
    occurred_at REAL,
    received_at REAL NOT NULL,
    applied     INTEGER NOT NULL DEFAULT 0,
    applied_at  REAL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_events_tenant_seq
    ON events(tenant, seq);
CREATE INDEX IF NOT EXISTS idx_events_tenant_applied_seq
    ON events(tenant, applied, seq);

CREATE TABLE IF NOT EXISTS gaps (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant      TEXT NOT NULL,
    gap_from    INTEGER NOT NULL,
    gap_to      INTEGER,
    detected_at REAL NOT NULL,
    filled_at   REAL,
    resolution  TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_gaps_tenant_from
    ON gaps(tenant, gap_from);

CREATE TABLE IF NOT EXISTS chains (
    chain_id    TEXT PRIMARY KEY,
    tenant      TEXT NOT NULL,
    event_type  TEXT,
    status      TEXT NOT NULL DEFAULT 'WITNESSED',
    alert_id    TEXT,
    saw_begin   INTEGER NOT NULL DEFAULT 0,
    saw_end     INTEGER NOT NULL DEFAULT 0,
    witnesses   INTEGER NOT NULL DEFAULT 0,
    last_reason TEXT NOT NULL DEFAULT '',
    created_at  REAL NOT NULL,
    updated_at  REAL NOT NULL,
    closed_at   REAL,
    fired_at    REAL
);
CREATE INDEX IF NOT EXISTS idx_chains_alert ON chains(alert_id);

CREATE TABLE IF NOT EXISTS alerts (
    id                 TEXT PRIMARY KEY,
    tenant             TEXT NOT NULL,
    alert_type         TEXT NOT NULL,
    status             TEXT NOT NULL,
    summary            TEXT NOT NULL DEFAULT '',
    occurrence_count   INTEGER NOT NULL DEFAULT 0,
    last_chain_id      TEXT,
    last_reason        TEXT NOT NULL DEFAULT '',
    created_at         REAL NOT NULL,
    updated_at         REAL NOT NULL,
    first_fired_at     REAL,
    last_notified_at   REAL,
    resolved_at        REAL,
    resolved_reason    TEXT NOT NULL DEFAULT '',
    closed_at          REAL,
    silence_rule_id    TEXT,
    pre_silence_state  TEXT
);
-- 同一租户+类型同时至多一条活动告警（聚合约束 / upsert 事实依据）
CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_active
    ON alerts(tenant, alert_type)
    WHERE status IN ('FIRING','ACKED','SILENCED');

CREATE TABLE IF NOT EXISTS alert_chains (
    alert_id TEXT NOT NULL,
    chain_id TEXT NOT NULL,
    PRIMARY KEY (alert_id, chain_id)
);

CREATE TABLE IF NOT EXISTS alert_occurrences (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id  TEXT NOT NULL,
    chain_id  TEXT NOT NULL,
    seq       INTEGER,
    event_id  TEXT NOT NULL,
    reason    TEXT NOT NULL DEFAULT '',
    at        REAL NOT NULL,
    notified  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS dedup_windows (
    tenant         TEXT NOT NULL,
    alert_type     TEXT NOT NULL,
    fingerprint    TEXT NOT NULL,
    window_seconds INTEGER NOT NULL,
    anchor_at      REAL NOT NULL,
    expires_at     REAL NOT NULL,
    PRIMARY KEY (tenant, alert_type, fingerprint)
);

CREATE TABLE IF NOT EXISTS silence_rules (
    id           TEXT PRIMARY KEY,
    tenant       TEXT NOT NULL,
    alert_type   TEXT,
    reason       TEXT,
    note         TEXT NOT NULL DEFAULT '',
    created_by   TEXT NOT NULL DEFAULT '',
    ttl_seconds  INTEGER,
    created_at   REAL NOT NULL,
    expires_at   REAL
);
CREATE INDEX IF NOT EXISTS idx_silence_match
    ON silence_rules(tenant, alert_type);

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    at          REAL NOT NULL,
    kind        TEXT NOT NULL,
    detail_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_kind ON audit_log(kind);
"""


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


class AlertStore:
    """单文件 SQLite 存储。线程安全（进程内 RLock）；跨进程靠条件更新。"""

    def __init__(self, path: str = ":memory:"):
        self.path = path
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(
            path, check_same_thread=False, isolation_level=None
        )
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA busy_timeout=6000")
        self.conn.execute("PRAGMA foreign_keys=ON")
        with self.lock, self.conn:
            self.conn.executescript(SCHEMA)

    def close(self) -> None:
        with self.lock:
            self.conn.close()

    # ------------------------------------------------------------------
    # 事务
    # ------------------------------------------------------------------

    @contextlib.contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """BEGIN IMMEDIATE：立即拿写锁，把“检查 + 条件更新 + 审计”变成原子步骤。"""
        with self.lock:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                yield self.conn
            except Exception:
                self.conn.execute("ROLLBACK")
                raise
            else:
                self.conn.execute("COMMIT")

    # ------------------------------------------------------------------
    # meta / 审计
    # ------------------------------------------------------------------

    def get_meta(self, key: str, default: Any = None) -> Any:
        row = self.conn.execute(
            "SELECT value FROM meta WHERE key=?", (key,)
        ).fetchone()
        return json.loads(row["value"]) if row else default

    def set_meta(self, key: str, value: Any) -> None:
        self.conn.execute(
            "INSERT INTO meta(key,value) VALUES(?,?)"
            " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, canonical(value)),
        )

    def audit(self, kind: str, detail: dict[str, Any]) -> int:
        cur = self.conn.execute(
            "INSERT INTO audit_log(at, kind, detail_json) VALUES(?,?,?)",
            (time.time(), kind, canonical(detail)),
        )
        return int(cur.lastrowid)

    def list_audit(self, limit: int = 100, kind: str | None = None,
                   after_id: int = 0) -> list[dict[str, Any]]:
        if kind:
            rows = self.conn.execute(
                "SELECT id, at, kind, detail_json FROM audit_log"
                " WHERE id > ? AND kind = ? ORDER BY id DESC LIMIT ?",
                (after_id, kind, limit),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT id, at, kind, detail_json FROM audit_log"
                " WHERE id > ? ORDER BY id DESC LIMIT ?",
                (after_id, limit),
            ).fetchall()
        out = []
        for r in rows:
            d = json.loads(r["detail_json"])
            out.append({"id": r["id"], "at": r["at"], "kind": r["kind"], "detail": d})
        return out

    # ------------------------------------------------------------------
    # 事件登记 / 水位
    # ------------------------------------------------------------------

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM events WHERE event_id=?", (event_id,)
        ).fetchone()
        return self._event_row(row) if row else None

    @staticmethod
    def _event_row(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        d["payload"] = json.loads(d.pop("payload_json") or "{}")
        d["applied"] = bool(d["applied"])
        return d

    def _alloc_seq(self, conn: sqlite3.Connection, tenant: str) -> int:
        """为未显式携带 seq 的事件分配稠密水位序号。

        始终取该租户已见最大序号 +1：自动序号排在显式序号之后，既不会与
        显式序号相撞，重启后也不会因丢失计数器而重号（事实来源是 events 表
        本身）。若显式序号曾跳号，恢复连续性的责任在显式生产方（订阅器
        始终走自动分配，天然不会跳号）。
        """
        max_row = conn.execute(
            "SELECT COALESCE(MAX(seq),0) AS m FROM events WHERE tenant=?",
            (tenant,),
        ).fetchone()
        return int(max_row["m"]) + 1

    def register_event(self, ev: dict[str, Any], now: float) -> tuple[dict[str, Any], bool]:
        """登记一条规范化事件。返回 ``(event_row, duplicate)``。

        同 ``event_id`` 重复投递（同事件幂等）直接返回已存行，不占新序号、
        不重复触发；不同事件占用同一 ``(tenant, seq)`` 是序号分叉，409 拒绝。
        """
        existing = self.get_event(ev["event_id"])
        if existing is not None:
            return existing, True
        seq = ev["seq"] or self._alloc_seq(self.conn, ev["tenant"])
        try:
            self.conn.execute(
                "INSERT INTO events(event_id,tenant,event_type,role,chain_id,seq,"
                " reason,payload_json,audit_ref,occurred_at,received_at,applied)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,0)",
                (ev["event_id"], ev["tenant"], ev["event_type"], ev["role"],
                 ev["chain_id"], seq, ev.get("reason") or "",
                 canonical(ev.get("payload") or {}), ev.get("audit_ref"),
                 ev.get("occurred_at"), now),
            )
        except sqlite3.IntegrityError as exc:
            raise models.AlertError(
                "SEQ_CONFLICT",
                f"租户 {ev['tenant']} 的水位序号 {seq} 已被另一事件占用"
                f"（{ev['event_id']}）", 409,
                details={"tenant": ev["tenant"], "seq": seq},
            ) from exc
        return self.get_event(ev["event_id"]), False  # type: ignore[return-value]

    def mark_event_applied(self, event_id: str, now: float) -> None:
        self.conn.execute(
            "UPDATE events SET applied=1, applied_at=? WHERE event_id=? AND applied=0",
            (now, event_id),
        )

    def next_due_event(self, tenant: str, next_seq: int) -> dict[str, Any] | None:
        """连续水位闸门：只取“恰好等于下一个序号”的未应用事件。"""
        row = self.conn.execute(
            "SELECT * FROM events WHERE tenant=? AND seq=? AND applied=0",
            (tenant, next_seq),
        ).fetchone()
        return self._event_row(row) if row else None

    def contiguous_until(self, tenant: str) -> int:
        """该租户连续水位：已应用序号恰好覆盖 1..N 的最大 N。"""
        rows = self.conn.execute(
            "SELECT seq FROM events WHERE tenant=? AND applied=1 ORDER BY seq",
            (tenant,),
        ).fetchall()
        expect = 1
        for r in rows:
            if int(r["seq"]) == expect:
                expect += 1
            elif int(r["seq"]) > expect:
                break
        return expect - 1

    def known_tenants(self) -> list[str]:
        rows = self.conn.execute(
            "SELECT DISTINCT tenant FROM events ORDER BY tenant"
        ).fetchall()
        return [r["tenant"] for r in rows]

    # ------------------------------------------------------------------
    # 水位缺口
    # ------------------------------------------------------------------

    def ensure_gap(self, tenant: str, gap_from: int, now: float,
                   detail: dict[str, Any]) -> bool:
        """登记一个起点缺口区间；已存在则不重复审计。返回是否新缺口。"""
        cur = self.conn.execute(
            "INSERT INTO gaps(tenant,gap_from,detected_at) VALUES(?,?,?)"
            " ON CONFLICT(tenant,gap_from) DO NOTHING",
            (tenant, gap_from, now),
        )
        return cur.rowcount > 0

    def fill_gaps_until(self, tenant: str, from_after: int, filled_until: int,
                        now: float, resolution: str) -> list[int]:
        """连续水位从 ``from_after`` 推进到 ``filled_until``：关闭本次新覆盖的缺口。

        只匹配 ``from_after < gap_from <= filled_until`` 的开放缺口，避免把
        早已被更高水位覆盖的缺口区间反复标记/审计。
        """
        before = {int(r[0]) for r in self.conn.execute(
            "SELECT id FROM gaps WHERE tenant=? AND filled_at IS NULL"
            " AND gap_from > ? AND gap_from <= ?",
            (tenant, from_after, filled_until),
        ).fetchall()}
        if not before:
            return []
        self.conn.execute(
            "UPDATE gaps SET filled_at=?, resolution=?"
            " WHERE tenant=? AND filled_at IS NULL"
            " AND gap_from > ? AND gap_from <= ?",
            (now, resolution, tenant, from_after, filled_until),
        )
        return sorted(before)

    def list_gaps(self, tenant: str | None = None, include_filled: bool = False,
                  limit: int = 200) -> list[dict[str, Any]]:
        sql = "SELECT * FROM gaps WHERE 1=1"
        args: list[Any] = []
        if tenant:
            sql += " AND tenant=?"
            args.append(tenant)
        if not include_filled:
            sql += " AND filled_at IS NULL"
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        return [dict(r) for r in self.conn.execute(sql, args).fetchall()]

    # ------------------------------------------------------------------
    # 事件链
    # ------------------------------------------------------------------

    def get_chain(self, chain_id: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM chains WHERE chain_id=?", (chain_id,)
        ).fetchone()
        return dict(row) if row else None

    def ensure_chain(self, chain_id: str, tenant: str,
                     event_type: str | None, now: float) -> dict[str, Any]:
        """取链或按首个角色事件建链。类型冲突按数据分叉拒绝。"""
        chain = self.get_chain(chain_id)
        if chain is None:
            # 新链统一从 WITNESSED（只见见证）/OPEN 起步没有意义：
            # 第一个角色事件的标记动作（chain_mark_role）决定链状态。
            self.conn.execute(
                "INSERT INTO chains(chain_id,tenant,event_type,status,"
                " created_at,updated_at) VALUES(?,?,?,?,?,?)",
                (chain_id, tenant, event_type, models.CHAIN_WITNESSED, now, now),
            )
            chain = self.get_chain(chain_id)
            return chain  # type: ignore[return-value]
        if chain["tenant"] != tenant:
            raise models.AlertError(
                "CHAIN_TENANT_CONFLICT",
                f"链 {chain_id} 已属于租户 {chain['tenant']}，"
                f"不能再挂到 {tenant}", 409)
        if event_type and chain["event_type"] and chain["event_type"] != event_type:
            raise models.AlertError(
                "CHAIN_TYPE_CONFLICT",
                f"链 {chain_id} 的类型冲突：已有 {chain['event_type']}，"
                f"又收到 {event_type}", 409,
                details={"chain_id": chain_id,
                         "existing": chain["event_type"], "received": event_type})
        if not chain["event_type"] and event_type:
            # 审计见证先到、BEGIN 后到：此刻链才有类型（OPEN 由角色标记负责）
            self.conn.execute(
                "UPDATE chains SET event_type=?, updated_at=?"
                " WHERE chain_id=? AND event_type IS NULL",
                (event_type, now, chain_id),
            )
            chain = self.get_chain(chain_id)
        return chain  # type: ignore[return-value]

    def chain_mark_role(self, chain_id: str, role: str, reason: str,
                        now: float) -> None:
        if role == models.BEGIN:
            # BORN_CLOSED（先 END、BEGIN 仍在缺口后才到）是终态：
            # 补到的 BEGIN 只记录角色事实，绝不把链复活成 OPEN 再误报。
            self.conn.execute(
                "UPDATE chains SET saw_begin=1,"
                " status=CASE WHEN status=? THEN status ELSE ? END,"
                " last_reason=?, updated_at=? WHERE chain_id=?",
                (models.CHAIN_BORN_CLOSED, models.CHAIN_OPEN,
                 reason or "", now, chain_id),
            )
        elif role == models.END:
            self.conn.execute(
                "UPDATE chains SET saw_end=1, status=?, closed_at=?, updated_at=?"
                " WHERE chain_id=?",
                (models.CHAIN_CLOSED, now, now, chain_id),
            )
        else:  # WITNESS
            self.conn.execute(
                "UPDATE chains SET witnesses=witnesses+1, updated_at=?"
                " WHERE chain_id=?",
                (now, chain_id),
            )

    def chain_bind_alert(self, chain_id: str, alert_id: str, now: float) -> None:
        self.conn.execute(
            "UPDATE chains SET alert_id=?, fired_at=?, updated_at=?"
            " WHERE chain_id=?",
            (alert_id, now, now, chain_id),
        )
        self.conn.execute(
            "INSERT OR IGNORE INTO alert_chains(alert_id,chain_id) VALUES(?,?)",
            (alert_id, chain_id),
        )

    def chain_mark_born_closed(self, chain_id: str, now: float) -> None:
        """未触发即终态：BEGIN 还在缺口后时 END 已到，链静默关闭，不补发。"""
        self.conn.execute(
            "UPDATE chains SET status=?, closed_at=COALESCE(closed_at,?),"
            " updated_at=? WHERE chain_id=?",
            (models.CHAIN_BORN_CLOSED, now, now, chain_id),
        )

    def open_chain_count(self, alert_id: str) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) AS c FROM alert_chains ac JOIN chains c"
            " ON ac.chain_id=c.chain_id"
            " WHERE ac.alert_id=? AND c.status=?",
            (alert_id, models.CHAIN_OPEN),
        ).fetchone()
        return int(row["c"])

    def list_chains(self, tenant: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        if tenant:
            rows = self.conn.execute(
                "SELECT * FROM chains WHERE tenant=? ORDER BY updated_at DESC LIMIT ?",
                (tenant, limit),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM chains ORDER BY updated_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def chains_for_alert(self, alert_id: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT c.* FROM chains c JOIN alert_chains ac"
            " ON c.chain_id=ac.chain_id WHERE ac.alert_id=?"
            " ORDER BY c.created_at",
            (alert_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # 告警
    # ------------------------------------------------------------------

    def find_active_alert(self, tenant: str, alert_type: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM alerts WHERE tenant=? AND alert_type=? AND status IN (?,?,?)",
            (tenant, alert_type, *models.ACTIVE_STATES),
        ).fetchone()
        return dict(row) if row else None

    def create_alert(self, alert: dict[str, Any]) -> None:
        self.conn.execute(
            "INSERT INTO alerts(id,tenant,alert_type,status,summary,occurrence_count,"
            " last_chain_id,last_reason,created_at,updated_at,first_fired_at,"
            " last_notified_at,silence_rule_id,pre_silence_state)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (alert["id"], alert["tenant"], alert["alert_type"], alert["status"],
             alert.get("summary", ""), alert.get("occurrence_count", 1),
             alert.get("last_chain_id"), alert.get("last_reason", ""),
             alert["created_at"], alert["updated_at"], alert.get("first_fired_at"),
             alert.get("last_notified_at"), alert.get("silence_rule_id"),
             alert.get("pre_silence_state")),
        )

    def transition_alert(self, alert_id: str, allowed_from: tuple[str, ...],
                         new_state: str, now: float,
                         fields: dict[str, Any] | None = None) -> bool:
        """条件状态转移：仅当当前状态 ∈ allowed_from 时生效。

        确认与恢复并发相撞时只有一个事务赢得这次 UPDATE（rowcount=1），
        输家不改状态、由调用方按既有状态幂等返回。
        """
        sets = ["status=?", "updated_at=?"]
        args: list[Any] = [new_state, now]
        for k, v in (fields or {}).items():
            sets.append(f"{k}=?")
            args.append(v)
        placeholders = ",".join("?" for _ in allowed_from)
        args.extend([alert_id, *allowed_from])
        cur = self.conn.execute(
            f"UPDATE alerts SET {', '.join(sets)}"
            f" WHERE id=? AND status IN ({placeholders})",
            args,
        )
        return cur.rowcount == 1

    def add_occurrence(self, alert_id: str, chain_id: str, seq: int | None,
                       event_id: str, reason: str, now: float, notified: bool) -> None:
        self.conn.execute(
            "INSERT INTO alert_occurrences(alert_id,chain_id,seq,event_id,reason,at,notified)"
            " VALUES(?,?,?,?,?,?,?)",
            (alert_id, chain_id, seq, event_id, reason, now, 1 if notified else 0),
        )
        self.conn.execute(
            "UPDATE alerts SET occurrence_count=occurrence_count+1,"
            " last_chain_id=?, last_reason=?, updated_at=? WHERE id=?",
            (chain_id, reason, now, alert_id),
        )

    def occurrences_for_alert(self, alert_id: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM alert_occurrences WHERE alert_id=? ORDER BY id",
            (alert_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_alert(self, alert_id: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM alerts WHERE id=?", (alert_id,)
        ).fetchone()
        return dict(row) if row else None

    def list_alerts(self, tenant: str | None = None, status: str | None = None,
                    alert_type: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        sql = "SELECT * FROM alerts WHERE 1=1"
        args: list[Any] = []
        if tenant:
            sql += " AND tenant=?"
            args.append(tenant)
        if status:
            sql += " AND status=?"
            args.append(status)
        elif status is None:
            pass
        if alert_type:
            sql += " AND alert_type=?"
            args.append(alert_type)
        sql += " ORDER BY created_at DESC, id DESC LIMIT ?"
        args.append(limit)
        return [dict(r) for r in self.conn.execute(sql, args).fetchall()]

    # ------------------------------------------------------------------
    # 滑动窗口去重
    # ------------------------------------------------------------------

    def get_open_window(self, tenant: str, alert_type: str, fingerprint: str,
                        now: float) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM dedup_windows WHERE tenant=? AND alert_type=? AND fingerprint=?"
            " AND expires_at > ?",
            (tenant, alert_type, fingerprint, now),
        ).fetchone()
        return dict(row) if row else None

    def anchor_window(self, tenant: str, alert_type: str, fingerprint: str,
                      window_seconds: int, now: float) -> None:
        """以“本次通知时刻”为新锚点开启/重置滑动窗口。

        去重命中（仅抑制通知）不调用本方法——窗口不被抑制事件滑动延长，
        窗口始终从**上次真正通知**起算 window_seconds。
        """
        self.conn.execute(
            "INSERT INTO dedup_windows(tenant,alert_type,fingerprint,window_seconds,"
            " anchor_at,expires_at) VALUES(?,?,?,?,?,?)"
            " ON CONFLICT(tenant,alert_type,fingerprint) DO UPDATE SET"
            " window_seconds=excluded.window_seconds, anchor_at=excluded.anchor_at,"
            " expires_at=excluded.expires_at",
            (tenant, alert_type, fingerprint, window_seconds,
             now, now + window_seconds),
        )

    def prune_windows(self, now: float) -> int:
        return int(self.conn.execute(
            "DELETE FROM dedup_windows WHERE expires_at <= ?", (now,)
        ).rowcount)

    # ------------------------------------------------------------------
    # 静默规则
    # ------------------------------------------------------------------

    def create_silence_rule(self, rule: dict[str, Any]) -> None:
        self.conn.execute(
            "INSERT INTO silence_rules(id,tenant,alert_type,reason,note,created_by,"
            " ttl_seconds,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (rule["id"], rule["tenant"], rule.get("alert_type"), rule.get("reason"),
             rule.get("note", ""), rule.get("created_by", ""),
             rule.get("ttl_seconds"), rule["created_at"], rule.get("expires_at")),
        )

    def get_silence_rule(self, rule_id: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM silence_rules WHERE id=?", (rule_id,)
        ).fetchone()
        return dict(row) if row else None

    def list_silence_rules(self, tenant: str | None = None,
                           active_only: bool = False, now: float | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM silence_rules WHERE 1=1"
        args: list[Any] = []
        if tenant:
            sql += " AND tenant=?"
            args.append(tenant)
        if active_only:
            sql += " AND (expires_at IS NULL OR expires_at > ?)"
            args.append(now if now is not None else time.time())
        sql += " ORDER BY created_at DESC"
        return [dict(r) for r in self.conn.execute(sql, args).fetchall()]

    def delete_silence_rule_if_exists(self, rule_id: str) -> bool:
        cur = self.conn.execute(
            "DELETE FROM silence_rules WHERE id=?", (rule_id,)
        )
        return cur.rowcount == 1

    def match_silence_rule(self, tenant: str, alert_type: str, reason: str,
                           now: float) -> dict[str, Any] | None:
        """匹配当前生效的静默规则：租户相等；类型/原因为空=通配，否则精确相等。

        多条命中时优先最具体（带原因码 > 带类型 > 纯租户），同级取最近创建。
        """
        rows = self.conn.execute(
            "SELECT * FROM silence_rules WHERE tenant=?"
            " AND (alert_type IS NULL OR alert_type=?) AND (reason IS NULL OR reason=?)"
            " AND (expires_at IS NULL OR expires_at > ?)"
            " ORDER BY (reason IS NOT NULL) DESC, (alert_type IS NOT NULL) DESC,"
            " created_at DESC",
            (tenant, alert_type, reason, now),
        ).fetchall()
        return dict(rows[0]) if rows else None

    def alerts_silenced_by(self, rule_id: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM alerts WHERE silence_rule_id=? AND status=?",
            (rule_id, models.ST_SILENCED),
        ).fetchall()
        return [dict(r) for r in rows]

    def alerts_with_expired_silence(self, now: float) -> list[dict[str, Any]]:
        """静默已到期但告警仍停在 SILENCED 的告警（sweeper 恢复它们）。"""
        rows = self.conn.execute(
            "SELECT a.* FROM alerts a JOIN silence_rules s ON a.silence_rule_id=s.id"
            " WHERE a.status=? AND s.expires_at IS NOT NULL AND s.expires_at <= ?",
            (models.ST_SILENCED, now),
        ).fetchall()
        return [dict(r) for r in rows]

    def alerts_with_vanished_silence(self) -> list[dict[str, Any]]:
        """静默规则被删除但告警仍停在 SILENCED 的告警。"""
        rows = self.conn.execute(
            "SELECT a.* FROM alerts a LEFT JOIN silence_rules s"
            " ON a.silence_rule_id=s.id WHERE a.status=? AND s.id IS NULL",
            (models.ST_SILENCED,),
        ).fetchall()
        return [dict(r) for r in rows]
