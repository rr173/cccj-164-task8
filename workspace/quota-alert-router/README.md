# 配额灾备异常告警路由器（qrouter）

订阅只读灾备**复制器**（`../replica`）的隔离、接管、缺口与审计信号，按
**租户 × 事件类型 × 事件链**聚合成告警，提供确认、静默、恢复、查询接口与
运维页面。纯 Python 3.11 标准库，零外部依赖，单一 SQLite 为事实来源。

```
复制器 replica（隔离/纪元接管/连续水位/审计轨迹）
   /ops/audit-tail · /ops/quarantine · /ops/status
                     │ 轮询订阅（游标持久化，去重）
                     ▼
        ReplicaSubscriber  →  统一四类事件
                     │
                     ▼
   POST /api/events  →  AlertRouter（连续水位准入 → 事件链折叠 → 告警状态机）
                     │
   SQLite: journal（事件溯源事实源）+ alerts/notifications/silences/audit…
                     │
   GET 运维查询 · POST ack/silence/recover/close · 运维页面 /
```

## 四类事件与两阶段事件链

| 类型 | 复制器来源 | 含义 |
|---|---|---|
| `QUARANTINE` | 审计 `segment_quarantined` / `ownership_lost`，隔离表 `resolved_at` | 分段被隔离 / 失主写入被拒；消除后收口 |
| `TAKEOVER` | 审计 `replicator_started`，status 纪元变化兜底 | 进程纪元提升、接管写入所有权（滚动升级） |
| `GAP` | `/ops/status.watermark_contiguous` | 连续水位不成立（缺段/错序）；恢复连续后收口 |
| `AUDIT` | 一致性审计结果 | 审计偏差记录 |

每条事件属于一条两阶段链（`chain_id` 相同）：`OPEN`（异常发生）与
`RESOLVE`（异常消除）。事件携带 `(tenant, seq)`，`seq` 在租户内从 1 连续。

## 核心准则（逐条对应需求）

- **只有完整事件链且连续水位成立才触发**
  - 事件按 `(tenant, seq)` 准入。`seq > next_seq` 说明更早事件还在路上 →
    事件**挂起**（记 `stream_gap` / `chain_held` 审计），不触发任何告警；
    水位连上后级联释放。
  - 触发相（OPEN）到达才建告警；只收到收口相（RESOLVE）、OPEN 永不到达的
    “幽灵链”不产生告警。
- **缺口补齐后补发或关闭**
  - 释放时链只有 OPEN → 正常触发，告警标 `backfilled=1`，通知 `fired`；
  - OPEN 与 RESOLVE 都在**连续水位之外**到达（补齐同批才释放）→
    **静默关闭**，不落 OPEN 告警/通知，仅记 `chain_pending_closed` 审计——
    异常从未在连续水位内被观察到，不该打扰值班；
  - 静默关闭后若同链再来新的 OPEN（新的异常周期），正常触发并可被收口恢复。
- **滑动窗口去重**
  - 同 `租户+类型+chain` 的 OPEN 在窗口内重复（上游重传），只累加
    `occurrence_count`，通知记 `deduped` 不再打扰；窗口过后再发重新 `fired`。
  - 窗口判定依据是落盘的 `notifications` 表，**重启后窗口仍成立**。
  - 默认窗口：QUARANTINE 600s / TAKEOVER 1800s / GAP 300s / AUDIT 3600s。
- **确认与恢复竞争**
  - 所有告警状态转移走 `version` 乐观条件 CAS；并发确认 vs 链收口恢复时
    只有一个赢家成为首转移，输家得到 `409 ALERT_VERSION_CONFLICT` 并回带
    当前版本；事件收口不认输（ACKED 后 RESOLVE 仍推进到 RECOVERED）。
  - 测试 `TestAckRecoverRace` 用双线程屏障真实并发验证。
- **服务重启恢复**
  - `journal`（事件 + 命令统一日志，`jseq` 有序）是唯一事实来源。启动清空
    全部物化表，按 jseq 全量重放重建告警/水位/挂起/静默；审计 `dedup_key`
    唯一保证重放绝不重复落账；停机期间到期的静默与 RECOVERED TTL 在启动时
    立即收口，不等第一个请求/tick。
- **同事件幂等**
  - `event_id` 唯一：重复投递返回 `idempotent_replay` 与既有告警状态，不二次
    折叠；运维命令支持 `idempotency_key`，同键重放返回首次结果。
- **审计每次状态转移**
  - fired / deduped / acked / recovered / closed / silenced / unsilenced /
    reopened / recovered_ttl_closed / chain_pending_closed / stream_gap /
    watermark_advance / silence_created|revoked|expired …，每条带
    `actor`、告警 id、租户与细节，可按 kind/tenant/alert 查询。

## 告警状态机

```
                 OPEN（触发，窗口内重传→deduped）
               ┌───┴────────┬──────────────┐
            ack│         recover/链收口      │建规则/单条静默
               ▼            ▼               ▼
            ACKED ──链收口─▶ RECOVERED     SILENCED
               │            │ TTL 到期/关闭  │规则撤销/到期
               │            ▼               ▼ → 回 OPEN（或回 ACKED，确认事实保留）
               └──────────▶ CLOSED ◀────────┘
   RECOVERED 后又来 OPEN → reopen 回 OPEN（异常复发）
```

- `RECOVERED` 在 `--recovered-ttl`（默认 3600s）后由后台 tick **自动关闭**；
- 静默精确度：`tenant+type` > `tenant` > 全局；规则创建时立即作用于已存在的
  活动 OPEN/ACKED 告警，撤销/到期时把告警恢复到静默前状态。

## 快速开始

```bash
cd quota-alert-router

# 1) 独立启动（可先注入演示数据）
python3 -m qrouter serve --db ./dr/alerts.db --port 8910 --seed-demo
# 运维页面
open http://localhost:8910/

# 2) 订阅真实复制器（先起主站与 replica，见 ../REPLICA_README.md）
python3 -m qrouter serve --db ./dr/alerts.db --port 8910 \
    --replica http://127.0.0.1:8899 --subscriber-name dr-site-1 \
    --poll-interval 2

# 离线查看审计轨迹
python3 -m qrouter audit-tail --db ./dr/alerts.db --kind alert_fired
# 向运行实例注入演示事件
python3 -m qrouter demo-events --url http://127.0.0.1:8910
```

## HTTP API

事件面：

| 方法/路径 | 说明 |
|---|---|
| `POST /api/events` | 投递单条事件（同 `event_id` 幂等），返回是否挂起/水位/触发的告警 |
| `POST /api/events/batch` | 批量投递；先整体校验，任一非法整批 `422`，不写半批 |
| `GET /api/watermarks` | 各租户连续水位、next_seq、挂起计数 |

告警面：

| 方法/路径 | 说明 |
|---|---|
| `GET /api/alerts?tenant=&type=&status=` | 按租户/类型/状态查询 |
| `GET /api/alerts/{id}` | 详情：告警 + 链事件 + 通知 + 转移审计时间线 |
| `POST /api/alerts/{id}/ack?version=N` | 确认（乐观锁；竞争输家 409） |
| `POST /api/alerts/{id}/recover?version=N` | 人工恢复 → RECOVERED |
| `POST /api/alerts/{id}/close` | 关闭（终态） |
| `POST /api/alerts/{id}/silence` | 单条静默（可带 `ends_at`/`reason`） |
| `POST /api/alerts/{id}/unsilence` | 解除单条静默 |

静默规则面：

| 方法/路径 | 说明 |
|---|---|
| `GET /api/silences?include_revoked=1` | 规则列表 |
| `POST /api/silences` | 建规则（`tenant`/`type` 省略=全局/全类型；`silence_id` 作幂等键） |
| `POST /api/silences/{id}/revoke` | 撤销（被静默的告警随之恢复），幂等 |

查询/运维：`GET /api/pending`（缺号/挂起链）、`GET /api/audit`、
`GET /api/stats`、`GET /healthz`、`GET /`（运维页面，3s 自动刷新，
带确认/恢复/静默/关闭操作与版本竞争提示）。

事件信封：

```jsonc
{
  "event_id": "dr1:q-open:42",      // 幂等键
  "tenant": "dr-site-1",
  "type": "QUARANTINE",             // QUARANTINE|TAKEOVER|GAP|AUDIT
  "phase": "OPEN",                  // OPEN|RESOLVE
  "chain_id": "quar-seg-42",        // 同一异常两阶段共享
  "seq": 7,                         // 租户内连续水位序号
  "occurred_at": "2026-10-07T10:00:00.123Z",
  "payload": {"reason": "EVENT_HASH_BROKEN", "summary": "…"}
}
```

## 持久化布局（单 SQLite，事件溯源）

| 表 | 内容 |
|---|---|
| `journal` | **事实来源**：事件 + 运维命令统一只追加日志（`jseq`），event/cmd 幂等键唯一，命令首次结果随命令落盘 |
| `alerts` | 告警聚合视图（版本乐观锁、计数、补发标记、静默/确认/恢复/关闭时间） |
| `alert_events` | 进入告警链的全部事件（触发/收口/重传，保序） |
| `notifications` | fired / deduped / suppressed / reopened / resolved —— 滑动窗口去重依据 |
| `stream_events` | 全部已接收事件（含 held=1 挂起），重建链与水位 |
| `tenants` | 各租户连续水位 next_seq / 水位事件 |
| `silences` | 静默规则（生效/到期/撤销） |
| `audit_log` | 只追加审计，`dedup_key` 唯一（重放不重复） |
| `kv` | 订阅游标、epoch/GAP 兜底标记 |

## 代码结构

| 文件 | 职责 |
|---|---|
| `qrouter/models.py` | 四类事件/两相、告警状态机与合法转移、审计 kind、事件校验、时间工具 |
| `qrouter/store.py` | SQLite 事件溯源：journal、物化表、版本 CAS、幂等审计、静默/水位查询 |
| `qrouter/engine.py` | 连续水位准入与级联释放、事件链折叠、补发/静默关闭、滑动窗口去重、静默、命令、TTL tick、journal 重放恢复 |
| `qrouter/subscriber.py` | 轮询复制器审计/隔离/状态 → 四类事件；游标持久化、epoch 兜底去重 |
| `qrouter/http_server.py` | 事件/告警/静默/查询接口与运维页面 |
| `qrouter/__main__.py` | `serve` / `audit-tail` / `demo-events` |
| `qrouter/demo.py` | 演示事件（覆盖触发/缺口挂起/补发/静默关闭/重传去重） |
| `qrouter/static/index.html` | 运维页面 |
| `tests/test_router.py` | 26 项引擎测试（含并发 CAS 竞争、重放等价、注入时钟 TTL） |
| `tests/test_http_e2e.py` | 7 项真实 HTTP + 假复制器订阅端到端测试 |

## 测试

```bash
cd quota-alert-router
python3 -m unittest tests.test_router tests.test_http_e2e -v
# 33 项：真实 SQLite、线程并发、服务重启重放、真实 HTTP 双端与订阅轮询
```

已通过三进程真实链路验证：`quota` 主站 + `replica` 复制器 + `qrouter`
订阅——复制器隔离经审计轨迹在一个轮询周期内变为 `QUARANTINE OPEN` 告警，
人工确认、链收口恢复各落一条转移审计；停掉 qrouter 后同库重启，告警版本、
计数与全部审计与重启前逐条一致。
