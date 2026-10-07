# 配额灾备异常告警路由器（alerter）

订阅只读灾备复制器（`replica/`）的**隔离、接管、缺口、审计**四类事件，按
「租户 + 事件类型」聚合成告警，提供确认 / 静默 / 恢复 / 查询接口与运维页面。
纯 Python 3.11 标准库，零外部依赖；与复制器同一套工程风格（SQLite 原子条件
更新 + 只追加审计轨迹）。

## 双闸门：只有“完整事件链”且“连续水位成立”才触发

```
复制器审计/隔离记录
        │  subscriber 归一化（确定性 event_id）
        ▼
规范化事件 ── 闸门①：租户流连续水位（seq 1..N 无缺口，缺口事件停在库后等待）
        │
        ▼
事件链 chain_id ── 闸门②：角色完整
                         ISOLATION / GAP：BEGIN + AUDIT 见证
                         TAKEOVER       ：BEGIN + END + AUDIT 见证
        │
        ▼
按 租户+类型 聚合（同时仅一条活动告警，多链累计发生次数）
        │
   滑动窗口去重 ── 命中静默规则？
        │              是 → SILENCED（不通知，仍聚合）
        ▼
      FIRING → 通知（锚定去重窗口）
        │
   END 到达且全部链关闭 / 接管链闭合
        ▼
    RESOLVED（自动恢复；ACKED 也会被事实态推进）
```

- **链未完整不触发**：缺角色的链停在 `OPEN/WITNESSED`；
- **END 先于链完整**（如见证还在水位缺口之后）：缺口补齐时链已终态，按
  `BORN_CLOSED` **静默关闭、不补发**；
- **先触发、END 后到**：ISOLATION/GAP 自动 RESOLVED；
- **TAKEOVER 必须见到 END**：链完整即生命周期闭合，通知一次后同事务自动恢复；
- **水位缺口**：缺 seq 的后续事件一律不处理，缺口检测/补齐各写一条审计；
  补齐后连续放行，被挡住的链按上面规则补发或关闭。

## 滑动窗口去重

- 维度：`(tenant, alert_type, fingerprint)`，`fingerprint` 为原因码（缺省
  `__generic__`）；窗口默认 300s（`--dedup-window`）。
- 窗口**锚定上次真正通知的时刻**：窗口内的新发生只记 occurrence + 审计
  `alert_deduped`，不重复通知；**被抑制的发生不滑动延长窗口**，窗口始终从
  上次通知起算。
- 窗口过期后的新发生会再次通知并重新锚定。

## 确认与恢复竞争

所有状态转移都是 `UPDATE ... WHERE status IN (...)` 的条件更新，并与审计记录
在**同一个 `BEGIN IMMEDIATE` 事务**提交。确认（ack）与恢复（自动 resolve /
人工 close）并发对撞时：

- 全局只有一个事务赢，只落**一次状态、一条审计**；
- 输家读到权威状态后**幂等返回**（终态不被覆盖：自动 RESOLVED 与人工 CLOSED
  先到先得）。

状态机：`FIRING ⇄ ACKED`、`FIRING/ACKED ⇄ SILENCED(→到期回原态)`、
任意活动态 → `RESOLVED`（自动）/ `CLOSED`（人工），两个终态不可逆。

## 服务重启恢复

- 事件、链、告警、去重窗口、静默规则、订阅游标全部在 SQLite；构造即执行
  `recover_on_startup()`：静默到期/规则失效的告警**立即**恢复（不等下个请求），
  清扫过期窗口，并写 `router_recovered` 审计；
- 重启**不重发通知、不重复触发**，已 FIRING 的告警仍是 FIRING，水位缺口从
  事件表重建；
- 同事件幂等：`event_id` 是去重键，重复投递（含批量重放）返回
  `duplicate_ignored`，不占新序号、不重复触发、不重复写登记审计；订阅器的
  event_id 由复制器记录 id 确定性派生，跨重启重放安全。

## 快速开始

```bash
# 1) 主站 + 复制器（见 ../REPLICA_README.md）
python3 -m quota.http_server --port 8765 --db ./dr/primary.db --allow-feed-chaos
python3 -m replica serve --primary http://127.0.0.1:8765 --db ./dr/replica.db --port 8899

# 2) 告警路由器（订阅复制器；运维页面 http://localhost:8910/）
python3 -m alerter --port 8910 --db ./dr/alerter.db \
    --replica http://127.0.0.1:8899 --dedup-window 300

# 3) 也可以脱离复制器、由外部系统直连投递规范化事件
python3 -m alerter --port 8910 --db ./dr/alerter.db
```

## 规范化事件

```jsonc
POST /api/events
{
  "event_id": "evt-1",            // 幂等键
  "tenant": "tenant-a",           // 按租户聚合
  "event_type": "ISOLATION",      // ISOLATION | GAP | TAKEOVER | AUDIT
  "role": "BEGIN",                // BEGIN | END（AUDIT 事件固定 WITNESS）
  "chain_id": "quarantine:11",    // 同一次灾备异常事件链
  "reason": "LAG_OVER_LIMIT",     // 去重指纹
  "seq": 12,                      // 可选：租户流水位序号；省略则稠密自动分配
  "audit_ref": "audit-11",        // AUDIT 事件必填：见证对象
  "payload": { "...": "..." }     // 任意明细
}
```

## HTTP API

| 方法/路径 | 说明 |
|---|---|
| `POST /api/events` / `POST /api/events/batch` | 接收事件（幂等） |
| `GET /api/alerts?tenant=&type=&status=` | 告警列表 |
| `GET /api/alerts/{id}` | 详情（聚合链、发生记录） |
| `POST /api/alerts/{id}/ack` / `unack` | 确认 / 取消确认 |
| `POST /api/alerts/{id}/silence` / `unsilence` | 静默（ttl_seconds）/ 解除 |
| `POST /api/alerts/{id}/resolve` | 人工恢复/关闭（与自动恢复竞争幂等） |
| `POST /api/silences` / `GET /api/silences` / `DELETE /api/silences/{id}` | 静默规则（租户/类型/原因码 + TTL，可回填静默既有活动告警） |
| `GET /api/chains` / `GET /api/gaps` / `GET /api/watermarks` | 链 / 水位缺口 / 每租户连续水位 |
| `GET /api/audit?kind=&limit=` | 审计轨迹（每次状态转移一条） |
| `GET /ops/status` | 总览（告警计数、水位、订阅游标） |
| `POST /ops/subscriber/poll` / `start` / `stop` | 手动轮询 / 启停后台订阅 |
| `POST /ops/sweep` / `POST /ops/recover` | 静默到期+窗口清扫 / 重启恢复 |

## 订阅复制器（`alerter/subscriber.py`）

轮询复制器 `GET /ops/audit-tail`（自增 id 游标）与
`GET /ops/quarantine?include_resolved=1`，翻译为：

| 复制器事实 | 合成事件 |
|---|---|
| `segment_quarantined`（缺口类：SEGMENT_INDEX_MISMATCH / SEQ_NOT_CONTIGUOUS / LAG_* / 断链） | GAP BEGIN + AUDIT 见证 |
| `segment_quarantined`（其余：BODY_CONFLICT / ENVELOPE_DIGEST_MISMATCH …） | ISOLATION BEGIN + AUDIT 见证 |
| 隔离记录出现 `resolved_at` | 同链 END + AUDIT 见证（自动恢复链路） |
| `ownership_lost` | TAKEOVER BEGIN + AUDIT 见证 |
| 新实例 `replicator_started`（存在对应开放接管链） | TAKEOVER END + AUDIT 见证 |

## 持久化布局

| 表 | 内容 |
|---|---|
| `events` | 规范化事件原文（event_id 幂等键、租户水位序号、是否已应用） |
| `gaps` | 每租户水位缺口区间（检测/补齐） |
| `chains` | 事件链：角色集合、状态、绑定告警 |
| `alerts` | 聚合告警与状态机（活动键 `(tenant,alert_type)` 部分唯一索引） |
| `alert_chains` / `alert_occurrences` | 告警聚合了哪些链 / 每次发生与是否已通知 |
| `dedup_windows` | 滑动去重窗口（锚定上次通知） |
| `silence_rules` | 静默规则（类型/原因码通配 + TTL） |
| `audit_log` | 只追加审计轨迹 |

## 代码结构 / 测试

| 文件 | 职责 |
|---|---|
| `alerter/models.py` | 规范化事件、链规则、状态常量、校验 |
| `alerter/store.py` | SQLite 持久化、条件状态转移、同事务审计 |
| `alerter/router.py` | 双闸门、链完整性、聚合计数、去重、静默、状态机、重启恢复 |
| `alerter/subscriber.py` | 复制器审计/隔离 → 规范化事件（游标 + 确定性 event_id） |
| `alerter/http_server.py` | HTTP API + 运维页面 + CLI |
| `alerter/static/index.html` | 运维页面（告警操作、静默规则、水位/缺口、审计、事件模拟器） |
| `test_alerter.py` | 34 项：双闸门/补发关闭/去重/聚合/竞争/静默/重启/幂等/订阅/HTTP |

```bash
python3 -m unittest test_alerter      # 34 项
```
