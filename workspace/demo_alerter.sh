#!/usr/bin/env bash
# 配额灾备异常告警路由器 —— 一键演示（直连模式，不依赖主站/复制器）。
#
# 场景：
#   ① 完整隔离链触发（BEGIN + AUDIT 见证，连续水位成立）
#   ② 同原因码再来两次：聚合成一条告警，滑动窗口抑制重复通知
#   ③ 水位缺口（seq 跳号）：缺口后的事件不触发；补齐后放行
#   ④ 未触发即终态（END 先于见证）：缺口补齐后不补发
#   ⑤ TAKEOVER 完整链（BEGIN+END+见证）：通知一次即自动恢复
#   ⑥ 确认 / 静默 / 人工恢复 / 同事件幂等 / 审计轨迹
#
# 用法：bash demo_alerter.sh [port]
set -euo pipefail

PORT="${1:-8911}"
DBDIR="$(mktemp -d)"
DB="$DBDIR/alerter-demo.db"
BASE="http://127.0.0.1:${PORT}"

python3 -m alerter --port "$PORT" --db "$DB" --dedup-window 300 >/dev/null 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null || true' EXIT

for _ in $(seq 1 30); do
  curl -sf "$BASE/ops/status" >/dev/null 2>&1 && break
  sleep 0.2
done

post() {
  local body="${2:-}"
  [ -z "$body" ] && body='{}'
  curl -s -X POST "$BASE$1" -H 'Content-Type: application/json' -d "$body"
}
ev() { post /api/events "$1"; }
# show "<说明>: " '<python 表达式，d 为响应 JSON>'
show() {
  local label="$1" expr="$2"
  curl -s "$BASE$3" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print('$label', $2)
"
}

echo "──────── ① 完整隔离链：BEGIN + AUDIT 见证 ────────"
ev '{"event_id":"e1","tenant":"t1","event_type":"ISOLATION","role":"BEGIN","chain_id":"c1","reason":"LAG_OVER_LIMIT"}' >/dev/null
ev '{"event_id":"e2","tenant":"t1","event_type":"AUDIT","chain_id":"c1","audit_ref":"a1","reason":"LAG_OVER_LIMIT"}' >/dev/null
show "触发 →" "d['alerts'][0]['id']+' '+d['alerts'][0]['alert_type']+' occ='+str(d['alerts'][0]['occurrence_count'])" "/api/alerts?status=FIRING"

echo "──────── ② 同原因码再发两条完整链：聚合 + 滑动窗口去重 ────────"
ev '{"event_id":"e3","tenant":"t1","event_type":"ISOLATION","role":"BEGIN","chain_id":"c2","reason":"LAG_OVER_LIMIT"}' >/dev/null
ev '{"event_id":"e4","tenant":"t1","event_type":"AUDIT","chain_id":"c2","audit_ref":"a2","reason":"LAG_OVER_LIMIT"}' >/dev/null
ev '{"event_id":"e5","tenant":"t1","event_type":"ISOLATION","role":"BEGIN","chain_id":"c3","reason":"LAG_OVER_LIMIT"}' >/dev/null
ev '{"event_id":"e6","tenant":"t1","event_type":"AUDIT","chain_id":"c3","audit_ref":"a3","reason":"LAG_OVER_LIMIT"}' >/dev/null
show "仍是一条活动告警（后两次被窗口抑制），occ=" "d['alerts'][0]['occurrence_count']" "/api/alerts?status=FIRING"
show "去重审计条数=" "len(d['entries'])" "/api/audit?limit=50&kind=alert_deduped"

echo "──────── ③ 水位缺口：seq3 先到、seq2 缺失 → 3 不触发 ────────"
ev '{"event_id":"g1","tenant":"t2","seq":1,"event_type":"GAP","role":"BEGIN","chain_id":"g1","reason":"SEGMENT_INDEX_MISMATCH"}' >/dev/null
ev '{"event_id":"g3","tenant":"t2","seq":3,"event_type":"GAP","role":"BEGIN","chain_id":"g3","reason":"SEGMENT_INDEX_MISMATCH"}' >/dev/null
show "t2 连续水位（seq3 被挡）=" "d['tenants']['t2']['contiguous_until']" "/api/watermarks"
show "开放缺口起点=" "d['gaps'][0]['gap_from']" "/api/gaps"
ev '{"event_id":"g2","tenant":"t2","seq":2,"event_type":"AUDIT","chain_id":"g1","audit_ref":"g2","reason":"SEGMENT_INDEX_MISMATCH"}' >/dev/null
show "补齐 seq2 后连续水位=" "d['tenants']['t2']['contiguous_until']" "/api/watermarks"
show "缺口全部关闭，开放缺口数=" "len(d['gaps'])" "/api/gaps"
show "seq1 链完整已触发 GAP 告警，状态=" "d['alerts'][0]['status']" "/api/alerts?tenant=t2&status=FIRING"

echo "──────── ④ END 先于见证（未触发即终态，补齐不补发） ────────"
ev '{"event_id":"b1","tenant":"t3","seq":1,"event_type":"ISOLATION","role":"BEGIN","chain_id":"bc","reason":"BODY_CONFLICT"}' >/dev/null
ev '{"event_id":"b2","tenant":"t3","seq":2,"event_type":"ISOLATION","role":"END","chain_id":"bc","reason":"BODY_CONFLICT"}' >/dev/null
ev '{"event_id":"b3","tenant":"t3","seq":3,"event_type":"AUDIT","chain_id":"bc","audit_ref":"b3","reason":"BODY_CONFLICT"}' >/dev/null
show "t3 告警数（链应为 BORN_CLOSED）=" "len(d['alerts'])" "/api/alerts?tenant=t3"
show "链状态=" "d['chains'][0]['status']" "/api/chains?tenant=t3"

echo "──────── ⑤ TAKEOVER 必须有 END：缺 END 不触发，齐了通知后自动恢复 ────────"
ev '{"event_id":"t1","tenant":"t4","event_type":"TAKEOVER","role":"BEGIN","chain_id":"tk","reason":"OWNERSHIP_LOST"}' >/dev/null
ev '{"event_id":"t2","tenant":"t4","event_type":"AUDIT","chain_id":"tk","audit_ref":"t2"}' >/dev/null
show "只有 BEGIN+见证，告警数=" "len(d['alerts'])" "/api/alerts?tenant=t4"
ev '{"event_id":"t3","tenant":"t4","event_type":"TAKEOVER","role":"END","chain_id":"tk","reason":"TAKEOVER_COMPLETE"}' >/dev/null
show "接管链闭合后（通知一次即自动恢复）=" "d['alerts'][0]['status']" "/api/alerts?tenant=t4"

echo "──────── ⑥ 确认 → 静默 → 解除 → 人工恢复；同事件幂等 ────────"
AID="$(curl -s "$BASE/api/alerts?status=FIRING" | python3 -c "import json,sys;print(json.load(sys.stdin)['alerts'][0]['id'])")"
post "/api/alerts/$AID/ack" '{"by":"demo"}'        | python3 -c "import json,sys;print('确认 →', json.load(sys.stdin)['status'])"
ev '{"event_id":"e2","tenant":"t1","event_type":"AUDIT","chain_id":"c1","audit_ref":"a1","reason":"LAG_OVER_LIMIT"}' \
  | python3 -c "import json,sys;print('同事件重放 →', json.load(sys.stdin)['outcome'])"
post "/api/alerts/$AID/silence" '{"ttl_seconds":60,"note":"维护窗口"}' \
  | python3 -c "import json,sys;print('静默 →', json.load(sys.stdin)['status'])"
post "/api/alerts/$AID/unsilence" '{"delete_rule":true}' \
  | python3 -c "import json,sys;print('解除静默 →', json.load(sys.stdin)['status'])"
post "/api/alerts/$AID/resolve" '{"by":"demo","note":"已处置"}' \
  | python3 -c "import json,sys;print('人工恢复 →', json.load(sys.stdin)['status'])"
echo
echo "审计轨迹（最近 14 条）:"
curl -s "$BASE/api/audit?limit=14" | python3 -c "
import json,sys
for e in json.load(sys.stdin)['entries']:
    print(f\"  #{e['id']:>3} {e['kind']}\")"
echo
echo "运维页面： $BASE/"
echo "数据库：  $DB（可再次 python3 -m alerter --db 打开核对重启恢复）"
