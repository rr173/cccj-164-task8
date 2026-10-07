"""配额灾备异常告警路由器 —— HTTP 接口与运维页面。

查询面
------

    GET  /api/alerts                 告警列表（tenant/type/status 过滤）
    GET  /api/alerts/{id}            告警详情（聚合链 / 发生记录）
    GET  /api/chains                事件链
    GET  /api/gaps                  连续水位缺口
    GET  /api/watermarks            每租户连续水位
    GET  /api/audit                 审计轨迹（kind 过滤；每次状态转移都在此）
    GET  /api/silences              静默规则
    GET  /ops/status                路由总览（订阅游标/告警计数/水位）

写入面
------

    POST /api/events                接收单条规范化事件（event_id 幂等）
    POST /api/events/batch          批量接收
    POST /api/alerts/{id}/ack       确认
    POST /api/alerts/{id}/unack     取消确认
    POST /api/alerts/{id}/silence   静默（ttl_seconds/note）
    POST /api/alerts/{id}/unsilence 解除静默（?delete_rule=1 连规则一起删）
    POST /api/alerts/{id}/resolve   人工恢复/关闭
    POST /api/silences              静默规则（可回填静默既有活动告警）
    DELETE /api/silences/{id}       删除静默规则（其静默的告警恢复）

订阅器
------

    POST /ops/subscriber/poll       手动轮询一轮复制器
    POST /ops/subscriber/start|stop 启停后台订阅
    POST /ops/sweep                 立即 sweep（静默到期 / 窗口清扫）
    POST /ops/recover               模拟重启恢复（新进程构造时也会自动执行）

运维页面：GET /
"""

from __future__ import annotations

import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .models import AlertError, ALERT_TYPES
from .router import AlertRouter
from .store import AlertStore
from .subscriber import Subscriber

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


class AlertHandler(BaseHTTPRequestHandler):
    server_version = "QuotaAlertRouter/1.0"

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        self.server.app_log(f"{self.command} {self.path}")  # type: ignore[attr-defined]

    # ------------------------------------------------------------------
    def _json(self, code: int, obj) -> None:
        body = json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise AlertError("BAD_JSON", f"请求体不是合法 JSON: {exc}", status=400)
        return data

    def _router(self) -> AlertRouter:
        return self.server.router  # type: ignore[attr-defined]

    def _subscriber(self) -> Subscriber | None:
        return getattr(self.server, "subscriber", None)

    def _error(self, exc: AlertError) -> None:
        self._json(exc.status, {
            "error": exc.reason, "message": str(exc), "details": exc.details})

    # ------------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        router = self._router()
        try:
            if path == "/" or path == "/index.html":
                return self._serve_static("index.html", "text/html; charset=utf-8")
            if path.startswith("/static/"):
                return self._serve_static(path[len("/static/"):])

            if path == "/api/alerts":
                params = self._list_params(query, allowed=("tenant", "status", "alert_type"))
                return self._json(200, {"alerts": router.list_alerts(limit=int(query.get("limit", ["200"])[0]), **params)})
            if path.startswith("/api/alerts/"):
                aid = path[len("/api/alerts/"):].strip("/")
                alert = router.get_alert(aid)
                if alert is None:
                    return self._json(404, {"error": "NOT_FOUND", "message": f"告警不存在: {aid}"})
                return self._json(200, alert)
            if path == "/api/chains":
                params = self._list_params(query, allowed=("tenant",))
                return self._json(200, {"chains": router.list_chains(limit=int(query.get("limit", ["200"])[0]), **params)})
            if path == "/api/gaps":
                params = self._list_params(query, allowed=("tenant",))
                include_filled = query.get("include_filled", ["0"])[0] in ("1", "true")
                return self._json(200, {"gaps": router.list_gaps(include_filled=include_filled, **params)})
            if path == "/api/watermarks":
                return self._json(200, router.watermarks())
            if path == "/api/audit":
                kind = query.get("kind", [None])[0]
                limit = int(query.get("limit", ["100"])[0])
                after_id = int(query.get("after_id", ["0"])[0])
                return self._json(200, {"entries": router.list_audit(limit=limit, kind=kind, after_id=after_id)})
            if path == "/api/silences":
                tenant = query.get("tenant", [None])[0]
                active = query.get("active", ["0"])[0] in ("1", "true")
                rules = router.list_silence_rules(tenant=tenant, active_only=active)
                return self._json(200, {"rules": rules})
            if path == "/ops/status":
                body = router.status()
                sub = self._subscriber()
                body["subscriber"] = sub.status() if sub else {"enabled": False}
                return self._json(200, body)
            self._json(404, {"error": "NOT_FOUND", "message": f"无此路径: {path}"})
        except AlertError as exc:
            self._error(exc)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        router = self._router()
        try:
            body = self._read_body()

            if path == "/api/events":
                result = router.ingest_event(body)
                return self._json(202, result)
            if path == "/api/events/batch":
                events = body.get("events") if isinstance(body, dict) else body
                results = router.ingest_batch(events or [])
                return self._json(202, {"results": results})

            if path == "/api/silences":
                if not isinstance(body, dict) or not body.get("tenant"):
                    raise AlertError("BAD_SILENCE", "需要 tenant", 400)
                rule = router.create_silence_rule(
                    tenant=body["tenant"],
                    alert_type=body.get("alert_type"),
                    reason=body.get("reason"),
                    ttl_seconds=body.get("ttl_seconds"),
                    note=body.get("note", ""),
                    created_by=body.get("created_by", "operator"),
                    silence_existing=bool(body.get("silence_existing", False)),
                )
                return self._json(201, rule)

            # /api/alerts/{id}/<action>
            if path.startswith("/api/alerts/"):
                return self._alert_action(path, body)

            if path == "/ops/subscriber/poll":
                sub = self._require_subscriber()
                return self._json(200, sub.poll_once())
            if path == "/ops/subscriber/start":
                sub = self._require_subscriber()
                sub.start()
                return self._json(200, sub.status())
            if path == "/ops/subscriber/stop":
                sub = self._require_subscriber()
                sub.stop()
                return self._json(200, sub.status())
            if path == "/ops/sweep":
                return self._json(200, router.sweep())
            if path == "/ops/recover":
                return self._json(200, router.recover_on_startup())

            self._json(404, {"error": "NOT_FOUND", "message": f"无此路径: {path}"})
        except AlertError as exc:
            self._error(exc)

    def do_DELETE(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        router = self._router()
        try:
            if path.startswith("/api/silences/"):
                sid = path[len("/api/silences/"):].strip("/")
                return self._json(200, router.delete_silence_rule(sid))
            self._json(404, {"error": "NOT_FOUND", "message": f"无此路径: {path}"})
        except AlertError as exc:
            self._error(exc)

    def _alert_action(self, path: str, body: dict) -> None:
        router = self._router()
        rest = path[len("/api/alerts/"):].strip("/")
        if "/" not in rest:
            raise AlertError("NOT_FOUND", "需要动作路径 .../{ack,silence,resolve}", 404)
        aid, action = rest.split("/", 1)
        by = str(body.get("by", "operator")) if isinstance(body, dict) else "operator"
        if action == "ack":
            return self._json(200, router.ack_alert(aid, by=by, note=str(body.get("note", ""))))
        if action == "unack":
            return self._json(200, router.unack_alert(aid, by=by))
        if action == "silence":
            return self._json(200, router.silence_alert(
                aid, ttl_seconds=body.get("ttl_seconds"),
                note=str(body.get("note", "")), by=by))
        if action == "unsilence":
            delete_rule = bool(body.get("delete_rule", False))
            return self._json(200, router.unsilence_alert(
                aid, delete_rule=delete_rule, by=by))
        if action == "resolve":
            return self._json(200, router.close_alert(
                aid, by=by, note=str(body.get("note", "")),
                reason_code=str(body.get("reason", "MANUAL_CLOSE"))))
        raise AlertError("NOT_FOUND", f"未知动作: {action}", 404)

    def _require_subscriber(self) -> Subscriber:
        sub = self._subscriber()
        if sub is None:
            raise AlertError(
                "SUBSCRIBER_DISABLED",
                "本进程未配置 --replica 订阅地址，使用 POST /api/events 直接接入", 409)
        return sub

    @staticmethod
    def _list_params(query: dict[str, list[str]], *, allowed: tuple[str, ...]) -> dict[str, str]:
        out = {}
        for key in allowed:
            value = query.get(key, [None])[0]
            if value is not None:
                out[key] = value
        return out

    def _serve_static(self, rel: str, content_type: str = "application/octet-stream") -> None:
        # 防路径穿越：解析后必须仍在 STATIC_DIR 内
        full = os.path.normpath(os.path.join(STATIC_DIR, rel))
        if not full.startswith(STATIC_DIR + os.sep) or not os.path.isfile(full):
            return self._json(404, {"error": "NOT_FOUND", "message": rel})
        if full.endswith(".html"):
            content_type = "text/html; charset=utf-8"
        elif full.endswith(".js"):
            content_type = "application/javascript; charset=utf-8"
        elif full.endswith(".css"):
            content_type = "text/css; charset=utf-8"
        with open(full, "rb") as fh:
            data = fh.read()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)


class AlertServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler, router: AlertRouter,
                 subscriber: Subscriber | None = None,
                 log_file=None):
        super().__init__(address, handler)
        self.router = router
        self.subscriber = subscriber
        self._log_file = log_file

    def app_log(self, message: str) -> None:
        line = f"{message}\n"
        if self._log_file:
            with open(self._log_file, "a", encoding="utf-8") as fh:
                fh.write(line)


def build_router(args: argparse.Namespace) -> tuple[AlertRouter, AlertStore]:
    store = AlertStore(args.db)
    router = AlertRouter(
        store,
        default_window_seconds=args.dedup_window,
    )
    # 构造即执行重启恢复：到期静默立即恢复、窗口清扫、留 router_recovered
    router.start()
    return router, store


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="配额灾备异常告警路由器")
    parser.add_argument("--port", type=int, default=8910)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--db", default="./dr/alerter.db")
    parser.add_argument("--replica", default=None,
                        help="复制器基址（如 http://127.0.0.1:8899）；不填则仅接收 POST /api/events")
    parser.add_argument("--poll-interval", type=float, default=1.0)
    parser.add_argument("--dedup-window", type=int, default=300,
                        help="滑动去重窗口秒数（锚定上次真正通知）")
    parser.add_argument("--no-subscribe-loop", action="store_true",
                        help="配置 --replica 但不自动启动后台轮询（仅手动 /ops/subscriber/poll）")
    parser.add_argument("--log-file", default=None)
    args = parser.parse_args(argv)

    os.makedirs(os.path.dirname(os.path.abspath(args.db)), exist_ok=True)
    router, _store = build_router(args)
    subscriber = None
    if args.replica:
        subscriber = Subscriber(router, args.replica,
                                poll_interval=args.poll_interval)
        if not args.no_subscribe_loop:
            subscriber.start()

    server = AlertServer((args.host, args.port), AlertHandler, router,
                         subscriber=subscriber, log_file=args.log_file)
    print(f"告警路由器监听 http://{args.host}:{args.port}（运维页面 /）"
          f"  db={args.db}"
          f"{'  订阅 ' + args.replica if args.replica else '  无订阅（直连模式）'}",
          flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if subscriber:
            subscriber.stop()
        server.shutdown()


if __name__ == "__main__":
    main()
