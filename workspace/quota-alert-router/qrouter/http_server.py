"""配额灾备异常告警路由器 · HTTP 接口（Python 标准库）。

事件面（复制器/订阅器/测试注入）：

  POST /api/events               单条事件投递（同 event_id 幂等）
  POST /api/events/batch         批量投递（逐条结果，任一条非法整体 422）
  GET  /api/watermarks           各租户连续水位与挂起计数

告警面（按租户+类型聚合）：

  GET  /api/alerts               查询（?tenant=&type=&status=）
  GET  /api/alerts/{id}          告警详情（链事件/通知/审计）
  POST /api/alerts/{id}/ack      确认（?version= 乐观锁，竞争输家 409）
  POST /api/alerts/{id}/recover  人工恢复（进入 RECOVERED，TTL 后自动关闭）
  POST /api/alerts/{id}/close    人工关闭
  POST /api/alerts/{id}/silence  单条静默（可带 ends_at / reason）
  POST /api/alerts/{id}/unsilence 解除单条静默

静默规则面：

  GET  /api/silences             静默规则（?include_revoked=1）
  POST /api/silences             创建规则（tenant/type 可选；缺省=全局）
  POST /api/silences/{id}/revoke 撤销规则（被静默的告警随之恢复）

查询/审计/运维：

  GET  /api/pending              挂起视图（缺号、挂起事件、挂起链）
  GET  /api/audit                审计轨迹（?kind=&tenant=&alert_id=&limit=）
  GET  /api/stats                计数与配置
  GET  /healthz                  存活
  GET  /                         运维页面
"""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .models import EVENT_TYPES, RouterError

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

COMMAND_ROUTES = {
    "POST": {
        "/api/alerts/{id}/ack": "ack",
        "/api/alerts/{id}/recover": "recover",
        "/api/alerts/{id}/close": "close",
        "/api/alerts/{id}/silence": "silence_alert",
        "/api/alerts/{id}/unsilence": "unsilence_alert",
    }
}


class RouterHandler(BaseHTTPRequestHandler):
    server_version = "QuotaAlertRouter/1.0"

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        self.server.app_log(f"{self.command} {self.path}")  # type: ignore[attr-defined]

    def _json(self, code: int, obj: dict | list) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise RouterError("BAD_JSON", f"请求体不是合法 JSON: {exc}", 400)
        return data if isinstance(data, dict) else {}

    def _engine(self):
        return self.server.router  # type: ignore[attr-defined]

    def _error(self, exc: RouterError) -> None:
        self._json(exc.status, {"error": exc.reason, "message": str(exc),
                                "details": exc.details})

    # ------------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path, query = parsed.path, parse_qs(parsed.query)
        eng = self._engine()
        try:
            if path == "/healthz":
                return self._json(200, {"ok": True})
            if path == "/api/stats":
                return self._json(200, eng.stats())
            if path == "/api/watermarks":
                return self._json(200, {"tenants": eng.watermarks()})
            if path == "/api/pending":
                return self._json(200, eng.pending_view())
            if path == "/api/alerts":
                return self._json(200, {"alerts": eng.list_alerts(
                    tenant=query.get("tenant", [None])[0],
                    etype=query.get("type", [None])[0],
                    status=query.get("status", [None])[0],
                    limit=int(query.get("limit", ["500"])[0]))})
            if path.startswith("/api/alerts/"):
                aid = path[len("/api/alerts/"):].strip("/")
                if aid and "/" not in aid:
                    return self._json(200, eng.get_alert_detail(aid))
            if path == "/api/silences":
                include = query.get("include_revoked", ["0"])[0] in ("1", "true")
                return self._json(200, {"silences": eng.list_silences(include)})
            if path == "/api/audit":
                kind = query.get("kind", [None])[0]
                tenant = query.get("tenant", [None])[0]
                alert_id = query.get("alert_id", [None])[0]
                limit = int(query.get("limit", ["100"])[0])
                return self._json(200, {"entries": eng.list_audit(
                    limit=limit, kind=kind, tenant=tenant, alert_id=alert_id)})
            if path in ("/", "/index.html"):
                return self._serve_static("index.html", "text/html; charset=utf-8")
            if path.startswith("/static/"):
                return self._serve_static(path[len("/static/"):],
                                          self._guess_mime(path))
            self._json(404, {"error": "NOT_FOUND", "message": f"未知路径: {path}"})
        except RouterError as exc:
            self._error(exc)
        except Exception as exc:  # noqa: BLE001
            self.server.app_log(f"ERROR GET {path}: {exc!r}")  # type: ignore[attr-defined]
            self._json(500, {"error": "InternalError", "message": str(exc)})

    # ------------------------------------------------------------------
    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path, query = parsed.path, parse_qs(parsed.query)
        eng = self._engine()
        try:
            # ---- 事件面 ----
            if path == "/api/events":
                body = self._read_body()
                result = eng.ingest_event(body)
                return self._json(202, result)
            if path == "/api/events/batch":
                raw = self._read_body()
                events = raw.get("events")
                if not isinstance(events, list) or not events:
                    raise RouterError("BAD_BATCH",
                                      "body.events 必须是非空数组", 400)
                # 先统一校验，任一非法整体拒绝（不写半批）
                from .models import normalize_event
                normalized = [normalize_event(e) for e in events]
                return self._json(202, {"results": eng.ingest_batch(normalized)})

            # ---- 单条告警命令 ----
            for tmpl, command in COMMAND_ROUTES["POST"].items():
                prefix, suffix = tmpl.split("{id}")
                if path.startswith(prefix) and path.endswith(suffix):
                    middle = path[len(prefix): -len(suffix)] if suffix else \
                        path[len(prefix):]
                    if middle and "/" not in middle:
                        body = self._read_body()
                        body["alert_id"] = middle
                        version = query.get("version", [None])[0]
                        if version is not None:
                            body["version"] = version
                        idem = query.get("idempotency_key",
                                         [body.pop("idempotency_key", None)])[0]
                        result = eng.execute(
                            command, body,
                            actor=body.get("actor") or self.headers.get(
                                "X-Operator", "operator"),
                            idem_key=idem)
                        return self._json(200, result)

            # ---- 静默规则 ----
            if path == "/api/silences":
                body = self._read_body()
                if body.get("type") not in (None, *EVENT_TYPES):
                    raise RouterError("BAD_EVENT_TYPE",
                                      f"未知事件类型: {body.get('type')}", 422)
                result = eng.execute(
                    "create_silence", body,
                    actor=body.get("created_by")
                    or self.headers.get("X-Operator", "operator"),
                    idem_key=body.get("idempotency_key")
                    or body.get("silence_id"))
                return self._json(201, result)
            if path.startswith("/api/silences/") and path.endswith("/revoke"):
                sid = path[len("/api/silences/"): -len("/revoke")].strip("/")
                body = self._read_body()
                body["silence_id"] = sid
                result = eng.execute(
                    "revoke_silence", body,
                    actor=body.get("actor")
                    or self.headers.get("X-Operator", "operator"),
                    idem_key=f"revoke:{sid}")
                return self._json(200, result)

            self._json(404, {"error": "NOT_FOUND", "message": f"未知路径: {path}"})
        except RouterError as exc:
            self._error(exc)
        except Exception as exc:  # noqa: BLE001
            self.server.app_log(f"ERROR POST {path}: {exc!r}")  # type: ignore[attr-defined]
            self._json(500, {"error": "InternalError", "message": str(exc)})

    do_PUT = do_DELETE = do_PATCH = lambda self: self._json(  # type: ignore[assignment]
        405, {"error": "METHOD_NOT_ALLOWED", "message": "仅支持 GET/POST"})

    # ------------------------------------------------------------------
    def _serve_static(self, rel_path: str, content_type: str) -> None:
        rel_path = rel_path.replace("\\", "/").lstrip("/")
        full = os.path.normpath(os.path.join(STATIC_DIR, rel_path))
        if not full.startswith(STATIC_DIR + os.sep) or not os.path.isfile(full):
            self._json(404, {"error": "NOT_FOUND", "message": rel_path})
            return
        with open(full, "rb") as fh:
            body = fh.read()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    @staticmethod
    def _guess_mime(path: str) -> str:
        if path.endswith(".css"):
            return "text/css; charset=utf-8"
        if path.endswith(".js"):
            return "application/javascript; charset=utf-8"
        return "application/octet-stream"


def create_server(host: str, port: int, router) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer((host, port), RouterHandler)
    httpd.router = router  # type: ignore[attr-defined]
    httpd.app_log = lambda msg: print(f"[qrouter] {msg}", flush=True)  # type: ignore[attr-defined]
    return httpd
