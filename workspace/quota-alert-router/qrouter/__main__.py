"""命令行入口。

    python3 -m qrouter serve --db ./dr/alerts.db --port 8910 \\
        [--replica http://127.0.0.1:8899] [--subscriber-name dr-site-1] \\
        [--recovered-ttl 3600] [--seed-demo]
    python3 -m qrouter audit-tail --db ./dr/alerts.db [--kind alert_fired]
    python3 -m qrouter demo-events --url http://127.0.0.1:8910   # 向运行实例注入演示事件
"""

from __future__ import annotations

import argparse
import json
import threading
import time

from .engine import AlertRouter
from .http_server import create_server
from .models import now_ts
from .store import Store


def _cmd_serve(args: argparse.Namespace) -> None:
    store = Store(args.db)
    router = AlertRouter(store, recovered_ttl_seconds=args.recovered_ttl)

    subscriber = None
    if args.replica:
        from .subscriber import ReplicaSubscriber
        subscriber = ReplicaSubscriber(
            router, args.replica, tenant=args.subscriber_name,
            poll_interval=args.poll_interval)
        subscriber.start()

    # 后台 tick：静默到期 / RECOVERED TTL 主动收口（不依赖请求惰性触发）
    stop = threading.Event()

    def _ticker() -> None:
        while not stop.wait(2.0):
            with router._lock, store.lock:  # noqa: SLF001
                try:
                    router._tick(now_ts())  # noqa: SLF001
                except Exception as exc:  # noqa: BLE001
                    print(f"[qrouter] tick 异常: {exc!r}", flush=True)

    ticker = threading.Thread(target=_ticker, name="qrouter-tick", daemon=True)
    ticker.start()

    if args.seed_demo:
        from .demo import seed_demo
        seed_demo(router)
        print("[qrouter] 已注入演示数据", flush=True)

    httpd = create_server(args.host, args.port, router)
    print(f"[qrouter] 告警路由器监听 http://{args.host}:{args.port}  "
          f"（db={args.db}，replica={args.replica or '未订阅'}）", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        if subscriber:
            subscriber.stop()
        httpd.server_close()
        store.close()


def _cmd_audit_tail(args: argparse.Namespace) -> None:
    store = Store(args.db)
    entries = store.list_audit(limit=args.limit, kind=args.kind,
                               tenant=args.tenant, alert_id=args.alert_id)
    print(json.dumps({"entries": entries}, ensure_ascii=False, indent=2))
    store.close()


def _cmd_demo_events(args: argparse.Namespace) -> None:
    from .demo import push_demo_events
    push_demo_events(args.url)


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="qrouter",
                                description="配额灾备异常告警路由器")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="启动 HTTP 服务")
    s.add_argument("--host", default="0.0.0.0")
    s.add_argument("--port", type=int, default=8910)
    s.add_argument("--db", default="./dr/alerts.db")
    s.add_argument("--replica", default=None,
                   help="要订阅的复制器基址，如 http://127.0.0.1:8899")
    s.add_argument("--subscriber-name", default="dr-site-1",
                   help="本订阅在告警中的租户名")
    s.add_argument("--poll-interval", type=float, default=2.0)
    s.add_argument("--recovered-ttl", type=float, default=3600,
                   help="RECOVERED 后多少秒自动关闭")
    s.add_argument("--seed-demo", action="store_true",
                   help="启动时注入演示事件链")
    s.set_defaults(func=_cmd_serve)

    a = sub.add_parser("audit-tail", help="查看本地审计轨迹")
    a.add_argument("--db", default="./dr/alerts.db")
    a.add_argument("--kind", default=None)
    a.add_argument("--tenant", default=None)
    a.add_argument("--alert-id", default=None)
    a.add_argument("--limit", type=int, default=100)
    a.set_defaults(func=_cmd_audit_tail)

    d = sub.add_parser("demo-events", help="向运行中的实例注入演示事件")
    d.add_argument("--url", default="http://127.0.0.1:8910")
    d.set_defaults(func=_cmd_demo_events)

    args = p.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
