"""Minimal CLI for running local dev server and simple commands."""
import argparse
import json
import time

import uvicorn


def serve(host: str = "127.0.0.1", port: int = 8000):
    uvicorn.run("aiaf.api.app:app", host=host, port=port, reload=True)


def run_monitoring_worker(poll_seconds: float = 30.0, once: bool = False):
    """Poll and execute persisted continuous-assurance schedules."""
    from .api.models import get_store
    from .core import MonitoringEngine

    if poll_seconds <= 0:
        raise ValueError("poll_seconds must be greater than zero")
    store = get_store()
    engine = MonitoringEngine(store)
    try:
        while True:
            result = engine.run_due()
            print(json.dumps(result, sort_keys=True), flush=True)
            if once:
                return result
            time.sleep(poll_seconds)
    finally:
        store.close()


def main():
    parser = argparse.ArgumentParser(prog="aiaf")
    sub = parser.add_subparsers(dest="cmd")

    run = sub.add_parser("run", help="Run the API server locally")
    run.add_argument("--host", default="127.0.0.1")
    run.add_argument("--port", type=int, default=8000)

    monitor = sub.add_parser("monitor", help="Run the continuous assurance worker")
    monitor.add_argument("--poll-seconds", type=float, default=30.0)
    monitor.add_argument("--once", action="store_true")

    args = parser.parse_args()
    if args.cmd == "run":
        serve(host=args.host, port=args.port)
    elif args.cmd == "monitor":
        run_monitoring_worker(poll_seconds=args.poll_seconds, once=args.once)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
