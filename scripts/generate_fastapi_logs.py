"""Generate REAL FastAPI/uvicorn logs from a deliberately buggy app.

Public datasets of production FastAPI logs don't exist (they'd be full of
PII/secrets), so this script produces the genuine article locally: it
boots an actual FastAPI app with realistic failure modes, drives traffic
at it, and captures the real uvicorn output — real tracebacks included.

Failure modes: DB connection-pool exhaustion (TimeoutError, 500s on
/checkout), an unreachable downstream (ConnectionError on /inventory),
unhandled KeyErrors on numeric path params (/order/{id}), and 422
validation rejects.

The server runs via `uv run --with fastapi --with uvicorn`, so neither
package needs to be a project dependency.

Usage:
    uv run python scripts/generate_fastapi_logs.py --requests 40
    uv run python scripts/run_on_raw_log.py fastapi_sample.log --errors-only
"""

from __future__ import annotations

import random
import time

# --- the buggy app (imported by the uvicorn subprocess, not by main()) ---
try:
    from fastapi import FastAPI
    from pydantic import BaseModel

    app = FastAPI()

    class _PaymentDB:
        def acquire_connection(self, timeout: float = 5.0):
            raise TimeoutError(
                f"could not acquire connection from pool (size=20, waited {timeout}s)"
            )

    _db = _PaymentDB()

    class Order(BaseModel):
        item_id: int
        quantity: int

    @app.post("/checkout")
    def checkout(order: Order):
        conn = _db.acquire_connection()  # always fails: pool exhausted
        return {"status": "ok", "conn": conn}

    @app.get("/order/{order_id}")
    def get_order(order_id: str):
        orders = {"1": "widget"}
        return {"item": orders[order_id]}  # KeyError for unknown ids

    @app.get("/inventory")
    def inventory():
        if random.random() < 0.7:
            raise ConnectionError("inventory-service unreachable at inventory:8080")
        return {"stock": 42}

    @app.get("/health")
    def health():
        return {"ok": True}

except ImportError:  # main() below never needs fastapi itself
    app = None


def main() -> None:
    import argparse
    import subprocess
    import sys
    from pathlib import Path

    import httpx

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("fastapi_sample.log"))
    parser.add_argument("--requests", type=int, default=40, help="Traffic rounds (4 requests each)")
    parser.add_argument("--port", type=int, default=8901)
    args = parser.parse_args()

    script_dir = Path(__file__).resolve().parent
    base = f"http://localhost:{args.port}"

    with args.output.open("w") as log_file:
        server = subprocess.Popen(
            [
                "uv",
                "run",
                "--with",
                "fastapi",
                "--with",
                "uvicorn",
                "uvicorn",
                f"{Path(__file__).stem}:app",
                "--app-dir",
                str(script_dir),
                "--port",
                str(args.port),
                "--log-level",
                "info",
            ],
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
        try:
            for _ in range(120):
                try:
                    httpx.get(f"{base}/health", timeout=1.0)
                    break
                except httpx.HTTPError:
                    if server.poll() is not None:
                        print("Server failed to start; see the log file.")
                        sys.exit(1)
                    time.sleep(0.5)
            else:
                print("Server never became healthy; see the log file.")
                sys.exit(1)

            rng = random.Random(7)
            with httpx.Client(timeout=5.0) as client:
                for _ in range(args.requests):
                    for method, url, kwargs in (
                        ("POST", "/checkout", {"json": {"item_id": 1, "quantity": 2}}),
                        ("GET", f"/order/{rng.randint(0, 4)}", {}),
                        ("GET", "/inventory", {}),
                        ("POST", "/checkout", {"json": {"bad": "payload"}}),
                    ):
                        try:
                            client.request(method, base + url, **kwargs)
                        except httpx.HTTPError:
                            pass
        finally:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()

    text = args.output.read_text(errors="replace")
    lines = text.count("\n")
    tracebacks = text.count("Traceback (most recent call last):")
    print(f"Wrote {lines} log lines ({tracebacks} real tracebacks) to {args.output}")
    print(f"Next: uv run python scripts/run_on_raw_log.py {args.output} --errors-only")


if __name__ == "__main__":
    main()
