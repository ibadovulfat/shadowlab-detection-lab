from __future__ import annotations

import argparse
import concurrent.futures
import time
from statistics import mean

import requests


def run_once(base_url: str, path: str, timeout: float) -> tuple[int, float]:
    started = time.perf_counter()
    response = requests.get(base_url.rstrip("/") + path, timeout=timeout)
    duration = time.perf_counter() - started
    return response.status_code, duration


def main() -> None:
    parser = argparse.ArgumentParser(description="Simple ShadowLab HTTP load test")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--path", default="/health")
    parser.add_argument("--requests", type=int, default=100)
    parser.add_argument("--concurrency", type=int, default=10)
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as executor:
        results = list(executor.map(lambda _: run_once(args.base_url, args.path, args.timeout), range(max(1, args.requests))))

    statuses = {}
    durations = []
    for status, duration in results:
        statuses[status] = statuses.get(status, 0) + 1
        durations.append(duration)

    print("ShadowLab Load Test")
    print(f"Target: {args.base_url.rstrip('/') + args.path}")
    print(f"Requests: {len(results)}")
    print(f"Concurrency: {args.concurrency}")
    print(f"Mean latency: {mean(durations):.4f}s")
    print(f"Max latency: {max(durations):.4f}s")
    print(f"Status counts: {statuses}")


if __name__ == "__main__":
    main()
