#!/usr/bin/env python3
"""Measure full-duplex TCP echo throughput through a MiniTCP TUN endpoint."""
from __future__ import annotations

import argparse
import json
import socket
import statistics
import threading
import time
from pathlib import Path


def transfer(host: str, port: int, payload_bytes: int, timeout_seconds: float) -> dict[str, float | int]:
    chunk = b"x" * min(64 * 1024, payload_bytes)
    received = 0
    reader_error: list[str] = []

    start = time.perf_counter()
    with socket.create_connection((host, port), timeout=timeout_seconds) as sock:
        sock.settimeout(timeout_seconds)

        def drain_echo() -> None:
            nonlocal received
            try:
                while received < payload_bytes:
                    block = sock.recv(min(64 * 1024, payload_bytes - received))
                    if not block:
                        break
                    received += len(block)
            except OSError as exc:
                reader_error.append(str(exc))

        reader = threading.Thread(target=drain_echo)
        reader.start()

        sent = 0
        while sent < payload_bytes:
            remaining = payload_bytes - sent
            sock.sendall(chunk[: min(len(chunk), remaining)])
            sent += min(len(chunk), remaining)
        sock.shutdown(socket.SHUT_WR)
        reader.join(timeout_seconds)

    elapsed = time.perf_counter() - start
    if reader.is_alive():
        raise RuntimeError(f"echo reader did not finish within {timeout_seconds}s")
    if reader_error:
        raise RuntimeError(f"echo reader failed: {reader_error[0]}")
    if received != payload_bytes:
        raise RuntimeError(f"echo mismatch: sent {payload_bytes} bytes, received {received}")

    return {
        "bytes": payload_bytes,
        "elapsed_seconds": elapsed,
        "throughput_mib_per_second": payload_bytes / elapsed / (1024 * 1024),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="10.0.0.2")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--payload-mib", type=int, default=4)
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument("--trials", type=int, default=5)
    parser.add_argument("--timeout-seconds", type=float, default=120.0)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    if args.payload_mib <= 0 or args.warmup < 0 or args.trials <= 0:
        parser.error("payload size and trial count must be positive; warmup may be zero")

    payload_bytes = args.payload_mib * 1024 * 1024
    for _ in range(args.warmup):
        transfer(args.host, args.port, payload_bytes, args.timeout_seconds)

    trials = [transfer(args.host, args.port, payload_bytes, args.timeout_seconds) for _ in range(args.trials)]
    throughputs = [trial["throughput_mib_per_second"] for trial in trials]
    result = {
        "benchmark": "minitcp_tun_echo",
        "host": args.host,
        "port": args.port,
        "payload_bytes": payload_bytes,
        "warmup_trials": args.warmup,
        "measured_trials": trials,
        "summary": {
            "median_mib_per_second": statistics.median(throughputs),
            "mean_mib_per_second": statistics.mean(throughputs),
            "min_mib_per_second": min(throughputs),
            "max_mib_per_second": max(throughputs),
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], indent=2))


if __name__ == "__main__":
    main()
