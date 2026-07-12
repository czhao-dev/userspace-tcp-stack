#!/usr/bin/env python3
"""Create matplotlib plots from `run_echo_benchmark.py` JSON output."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib.pyplot as plt


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    result = json.loads(args.input.read_text(encoding="utf-8"))
    trials = result["measured_trials"]
    indexes = list(range(1, len(trials) + 1))
    throughput = [trial["throughput_mib_per_second"] for trial in trials]
    elapsed = [trial["elapsed_seconds"] for trial in trials]
    summary = result["summary"]

    figure, (throughput_ax, elapsed_ax) = plt.subplots(1, 2, figsize=(11, 4.5), layout="constrained")
    figure.suptitle("MiniTCP TUN Echo Benchmark")

    throughput_ax.plot(indexes, throughput, marker="o", color="#1f77b4")
    throughput_ax.axhline(summary["median_mib_per_second"], color="#ff7f0e", linestyle="--", label="median")
    throughput_ax.set(title="Throughput by trial", xlabel="Measured trial", ylabel="MiB/s")
    throughput_ax.set_xticks(indexes)
    throughput_ax.legend()
    throughput_ax.grid(axis="y", alpha=0.25)

    elapsed_ax.bar(indexes, elapsed, color="#2ca02c")
    elapsed_ax.set(title=f"Elapsed time ({result['payload_bytes'] / (1024 * 1024):g} MiB echo)", xlabel="Measured trial", ylabel="Seconds")
    elapsed_ax.set_xticks(indexes)
    elapsed_ax.grid(axis="y", alpha=0.25)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(args.output, dpi=160)


if __name__ == "__main__":
    main()
