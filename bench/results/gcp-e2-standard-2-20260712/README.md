# GCP benchmark result — 2026-07-12

- **VM:** Google Compute Engine `e2-standard-2`, `us-central1-a`, Ubuntu
  22.04, Linux `6.8.0-1063-gcp`; the captured CPU metadata is in `lscpu.txt`.
- **Source:** `e76a00d` (recorded in `git-revision.txt`).
- **Workload:** one warm-up followed by five measured 4 MiB transfers from a
  kernel TCP client to `bench_echo_server` over `tun0`; the server echoed each
  payload through MiniTCP. This is a single-client, same-VM end-to-end TUN
  measurement, not Internet or multi-connection throughput.
- **Result:** median application-payload throughput **22.38 MiB/s** (mean
  22.31 MiB/s; range 21.83–22.60 MiB/s). Per-trial samples are in `echo.json`;
  `echo-throughput.png` is the matplotlib plot of throughput and elapsed time.
