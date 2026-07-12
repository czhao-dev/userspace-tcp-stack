# Benchmarking MiniTCP

`run_gcp_vm.sh` measures full-duplex echo throughput between a kernel TCP
client and `bench_echo_server`, which runs on MiniTCP through `tun0`. It runs
one warm-up and five measured 4 MiB echo transfers by default, writes the raw
JSON results plus machine metadata, and uses matplotlib to create a PNG plot.

Run it on a Linux VM with `/dev/net/tun` and passwordless `sudo`:

```bash
./bench/run_gcp_vm.sh
```

The script installs its runtime dependencies, builds the release binary, and
tears down `tun0` on exit. Override `PAYLOAD_MIB`, `WARMUP_TRIALS`,
`MEASURED_TRIALS`, and `RESULT_DIR` to change a run. The benchmark is a
single-client end-to-end measurement; it does not claim multi-connection
scalability or wire-network throughput.
