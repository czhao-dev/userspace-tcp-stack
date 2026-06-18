# TCP State Machine — Annotated

The eleven states from RFC 793 §3.2 / RFC 9293 §3.3.2, and exactly
where each transition is implemented. Every transition below is one
`case` (or one branch within a `case`) in `process_segment()`,
the anonymous-namespace function in `src/tcp.cpp` that `handle_tcp()`
dispatches into per-connection.

```
                         CLOSE                    CLOSE
                  ┌────────────────┐       ┌────────────────┐
                  ▼                │       ▼                │
            ┌──────────┐           │ ┌──────────┐            │
            │  CLOSED  │           │ │  CLOSED  │            │
            └────┬─────┘           │ └────┬─────┘            │
                 │ LISTEN          │      │ active OPEN      │
                 ▼                 │      │ (send SYN)       │
            ┌──────────┐           │      ▼                  │
            │  LISTEN  │           │ ┌──────────┐             │
            └────┬─────┘           │ │ SYN_SENT │             │
                 │ recv SYN        │ └────┬─────┘             │
                 │ (send SYN,ACK)  │      │ recv SYN,ACK      │
                 ▼                 │      │ (send ACK)        │
            ┌──────────┐           │      ▼                   │
            │ SYN_RCVD │           │ ┌─────────────┐           │
            └────┬─────┘           │ │ ESTABLISHED │◀──────────┘
                 │ recv ACK        │ └──────┬──────┘
                 └─────────────────┴────────┤
                                   data transfer
                                             │ close() (send FIN)
                                             ▼
                                      ┌─────────────┐
                                      │ FIN_WAIT_1  │
                                      └──────┬──────┘
                              recv ACK       │       recv FIN+ACK
                          ┌──────────────────┴──────────────────┐
                          ▼                                     ▼
                  ┌─────────────┐                       ┌─────────────┐
                  │ FIN_WAIT_2  │                       │   CLOSING   │
                  └──────┬──────┘                       └──────┬──────┘
                         │ recv FIN (send ACK)                  │ recv ACK
                         ▼                                      │
                  ┌─────────────┐                               │
                  │  TIME_WAIT  │◀──────────────────────────────┘
                  └──────┬──────┘
                         │ 2×MSL timeout (shortened to 4s for demo purposes)
                         ▼
                  ┌──────────┐
                  │  CLOSED  │
                  └──────────┘
```

## Transition table

| Transition | RFC section | Where in `src/tcp.cpp` |
|---|---|---|
| `CLOSED → LISTEN` | RFC 9293 §3.10.1 | `tcp_listen()` — registers `(addr, port)` in `g_listeners`, no `TCPConnection` exists yet |
| `LISTEN → SYN_RCVD` | RFC 9293 §3.10.7.2 | `handle_tcp()`'s "no existing connection, SYN to a listening port" branch |
| `CLOSED → SYN_SENT` | RFC 9293 §3.10.1 (active open) | `tcp_connect()` |
| `SYN_SENT → ESTABLISHED` | RFC 9293 §3.10.7.3 | `process_segment()`, `case SYN_SENT`, on `SYN,ACK` whose `ack_num == snd_nxt` |
| `SYN_RCVD → ESTABLISHED` | RFC 9293 §3.10.7.4 | `process_segment()`, `case SYN_RCVD`, on `ACK` whose `ack_num == snd_nxt`; also `enqueue_accept()`s the connection here |
| `ESTABLISHED →` data transfer | RFC 9293 §3.10.7.4 | `case ESTABLISHED` → `receive_data_and_maybe_fin()` (in-order delivery, out-of-order buffering, FIN detection) + `flush_send()` (window-limited send) |
| `ESTABLISHED → FIN_WAIT_1` | RFC 9293 §3.10.4 (local close) | `tcp_close()`, `case ESTABLISHED` |
| `ESTABLISHED → CLOSE_WAIT` | RFC 9293 §3.10.7.4 (remote FIN) | `case ESTABLISHED`, when `receive_data_and_maybe_fin()` reports `fin_consumed` |
| `FIN_WAIT_1 → FIN_WAIT_2` | RFC 9293 §3.10.7.5 | `case FIN_WAIT_1`, `our_fin_acked && !fin` |
| `FIN_WAIT_1 → CLOSING` | RFC 9293 §3.10.7.5 (simultaneous close) | `case FIN_WAIT_1`, `!our_fin_acked && fin` |
| `FIN_WAIT_1 → TIME_WAIT` | RFC 9293 §3.10.7.5 (both at once) | `case FIN_WAIT_1`, `our_fin_acked && fin` |
| `FIN_WAIT_2 → TIME_WAIT` | RFC 9293 §3.10.7.5 | `case FIN_WAIT_2`, on remote FIN |
| `CLOSING → TIME_WAIT` | RFC 9293 §3.10.7.5 | `case CLOSING`, on ACK of our FIN |
| `CLOSE_WAIT → LAST_ACK` | RFC 9293 §3.10.4 | `tcp_close()`, `case CLOSE_WAIT` |
| `LAST_ACK → CLOSED` | RFC 9293 §3.10.7.5 | `case LAST_ACK`, on ACK of our FIN |
| `TIME_WAIT → CLOSED` | RFC 9293 §3.10.8 (2 MSL) | `tcp_tick()`, deadline check |
| `TIME_WAIT` re-ACKs a duplicate FIN | RFC 9293 §3.10.8 | `case TIME_WAIT` — re-sends the ACK and restarts the timer; this is the one case that *must* still respond, since it exists specifically to handle a lost final ACK |

## Simultaneous open and close

- **Simultaneous close** (both sides call `close()` before either has
  seen the other's FIN) **is handled**: `FIN_WAIT_1`'s branch for
  "remote FIN arrived but our FIN isn't acked yet" goes to `CLOSING`
  rather than assuming a strict half-duplex teardown order. This path
  is exercised directly in `tests/retransmission_test.cpp`, where the
  client and server close at effectively the same simulated instant.
- **Simultaneous open** (both sides send SYN to each other before
  either has sent SYN,ACK, RFC 9293 §3.10.7.3's `SYN_SENT` recv-SYN
  case) is **not implemented**. `process_segment()`'s `SYN_SENT` case
  only handles `SYN,ACK`; a bare `SYN` received in `SYN_SENT` is
  silently ignored rather than transitioning to `SYN_RCVD` and merging
  the two handshakes. This is an explicit, documented scope cut —
  simultaneous open is rare in practice (it requires both peers to
  initiate a connection to each other at the same moment using
  pre-arranged ports) and meaningfully complicates ISN/state
  bookkeeping for a case the project's interoperability goals
  (talking to real `nc`/`curl`/`ping`) never exercise.
- Real TCP stacks also retain a `RST`-on-unexpected-segment behavior
  for unmatched connections; MiniTCP implements a minimal version of
  this (`send_rst_for_unknown()` in `src/tcp.cpp`) so a segment
  arriving for a port nobody is listening on gets a `RST,ACK` rather
  than silent drop — visible in the trace as `port N unreachable`.

## Why no real congestion control

The README's Phase 5 lists slow-start `cwnd` as an explicit, optional
stretch goal. MiniTCP implements the rest of RFC 6298-style
reliability (single retransmission timer, exponential backoff, capped
retries) but **does not** implement a congestion window — `snd_wnd`
here is purely the *receiver's advertised flow-control window*, never
reduced by a sender-side congestion estimate. Given the project's
scope was already dominated by the state machine, sliding window, and
out-of-order reassembly, a real congestion control algorithm (even
basic slow start, let alone Reno/CUBIC) was cut to keep the surface
area manageable — noted here rather than silently, per the README's
own framing of that task.
