# MiniTCP — A User-Space TCP/IP Stack

[![C++](https://img.shields.io/badge/C%2B%2B-17-00599C?logo=c%2B%2B&logoColor=white)](https://en.cppreference.com/w/cpp/17)
[![CMake](https://img.shields.io/badge/build-CMake%203.20%2B-064F8C?logo=cmake&logoColor=white)](https://cmake.org/)
[![Docker](https://img.shields.io/badge/dev%20env-Docker-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%2F%20TUN-FCC624?logo=linux&logoColor=black)](https://www.kernel.org/)
[![Tests](https://img.shields.io/badge/tests-5%2F5%20passing-brightgreen)](#test-results)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

> A TCP/IP protocol stack implemented entirely in user space over a Linux TUN
> virtual network interface — IP, ICMP, UDP, and a full eleven-state TCP
> state machine with sliding-window flow control, retransmission, and
> out-of-order reassembly — interoperable with real tools like `ping`,
> `curl`, and `netcat` against the actual Linux network stack, and with a
> second instance of itself across two TUN devices bridged by the kernel.

---

## Overview

MiniTCP implements the core of the TCP/IP protocol suite from raw packet
bytes upward, bypassing the kernel's own network stack by reading and writing
IP packets directly through a TUN device. The kernel hands MiniTCP raw IP
packets; everything above that — header parsing, checksums, the ICMP echo
protocol, UDP, and the full TCP connection lifecycle — is implemented by hand.

The project is intentionally small enough to inspect end to end while still
behaving like a real network endpoint. A `connect()` from `curl` or `netcat`
turns into raw TCP segments on the TUN device; MiniTCP parses those packets,
updates protocol state, generates replies, retransmits lost data, and delivers
application bytes in order.

The TCP implementation is centered on an explicit finite state machine:
`LISTEN`, `SYN_RCVD`, `ESTABLISHED`, `FIN_WAIT`, `TIME_WAIT`, `CLOSED`, and
the other RFC-defined states are represented directly in code. Each transition
is driven by incoming segment flags, local API calls, retransmission timers, or
connection teardown events, including less common cases such as simultaneous
close and FIN retransmission while in `TIME_WAIT`.

---

## What MiniTCP Implements

**IP layer** — `include/ip.h`, `src/ip.cpp`
Parses and constructs IPv4 headers: version, header length, total length,
TTL, protocol field, header checksum, source and destination addresses.
Validates the header checksum on receipt and recomputes it on send.

**ICMP** — `include/icmp.h`, `src/icmp.cpp`
Responds to ICMP Echo Request (type 8) with Echo Reply (type 0), so the
real `ping` command run against MiniTCP's virtual IP address gets a correct
reply.

**UDP** — `include/udp.h`, `src/udp.cpp`
Parses and constructs UDP headers (source port, destination port, length,
checksum, including the 12-byte pseudo-header). A datagram is delivered to
an application socket if one is bound to its destination `(address, port)`;
otherwise it's echoed back to the sender, exactly as before the socket-level
UDP API existed.

**TCP** — `include/tcp.h`, `src/tcp.cpp` (the centerpiece)

- The three-way handshake: `SYN` → `SYN-ACK` → `ACK`
- The full eleven-state connection state machine (RFC 793 / RFC 9293),
  including the simultaneous-close edge case — see
  [docs/state_machine.md](docs/state_machine.md)
- Sliding-window flow control using the receive window field
- Per-segment retransmission with exponential backoff (RFC 6298-style,
  single timer per connection)
- In-order delivery: out-of-order segments are buffered and spliced in once
  gaps are filled
- Graceful connection teardown in both directions: local-initiated close
  and remote-initiated close are genuinely different code paths, both
  tested against real `nc`
- `TIME_WAIT` correctly re-ACKs a retransmitted FIN (the scenario
  `TIME_WAIT` exists to handle) rather than silently dropping it

Slow-start congestion control was scoped out — see
[docs/state_machine.md](docs/state_machine.md#why-no-real-congestion-control)
for why.

**Socket-like API** — `include/socket_api.h`, `src/socket_api.cpp`
A small wrapper so application code looks like BSD sockets and never
touches `TCPConnection`/`TCPState`/`UDPSocket` directly:

- TCP: `minitcp_socket`, `minitcp_listen`, `minitcp_accept`, `minitcp_connect`,
  `minitcp_send`, `minitcp_recv`, `minitcp_close`. Used by both demo apps
  below.
- UDP: `minitcp_udp_socket`, `minitcp_bind`, `minitcp_sendto`,
  `minitcp_recvfrom`, addressed with the real POSIX `struct sockaddr_in`
  rather than a custom type.
- Socket options: `minitcp_setsockopt`/`minitcp_getsockopt` mirror POSIX's
  signature and reuse its `SOL_SOCKET`/`SO_*` constants. Four are wired up
  to real, observable behavior rather than just stored — `SO_RCVTIMEO`
  makes `recv`/`recvfrom`/`accept` actually stop blocking, `SO_REUSEADDR`
  lets `listen()` bypass a port still occupied by a connection in
  `TIME_WAIT`, and `SO_RCVBUF`/`SO_SNDBUF` tune the per-socket buffer caps.
  All four are opt-in and don't change the behavior of any call site that
  doesn't use them.

**Demo apps** — `apps/chat_server.cpp`, `apps/chat_client.cpp`
A minimal chat server/client built only on the socket API. The server also
recognizes HTTP requests and answers with a fixed `200 OK`, so the same
listener serves both `nc` chat sessions and `curl`.

---

## TCP State Machine

This is the core TCP lifecycle implemented by MiniTCP. See
[docs/state_machine.md](docs/state_machine.md) for an annotated version with
the RFC section and implementing function for every transition.

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
                         │ 2×MSL timeout
                         ▼
                  ┌──────────┐
                  │  CLOSED  │
                  └──────────┘
```

---

## Architecture

```
Application (chat client/server, or a manual test harness)
        │
        ▼
 Socket-like API     TCP: connect/listen/accept/send/recv
                     UDP: bind/sendto/recvfrom (sockaddr_in, setsockopt)
        │
        ▼
 TCP                 state machine, sliding window, retransmission
        │
        ▼
 UDP / ICMP           UDP: deliver to a bound socket, else auto-echo
                      ICMP: echo reply
        │
        ▼
 IP                  header parse/construct, checksum, routing decision
        │
        ▼
 TUN device           /dev/net/tun — kernel hands us raw IP packets
        │
        ▼
 Linux kernel routing / real network
        │
        ▼
 External tools: ping, curl, netcat — talk to MiniTCP as a real IP endpoint
```

The TUN device is the key piece of infrastructure that makes this project
both tractable and demonstrable. The kernel handles Ethernet framing and
physical transmission; MiniTCP only ever sees and produces IP packets,
which keeps the scope focused on the protocols that matter, while still
producing a stack that real, unmodified tools can talk to.

Development happens on macOS via Docker (a Linux container, since TUN/TAP
needs a real Linux kernel); the same `Dockerfile`/`docker-compose.yml` work
unmodified on a native Linux host.

---

## Example Session — Real Trace, Not a Mockup

Captured live: `chat_server --trace` running on `tun0` (self address
`10.0.0.2`), a real `nc 10.0.0.2 8080` from a second shell in the same
container.

```
chat_server: listening on port 8080 (self=10.0.0.2, tun=tun0)
[IP  ] recv  10.0.0.1 -> 10.0.0.2   proto=TCP  len=60
[TCP ] recv  SYN         seq=1842910416 ack=0 win=64240 len=20  state=LISTEN
[TCP ] state LISTEN -> SYN_RCVD
[TCP ] send  SYN,ACK     seq=531850564 ack=1842910417 win=65535 len=0
[IP  ] recv  10.0.0.1 -> 10.0.0.2   proto=TCP  len=40
[TCP ] recv  ACK         seq=1842910417 ack=531850565 win=64240 len=0  state=SYN_RCVD
[TCP ] state SYN_RCVD -> ESTABLISHED
chat_server: client connected

--- connection established, application can now send/recv ---

[IP  ] recv  10.0.0.1 -> 10.0.0.2   proto=TCP  len=46
[TCP ] recv  ACK,PSH     seq=1842910417 ack=531850565 win=64240 len=6  state=ESTABLISHED
[TCP ] send  ACK         seq=531850565 ack=1842910423 win=65530 len=0
hello
[TCP ] send  ACK,PSH     seq=531850565 ack=1842910423 win=65535 len=6

[IP  ] recv  10.0.0.1 -> 10.0.0.2   proto=TCP  len=40
[TCP ] recv  ACK,FIN     seq=1842910423 ack=531850571 win=64234 len=0  state=ESTABLISHED
[TCP ] send  ACK         seq=531850571 ack=1842910424 win=65535 len=0
[TCP ] state ESTABLISHED -> CLOSE_WAIT
chat_server: client disconnected
[TCP ] send  ACK,FIN     seq=531850571 ack=1842910424 win=65535 len=0
[TCP ] state CLOSE_WAIT -> LAST_ACK
[IP  ] recv  10.0.0.1 -> 10.0.0.2   proto=TCP  len=40
[TCP ] recv  ACK         seq=1842910424 ack=531850572 win=64234 len=0  state=LAST_ACK
[TCP ] state LAST_ACK -> CLOSED
```

`curl` against the same listener, proving the stack is indistinguishable
from a real one to a completely unmodified HTTP client:

```
$ curl -s -i http://10.0.0.2:8080/
HTTP/1.1 200 OK
Content-Length: 6
Connection: close

hello
```

---

## Test Results

Five test binaries, run via `ctest`:

```
Test project /minitcp/build
    Start 1: checksum_test
1/5 Test #1: checksum_test ....................   Passed    0.00 sec
    Start 2: tcp_state_test
2/5 Test #2: tcp_state_test ...................   Passed    0.00 sec
    Start 3: retransmission_test
3/5 Test #3: retransmission_test ..............   Passed   13.10 sec
    Start 4: udp_socket_test
4/5 Test #4: udp_socket_test ..................   Passed    0.00 sec
    Start 5: sockopt_test
5/5 Test #5: sockopt_test .....................   Passed    0.21 sec

100% tests passed, 0 tests failed out of 5
```

- **`checksum_test`** — the RFC 1071 worked example, a build/verify
  round-trip, and an odd-length edge case.
- **`tcp_state_test`** — drives `handle_tcp()` directly with hand-crafted
  segments (no TUN device): three data segments delivered **out of
  order** (`C, A, B`) are reassembled correctly before being handed to the
  application, then the connection is torn down via remote-FIN → local
  `close()`.
- **`retransmission_test`** — two in-process TCP endpoints connected over a
  lossy simulated link (a real packet-loss harness, not a mock), run at
  0%, 10%, and 30% simulated loss:

  ```
  retransmission_test: drop_rate=  0%  completed OK  (simulated drops: 0, data: "hello from minitcp client")
  retransmission_test: drop_rate= 10%  completed OK  (simulated drops: 1, data: "hello from minitcp client")
  retransmission_test: drop_rate= 30%  completed OK  (simulated drops: 2, data: "hello from minitcp client")
  retransmission_test: all trials passed
  ```

  Every trial completes the full handshake → data transfer → simultaneous
  teardown sequence correctly regardless of loss rate — just with more
  retransmissions logged at higher loss.

- **`udp_socket_test`** — drives `udp.h`/`tcp.h` directly (no TUN device):
  a `sendto`/`recvfrom`-style round trip through a bound `UDPSocket`, a
  datagram dropped when it would exceed the `SO_RCVBUF` cap, the auto-echo
  fallback still firing when nothing is bound to a port, and the
  `SO_REUSEADDR` guard in `tcp_listen` — blocked by a connection sitting in
  `TIME_WAIT`, then allowed through once `reuse_addr` is set.
- **`sockopt_test`** — exercises `minitcp_setsockopt`/`getsockopt` end to
  end against a real (in-process) blocking call, using `minitcp_init_with_fd()`
  with a `socketpair` standing in for the TUN device: `SO_RCVTIMEO` actually
  causes an idle `minitcp_recvfrom()` to return a timeout instead of
  blocking forever, and `SO_REUSEADDR`/`SO_RCVBUF`/`SO_SNDBUF` round-trip
  correctly through `getsockopt`.

**Manually verified against real, unmodified tools** (see
[Build & Run](#build--run) for the exact commands):

| Scenario | Tool | Result |
|---|---|---|
| ICMP echo | `ping -c 4 10.0.0.2` | 4/4 replies, correct trace |
| UDP echo | `nc -u 10.0.0.2 9000` | line echoed back |
| TCP handshake + chat, remote-initiated close | `nc 10.0.0.2 8080` | `SYN→SYN,ACK→ACK→ESTABLISHED`, data echoed, clean `FIN→CLOSE_WAIT→LAST_ACK→CLOSED` |
| TCP + HTTP, local-initiated close | `curl http://10.0.0.2:8080/` | correct `200 OK`, clean `FIN_WAIT_1→FIN_WAIT_2→TIME_WAIT→CLOSED` |
| MiniTCP talking to MiniTCP | `chat_client` ↔ `chat_server` on separate TUN devices, bridged by real kernel IP forwarding | full two-party conversation over our own TCP implementation on both ends |
| UDP socket API | a small program using `minitcp_udp_socket`/`bind`/`recvfrom`/`sendto`, exercised with `nc -u 10.0.0.2 <port>` | bound port: trace shows `deliver -> bound app socket`, the app echoes the datagram; a *different*, unbound port still auto-echoes as before |
| `SO_RCVTIMEO` | the same program, left idle with a 1s receive timeout set | `minitcp_recvfrom` returns the timeout sentinel once a second instead of blocking forever |

---

## Repo Structure

```
minitcp/
├── README.md
├── docker/
│   └── Dockerfile           ← Linux dev/runtime environment (TUN needs real Linux)
├── docker-compose.yml
├── include/
│   ├── tun.h
│   ├── ip.h
│   ├── icmp.h
│   ├── udp.h
│   ├── tcp.h                ← state machine, segment structs
│   ├── dispatch.h            ← shared IP-packet dispatch, used by main.cpp and socket_api.cpp
│   └── socket_api.h
├── src/
│   ├── tun.cpp                ← open/configure the TUN device
│   ├── ip.cpp                  ← header parse/construct, checksum
│   ├── icmp.cpp                  ← echo request/reply
│   ├── udp.cpp
│   ├── tcp.cpp                     ← the core: state machine + reliability
│   ├── dispatch.cpp
│   ├── socket_api.cpp
│   └── main.cpp                      ← event loop: read TUN, dispatch by protocol
├── apps/
│   ├── chat_server.cpp                ← demo app: chat + HTTP, built on the socket API
│   └── chat_client.cpp
├── tests/
│   ├── checksum_test.cpp
│   ├── tcp_state_test.cpp              ← drive the state machine with crafted segments
│   ├── retransmission_test.cpp           ← simulate packet loss, verify retry + backoff
│   ├── udp_socket_test.cpp                 ← UDP bind/sendto/recvfrom, echo fallback, SO_REUSEADDR
│   └── sockopt_test.cpp                      ← setsockopt/getsockopt, SO_RCVTIMEO actually timing out
├── scripts/
│   ├── setup_tun.sh                       ← create tun0/tun1 with point-to-point addressing
│   └── teardown_tun.sh
└── docs/
    ├── protocol_notes.md                    ← header layouts, byte offsets, checksum algorithm
    └── state_machine.md                       ← annotated FSM, RFC sections, scope cuts
```

---

## Build & Run

MiniTCP needs a real Linux TUN device, so on macOS (or any non-Linux host)
development happens inside a Docker container. On native Linux, skip the
Docker steps and just run the `cmake`/`make` + script commands directly.

```bash
# Build the dev image and start the container (repo is bind-mounted)
docker compose up -d
docker compose exec minitcp bash      # "Shell A", inside the container from here on

# Build
mkdir -p build && cd build
cmake -G Ninja .. && ninja            # (or: cmake .. && make -j$(nproc))

# Run the unit tests (no TUN device needed — segments are crafted in-memory)
ctest --output-on-failure

# Create tun0 (point-to-point: 10.0.0.1 is the kernel side, 10.0.0.2 is
# MiniTCP's own address — see the note below on why this matters)
sudo ../scripts/setup_tun.sh

# Run the chat/HTTP demo server
sudo ./apps/chat_server --trace --port 8080
```

In a **second** `docker exec -it minitcp-dev bash` (a real second terminal
into the *same* container — see note below), exercise it with real tools:

```bash
ping -c 4 10.0.0.2                      # ICMP path
nc -u 10.0.0.2 9000                     # UDP echo
nc 10.0.0.2 8080                        # TCP chat — type lines, see them echoed
curl http://10.0.0.2:8080/              # TCP + the toy HTTP response
```

To watch MiniTCP talk to a *second instance of itself* across two TUN
devices bridged by the real kernel routing table:

```bash
# Still in Shell A / a third exec'd shell:
cat /proc/sys/net/ipv4/ip_forward       # must be 1; if not: sudo sysctl -w net.ipv4.ip_forward=1
sudo ip tuntap add dev tun1 mode tun
sudo ip addr add 10.0.1.1 peer 10.0.1.2 dev tun1
sudo ip link set tun1 up

./apps/chat_client --tun tun1 --addr 10.0.1.2 --server 10.0.0.2 --port 8080
```

Tear down when done:

```bash
sudo ../scripts/teardown_tun.sh
```

### Why point-to-point addressing?

`setup_tun.sh` assigns `10.0.0.1` to the kernel side of `tun0` and
`10.0.0.2` as its **peer** address, then everything above (`ping`, `nc`,
`curl`, `chat_client`) targets `10.0.0.2` — never `10.0.0.1`. A plain
same-subnet address (`10.0.0.1/24`) doesn't work for testing *inside a
single container*: both the test client and MiniTCP would share one network
namespace, so the kernel would recognize `10.0.0.1` as already locally
owned and answer pings itself via loopback delivery, without the packet
ever reaching MiniTCP's `tun_read()`. Point-to-point addressing forces
traffic to the peer address to actually route out through `tun0`, into
MiniTCP's own code.

---

## Implementation Notes

MiniTCP handles TCP reliability with a deliberately simple retransmission
model: each connection tracks unacknowledged segments and uses a single
per-connection retransmission timer with exponential backoff. This keeps the
mechanism compact while still exercising the core behavior required for data
delivery over a lossy link.

Out-of-order data is buffered until the missing sequence range arrives, then
spliced back into the receive stream before being exposed through
`minitcp_recv`. The `tcp_state_test` covers this by delivering three data
segments in the order `C, A, B` and verifying that the application receives
the original byte stream.

Connection teardown is implemented as separate local-close and remote-close
paths. `TIME_WAIT` also re-ACKs retransmitted FINs, which is necessary when
the final ACK is lost and the peer retries its FIN.

Selective acknowledgment (`SACK`) and full congestion control are natural
future extensions. The current implementation focuses on correctness of the
core connection lifecycle, retransmission, in-order delivery, and
interoperability with real Linux networking tools.

UDP's socket layer and the new socket options were added without changing
any existing call site's behavior. `handle_udp()` only stops auto-echoing a
port once an application explicitly binds a `UDPSocket` to it; nothing else
observes the difference. Socket options are genuinely wired up rather than
just stored: `SO_RCVTIMEO` bounds the same `pump_once()`-driven blocking
loops that `minitcp_recv`/`minitcp_accept` always used, `SO_REUSEADDR`
bypasses a real "address in use" check added to `tcp_listen()` for a port
held by a connection in `TIME_WAIT`, and `SO_RCVBUF`/`SO_SNDBUF` resize the
buffer caps that used to be fixed constants on `TCPConnection`. Because a
fresh socket never touches these options, every existing demo app and test
keeps its original behavior by default.

---

## Further Reading

- [docs/protocol_notes.md](docs/protocol_notes.md) — header layouts, byte
  offsets, the checksum algorithm with a worked example, and known
  limitations
- [docs/state_machine.md](docs/state_machine.md) — every transition mapped
  to its RFC section and implementing code, plus the simultaneous-open/close
  discussion
- [RFC 9293 — Transmission Control Protocol (TCP)](https://www.rfc-editor.org/rfc/rfc9293) —
  the current standard; supersedes the original RFC 793
- [RFC 791 — Internet Protocol](https://www.rfc-editor.org/rfc/rfc791)
- [Beej's Guide to Network Programming](https://beej.us/guide/bgnet/) —
  the standard reference for raw sockets and TUN/TAP setup
- *TCP/IP Illustrated, Volume 1* — W. Richard Stevens — the canonical text;
  Chapters 17–24 cover the TCP state machine and reliability mechanisms in
  the depth this project implements
- [level-ip](https://github.com/saminiir/level-ip) — a similar open-source
  user-space TCP/IP stack; useful as a reference implementation to compare
  design decisions against, not to copy from directly
