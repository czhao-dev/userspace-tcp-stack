# MiniTCP — A User-Space TCP/IP Stack

> A TCP/IP protocol stack implemented entirely in user space over a Linux TUN
> virtual network interface — IP, ICMP, UDP, and a full TCP state machine
> with sliding-window reliability — interoperable with real tools like `ping`,
> `curl`, and `netcat` against the actual Linux network stack.

---

## Overview

MiniTCP implements the core of the TCP/IP protocol suite from raw packet
bytes upward, bypassing the kernel's own network stack by reading and writing
IP packets directly through a TUN device. The kernel hands MiniTCP raw IP
packets; everything above that — header parsing, checksums, the ICMP echo
protocol, UDP, and the full TCP connection lifecycle — is implemented by hand.

This is the same class of work done by network driver teams, NIC vendors
(Mellanox/NVIDIA, Broadcom), and embedded systems teams implementing
lightweight stacks (lwIP, picoTCP) for resource-constrained devices. It
demonstrates that you understand what actually happens between a `connect()`
call and bytes arriving in order on the other end — knowledge that is
increasingly rare as most engineers only ever interact with sockets through
a high-level API.

There is also a direct line back to EDA and digital design: the TCP state
machine — `LISTEN`, `SYN_RCVD`, `ESTABLISHED`, `FIN_WAIT`, `CLOSED`, and the
transitions between them — is a finite state machine in the same formal sense
as the FSMs verified in RTL. Implementing TCP's state machine by hand and
reasoning about every transition is, in a real sense, protocol verification
work — a connection point worth making explicitly to an EDA or verification
audience.

---

## What MiniTCP Implements

**IP layer**
Parses and constructs IPv4 headers: version, header length, total length,
TTL, protocol field, header checksum, source and destination addresses.
Validates the header checksum on receipt and recomputes it on send.

**ICMP**
Responds to ICMP Echo Request (type 8) with Echo Reply (type 0), so the
real `ping` command run against MiniTCP's virtual IP address gets a correct
reply — the first end-to-end correctness test and the easiest one to
demonstrate live.

**UDP**
Parses and constructs UDP headers (source port, destination port, length,
checksum) and exposes a minimal `udp_send` / `udp_recv` API. Used as a
stepping stone before TCP because it has no connection state to manage.

**TCP**
The centerpiece of the project. Implements:

- The three-way handshake: `SYN` → `SYN-ACK` → `ACK`
- The full connection state machine (eleven states per RFC 793 /
  RFC 9293, see diagram below)
- Sliding-window flow control using the receive window field
- Per-segment retransmission timers with exponential backoff
- In-order delivery: out-of-order segments are buffered and only released
  to the application once gaps are filled
- Graceful connection teardown: `FIN` / `FIN-ACK` / `ACK` in both directions
- A minimal slow-start congestion control window (optional stretch goal)

**Socket-like API**
A small wrapper (`minitcp_socket`, `minitcp_connect`, `minitcp_listen`,
`minitcp_accept`, `minitcp_send`, `minitcp_recv`, `minitcp_close`) so
application code using MiniTCP looks similar to BSD sockets, making the
stack demoable with a simple chat client/server built on top of it.

---

## TCP State Machine

This is the diagram you should be able to redraw from memory in an
interview — it is the core of the project.

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

Every arrow above corresponds to one `case` in the TCP segment-processing
switch statement in `src/tcp.cpp`. Implementing this correctly — including
the simultaneous-close and simultaneous-open edge cases — is the single
hardest part of the project and the part most worth discussing in depth in
an interview.

---

## Architecture

```
Application (chat client/server, or a manual test harness)
        │
        ▼
 Socket-like API     minitcp_connect / listen / accept / send / recv
        │
        ▼
 TCP                 state machine, sliding window, retransmission
        │
        ▼
 UDP / ICMP           connectionless protocols, simpler to implement first
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

---

## Example Session — Three-Way Handshake Trace

This is the kind of end-to-end trace worth walking through in an interview.

**Setup:** MiniTCP is running on TUN interface `tun0` at `10.0.0.1`, listening
on port `8080`. A real client runs `nc 10.0.0.1 8080`.

```
[IP ]  recv  10.0.0.2 → 10.0.0.1   proto=TCP  len=44
[TCP]  recv  SYN       seq=1000              flags=SYN
[TCP]  state LISTEN → SYN_RCVD
[TCP]  send  SYN,ACK   seq=5000  ack=1001     flags=SYN,ACK
[IP ]  recv  10.0.0.2 → 10.0.0.1   proto=TCP  len=40
[TCP]  recv  ACK       seq=1001  ack=5001     flags=ACK
[TCP]  state SYN_RCVD → ESTABLISHED

--- connection established, application can now send/recv ---

[IP ]  recv  10.0.0.2 → 10.0.0.1   proto=TCP  len=52
[TCP]  recv  PSH,ACK   seq=1001  ack=5001     flags=PSH,ACK  data="hello\n"
[TCP]  send  ACK       seq=5001  ack=1007     flags=ACK
[APP]  recv  "hello\n"

[TCP]  recv  FIN,ACK   seq=1007  ack=5001     flags=FIN,ACK
[TCP]  state ESTABLISHED → CLOSE_WAIT
[TCP]  send  ACK       seq=5001  ack=1008     flags=ACK
[APP]  close()
[TCP]  send  FIN,ACK   seq=5001  ack=1008     flags=FIN,ACK
[TCP]  state CLOSE_WAIT → LAST_ACK
[TCP]  recv  ACK       seq=1008  ack=5002     flags=ACK
[TCP]  state LAST_ACK → CLOSED
```

This log format — implemented behind a `--trace` flag — is what makes the
project demoable in an interview: you can run `nc` against your own stack
live and narrate exactly what is happening at each line.

---

## Repo Structure

```
minitcp/
├── README.md
├── include/
│   ├── tun.h
│   ├── ip.h
│   ├── icmp.h
│   ├── udp.h
│   ├── tcp.h               ← state machine, segment structs
│   └── socket_api.h
├── src/
│   ├── tun.cpp              ← open/configure the TUN device
│   ├── ip.cpp               ← header parse/construct, checksum
│   ├── icmp.cpp              ← echo request/reply
│   ├── udp.cpp
│   ├── tcp.cpp               ← the core: state machine + reliability
│   ├── socket_api.cpp
│   └── main.cpp              ← event loop: read TUN, dispatch by protocol
├── apps/
│   ├── chat_server.cpp       ← demo app built on the socket API
│   └── chat_client.cpp
├── tests/
│   ├── checksum_test.cpp
│   ├── tcp_state_test.cpp    ← drive the state machine with crafted segments
│   └── retransmission_test.cpp ← simulate packet loss, verify retry + backoff
├── scripts/
│   ├── setup_tun.sh          ← create and configure tun0 with sudo
│   └── teardown_tun.sh
└── docs/
    ├── protocol_notes.md     ← TCP/IP header layouts, checksum algorithm
    └── state_machine.md      ← annotated version of the FSM diagram above
```

---

## Build & Run

```bash
# Dependencies: Linux (TUN/TAP requires the Linux kernel), CMake 3.20+,
# a C++17 compiler. Root/sudo is required to create the TUN interface.

# Build
mkdir build && cd build
cmake ..
make -j$(nproc)

# Create and configure the TUN interface (run once, requires sudo)
sudo ../scripts/setup_tun.sh    # creates tun0 at 10.0.0.1/24

# Run the stack (own terminal, requires sudo for raw TUN access)
sudo ./minitcp --trace

# In a second terminal — real tools talking to your stack:
ping 10.0.0.1                      # exercises the ICMP path
nc 10.0.0.1 8080                   # exercises the TCP path
curl http://10.0.0.1:8080/         # exercises TCP + a toy HTTP echo

# Run the demo chat server built on the socket API
sudo ./apps/chat_server --port 8080
# from another machine or terminal:
nc 10.0.0.1 8080

# Run correctness tests (no TUN device needed — segments are crafted in-memory)
./tests/tcp_state_test
./tests/retransmission_test

# Tear down
sudo ../scripts/teardown_tun.sh
```

---

## Step-by-Step Build Guide

### Phase 1 — TUN Setup & IP Layer (Weekend 1)

**Task 1.1 — Open and configure the TUN device**
In `src/tun.cpp`, open `/dev/net/tun`, configure it with `ioctl(TUNSETIFF)`
in `IFF_TUN | IFF_NO_PI` mode (no extra packet-info header — you want raw
IP packets), and bring the interface up with an assigned address using a
shell script (`scripts/setup_tun.sh`) calling `ip addr add` and `ip link set
up`. Confirm you can read raw bytes from the file descriptor by running
`ping 10.0.0.1` and printing the byte count of whatever arrives.

**Task 1.2 — Parse the IPv4 header**
In `src/ip.cpp`, define an `IPHeader` struct matching RFC 791's layout
exactly (version/IHL, type of service, total length, identification,
flags/fragment offset, TTL, protocol, header checksum, source and
destination addresses) and a `parse_ip_header(bytes) → IPHeader` function.
Watch for endianness — all multi-byte fields are network byte order and
need `ntohs`/`ntohl`.

**Task 1.3 — Implement and verify the IP checksum**
Implement the standard one's-complement checksum algorithm: sum all 16-bit
words, fold any carry back in, take the one's complement. Verify it against
a known-good packet captured with `tcpdump -w capture.pcap` while pinging
the interface — your computed checksum must match the kernel's.

**Task 1.4 — Construct and send IP packets**
Implement `build_ip_header()` and a `send_ip_packet()` that writes the
header plus payload back out through the TUN file descriptor. This
completes the round trip needed for ICMP in Phase 2.

---

### Phase 2 — ICMP Echo (Weekend 1, continued)

**Task 2.1 — Parse and respond to ICMP Echo Request**
In `src/icmp.cpp`, parse the ICMP header (type, code, checksum, identifier,
sequence number) from the IP payload when the protocol field is `1`. For an
Echo Request (type 8), construct an Echo Reply (type 0) with the same
identifier, sequence number, and payload, swap source/destination addresses
in the IP header, and send it back.

**Task 2.2 — Verify with real `ping`**
Run your stack and `ping -c 4 10.0.0.1` from another terminal. All four
pings should succeed with correct round-trip times. This is your first
real, externally-verifiable milestone — screenshot it for your README.

---

### Phase 3 — UDP (Weekend 2)

**Task 3.1 — Parse and construct UDP headers**
In `src/udp.cpp`, parse the UDP header (source port, destination port,
length, checksum) from the IP payload when the protocol field is `17`.
The UDP checksum covers a "pseudo-header" of source/destination IP plus
protocol and length — implement this carefully, it's a common source of
subtle bugs.

**Task 3.2 — Implement a minimal UDP echo server**
Bind to a port, and for any received datagram, echo the payload back to the
sender's address and port. Verify with `nc -u 10.0.0.1 9000` from another
terminal — type a line, see it echoed back.

---

### Phase 4 — TCP Handshake & State Machine (Weekends 3–4)

This is the core of the project — budget the most time here.

**Task 4.1 — Define the TCP segment structure and connection state**
In `include/tcp.h`, define a `TCPHeader` struct matching the segment layout
(source/destination port, sequence number, acknowledgment number, flags,
window size, checksum, urgent pointer) and a `TCPConnection` struct holding
the current state enum, local and remote sequence numbers, the receive
window, and buffers for unacknowledged and out-of-order data.

**Task 4.2 — Implement the state machine skeleton**
Write a `process_segment(TCPConnection&, TCPHeader, payload)` function
structured as a switch on the current state. Start with just three states:
`LISTEN`, `SYN_RCVD`, `ESTABLISHED`. Get the three-way handshake working
end to end before adding any other state.

**Task 4.3 — Verify the handshake against a real client**
Run `nc 10.0.0.1 8080` and confirm, with `--trace` enabled, that you see
`SYN` → `SYN,ACK` → `ACK` and the state transitions to `ESTABLISHED`.
Use `tcpdump -i tun0` in parallel to cross-check your trace against ground
truth — this is the single most valuable debugging tool for this phase.

**Task 4.4 — Implement data transfer in ESTABLISHED**
Handle incoming segments with the `PSH` flag: extract the payload, deliver
it to the application via the socket API, and send an `ACK` with the
correctly incremented acknowledgment number. Handle outgoing sends
symmetrically. Verify by typing text into `nc` and seeing it delivered to
your application layer.

**Task 4.5 — Implement connection teardown**
Add the `FIN_WAIT_1`, `FIN_WAIT_2`, `CLOSING`, `TIME_WAIT`, `CLOSE_WAIT`,
and `LAST_ACK` states from the diagram above. Test both directions of
closure: your application calling `close()` first, and the remote `nc`
process closing first (`Ctrl+D`). These are two genuinely different code
paths through the state machine — test both explicitly.

---

### Phase 5 — Reliability: Windows, Retransmission, Ordering (Weekends 5–6)

**Task 5.1 — Implement the retransmission timer**
For every segment sent, start a timer. If no `ACK` covering that segment
arrives before the timer fires, retransmit it and double the timeout
(exponential backoff), capped at a maximum. Test this by artificially
dropping a fixed percentage of outgoing segments in a debug build and
confirming the connection still completes correctly, just slower.

**Task 5.2 — Implement sliding-window flow control**
Track the receiver's advertised window from the `TCP` header's window field.
Do not send more unacknowledged data than the window allows. Implement this
on the receiving side too: advertise a smaller window when your own
application-layer receive buffer is filling up, and verify the sender
correctly throttles.

**Task 5.3 — Handle out-of-order segments**
When a segment arrives with a sequence number beyond what is expected
(a gap), buffer it instead of delivering it to the application, and send a
duplicate `ACK` for the last in-order byte received. When the gap is filled
by a later segment, deliver the buffered segments in order. Test this with
a unit test in `tests/tcp_state_test.cpp` that feeds segments to the state
machine out of order and asserts the application receives them back in
order.

**Task 5.4 — (Stretch) Basic slow-start congestion control**
Maintain a congestion window (`cwnd`) starting at one segment, doubling on
each `ACK` received until a threshold, then growing linearly. This is
optional — note in your README whether you implemented it or stopped before
this task, since congestion control is a substantial topic on its own.

---

### Phase 6 — Testing & Demo Application (Weekend 7)

**Task 6.1 — Write the packet-loss simulation test**
In `tests/retransmission_test.cpp`, wrap the send path with a function that
drops outgoing segments with a configurable probability. Run a full
handshake-through-data-transfer-through-teardown sequence at 0%, 10%, and
30% loss and assert the connection still completes correctly at all three
loss rates — just with measurably more retransmissions logged.

**Task 6.2 — Build the chat client/server demo**
In `apps/chat_server.cpp` and `apps/chat_client.cpp`, build a minimal
multi-line chat application using only the `minitcp_*` socket API — no
direct access to TCP internals. This proves the socket abstraction is
usable for real application code, not just internal tests.

**Task 6.3 — Cross-validate with `curl`**
Implement a trivial fixed HTTP response (`HTTP/1.1 200 OK\r\n\r\nhello`) on
any TCP connection to port 8080, and confirm `curl http://10.0.0.1:8080/`
gets a correct response. This proves your TCP implementation is
indistinguishable from a real one to a completely unmodified, off-the-shelf
client — the strongest correctness statement you can make.

---

### Phase 7 — Polish (Weekend 8)

**Task 7.1 — Write `docs/protocol_notes.md`**
Document the exact header layouts for IP, ICMP, UDP, and TCP with byte
offsets, and explain the checksum algorithm with a worked example. This is
the reference document for anyone reading your code.

**Task 7.2 — Write `docs/state_machine.md`**
Annotate the FSM diagram with which RFC section each transition comes from
and which function in `tcp.cpp` implements it. Explicitly call out the
simultaneous-open and simultaneous-close edge cases and how (or whether)
your implementation handles them.

**Task 7.3 — Record a terminal session for the README**
Capture a `--trace` session showing the full lifecycle — handshake, data
transfer, teardown — against real `nc` and `curl`, and include it verbatim
in the README's example session section (already drafted above as a
placeholder — replace it with your actual trace output).

---

## Realistic Timeline

| Phase | Content | Time |
|---|---|---|
| 1 | TUN setup + IP layer | Weekend 1 |
| 2 | ICMP echo | Weekend 1 |
| 3 | UDP | Weekend 2 |
| 4 | TCP handshake + state machine | Weekends 3–4 |
| 5 | Reliability: windows, retransmission, ordering | Weekends 5–6 |
| 6 | Testing + demo app | Weekend 7 |
| 7 | Docs + polish | Weekend 8 |

**Total: ~8 weekends.** Phases 1–3 are individually small and each produce
an externally verifiable milestone (`ping` working, then a UDP echo test) —
useful checkpoints if time pressure forces you to stop early. If the project
must be cut short, completing Phase 4 (working three-way handshake and basic
data transfer, verified against real `nc`) is already a strong, demoable
result even without the full reliability layer in Phase 5.

---

## How to Talk About This Project in an Interview

**What is the project?**
"I implemented a TCP/IP stack from scratch in user space, reading and
writing raw IP packets through a Linux TUN interface. It handles ICMP, UDP,
and a full TCP connection — handshake, data transfer, retransmission on
loss, and graceful teardown — and it's interoperable with real tools, so I
can run `curl` or `netcat` against my own implementation and get a correct
response."

**Walk me through the TCP state machine.**
"A connection starts in `LISTEN`. On receiving a `SYN`, it moves to
`SYN_RCVD` and replies with `SYN,ACK`. On receiving the final `ACK`, it
reaches `ESTABLISHED`, where data transfer happens. Closing is more involved
— calling close sends a `FIN` and moves to `FIN_WAIT_1`, and depending on
whether the remote side acknowledges first or sends its own `FIN` first, you
go through different paths — `FIN_WAIT_2` then `TIME_WAIT`, or `CLOSING`
then `TIME_WAIT`. Getting both teardown orderings correct, plus the
simultaneous case, was the trickiest part of the state machine."

**What was the hardest part?**
"Reliability under packet loss. The handshake is straightforward once you
have the state machine; the harder problem is correctly tracking
unacknowledged segments, retransmitting them with the right backoff, and
handling segments that arrive out of order without either losing data or
delivering it in the wrong order. I tested this by writing a harness that
randomly drops a percentage of outgoing segments and verifying the
connection still completes correctly, just slower — that test caught
several bugs in my retransmission timer logic."

**What would you do next?**
"Selective acknowledgment (`SACK`) would make retransmission far more
efficient than my current go-back-N-style behavior, and a real congestion
control algorithm — Reno or Cubic — would be the natural extension beyond
the basic slow start I implemented. Beyond TCP itself, the same TUN-based
approach extends naturally to IPv6 or to experimenting with a custom
transport protocol."

---

## Further Reading

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
