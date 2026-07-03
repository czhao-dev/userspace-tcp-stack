# Protocol Notes

Byte-level layouts for every header MiniTCP parses and builds, plus a
worked checksum example. All headers below are written assuming no
options (IP IHL is always 5, TCP data offset is always 5) — see
[Known Limitations](#known-limitations).

## IPv4 header (20 bytes) — `src/ip.rs`

RFC 791. All multi-byte fields are network (big-endian) byte order on
the wire; `parse_ip_header`/`build_ip_header` convert to/from host
order at the boundary so the rest of the code never has to think
about it.

```
 Byte:    0           1           2     3
        +-----+-----+-----------+-----------+
   0    |Ver. | IHL |    ToS    |     |      |
        +-----+-----+-----------+-----+------+
        |        Total Length (16)            |   bytes 2-3
        +---------------------------------------+
        |   Identification (16)  | Flags | Frag  |  bytes 4-7
        |                        |  (3)  | Offset|
        +---------------------------------------+
        |    TTL    | Protocol  |  Header Checksum (16)|  bytes 8-11
        +---------------------------------------+
        |          Source Address (32)          |  bytes 12-15
        +---------------------------------------+
        |        Destination Address (32)       |  bytes 16-19
        +---------------------------------------+
```

| Offset | Field | Size | Notes |
|---|---|---|---|
| 0 | version (4 bits) + IHL (4 bits) | 1 | IHL in 32-bit words; always 5 here |
| 1 | type of service | 1 | unused, passed through as 0 |
| 2-3 | total length | 2 | header + payload, bytes |
| 4-5 | identification | 2 | unused for fragmentation here |
| 6-7 | flags (3 bits) + fragment offset (13 bits) | 2 | no fragmentation support |
| 8 | TTL | 1 | set to 64 on send |
| 9 | protocol | 1 | 1=ICMP, 6=TCP, 17=UDP |
| 10-11 | header checksum | 2 | RFC 1071, header only |
| 12-15 | source address | 4 | |
| 16-19 | destination address | 4 | |

## ICMP header (8 bytes) — `src/icmp.rs`

RFC 792. Only Echo Request (type 8) / Echo Reply (type 0) are
implemented.

| Offset | Field | Size |
|---|---|---|
| 0 | type | 1 |
| 1 | code | 1 |
| 2-3 | checksum | 2 |
| 4-5 | identifier | 2 |
| 6-7 | sequence number | 2 |

Checksum covers the ICMP header + data only — **no pseudo-header**,
unlike UDP/TCP.

## UDP header (8 bytes) — `src/udp.rs`

RFC 768.

| Offset | Field | Size |
|---|---|---|
| 0-1 | source port | 2 |
| 2-3 | destination port | 2 |
| 4-5 | length | 2 | header + data |
| 6-7 | checksum | 2 |

UDP's checksum covers a 12-byte **pseudo-header** (source IP, dest IP,
zero byte, protocol=17, UDP length) in addition to the header + data —
this is the detail most often gotten wrong, since it pulls fields from
the *IP* header into a TCP/UDP-layer checksum.

## TCP header (20 bytes) — `src/tcp.rs`

RFC 793 / RFC 9293.

```
 0                   1                   2                   3
 +-------------------------------+-------------------------------+
 |          Source Port          |        Destination Port       |
 +-------------------------------+-------------------------------+
 |                        Sequence Number                        |
 +-----------------------------------------------------------------+
 |                    Acknowledgment Number                       |
 +-----+-----+-------------------+-------------------------------+
 |Data |Resvd|  Flags (6 used)   |           Window               |
 |Off. |     | U A P R S F       |                                 |
 +-----+-----+-------------------+-------------------------------+
 |            Checksum            |        Urgent Pointer          |
 +-----------------------------------------------------------------+
```

| Offset | Field | Size |
|---|---|---|
| 0-1 | source port | 2 |
| 2-3 | destination port | 2 |
| 4-7 | sequence number | 4 |
| 8-11 | acknowledgment number | 4 |
| 12 | data offset (top nibble) + reserved | 1 | always `5 << 4` here |
| 13 | flags | 1 | `FIN=0x01 SYN=0x02 RST=0x04 PSH=0x08 ACK=0x10 URG=0x20` |
| 14-15 | window | 2 | our/their advertised receive window |
| 16-17 | checksum | 2 | pseudo-header + header + data, like UDP but protocol=6 |
| 18-19 | urgent pointer | 2 | unused (URG not implemented) |

## Checksum algorithm (RFC 1071) — `checksum16()` in `src/ip.rs`

1. Treat the buffer as a sequence of 16-bit big-endian words (the
   trailing byte of an odd-length buffer is the high byte of a
   zero-padded word).
2. Sum all words into a 32-bit accumulator.
3. **Fold carries in a loop**, not a single fold: `while (sum >> 16) sum
   = (sum & 0xFFFF) + (sum >> 16);` — a buffer with enough words can
   carry out of bit 16 more than once.
4. The checksum is the one's complement of the result: `~sum & 0xFFFF`.

**Worked example** (the classic RFC 1071 vector, also in
`src/ip.rs`'s `known_vector` unit test): bytes `00 01 f2 03 f4 f5 f6 f7`.

```
words:  0x0001 + 0xf203 + 0xf4f5 + 0xf6f7
      = 0x0001 + 0xf203 = 0xf204
      + 0xf4f5           = 0x1e6f9   (carries past bit 16)
      + 0xf6f7           = 0x2ddf0
fold:   0x2ddf0 -> (0x2ddf0 & 0xFFFF) + (0x2ddf0 >> 16) = 0xddf0 + 0x2 = 0xddf2
result: ~0xddf2 & 0xFFFF = 0x220d
```

**Validating** a received header is the same computation over the
header *with its received checksum field included, unmodified*: a
correctly-checksummed header always sums to `0xFFFF` before the
complement, so `checksum16()` returns exactly `0`. `build_ip_header()`
zeroes the checksum field first, computes, then writes the result
back — `verify_ip_checksum()` / `tcp_checksum() == 0` do the reverse.

## Known limitations

- No IP options support (IHL is always 5) and no TCP options support
  (data offset is always 5) — no MSS negotiation, no window scaling,
  no SACK.
- No fragmentation/reassembly at the IP layer.
- Sequence number comparisons use plain `uint32_t` arithmetic without
  explicit wraparound-safe comparisons — fine for the short-lived
  demo connections this project is exercised against, not safe for
  multi-gigabyte transfers where sequence numbers actually wrap.
- Retransmission is a single-timer-per-connection, go-back-N-style
  scheme (RFC 6298's classic non-SACK approach) — no selective
  acknowledgment, no fast retransmit on duplicate ACKs.
- No real congestion control (no slow start / cwnd) — see
  [state_machine.md](state_machine.md) and the main README for why
  this was scoped out.
