#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <vector>

#include "ip.h"

namespace minitcp {

#pragma pack(push, 1)
struct TCPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset_reserved;  // top nibble = data offset, in 32-bit words
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
};
#pragma pack(pop)
static_assert(sizeof(TCPHeader) == 20, "TCPHeader must be 20 bytes (no options)");

constexpr size_t kTcpHeaderLen = 20;

constexpr uint8_t kTcpFin = 0x01;
constexpr uint8_t kTcpSyn = 0x02;
constexpr uint8_t kTcpRst = 0x04;
constexpr uint8_t kTcpPsh = 0x08;
constexpr uint8_t kTcpAck = 0x10;
constexpr uint8_t kTcpUrg = 0x20;

// Parses the first 20 bytes of `bytes` into a TCPHeader, converting
// multi-byte fields to host byte order. Returns false if `len` < 20.
bool parse_tcp_header(const uint8_t* bytes, size_t len, TCPHeader& out);

// Serializes `hdr` (host byte order) into out_bytes[0..19].
void build_tcp_header(const TCPHeader& hdr, uint8_t* out_bytes);

// TCP checksum, which (unlike ICMP) covers a 12-byte pseudo-header of
// (src IP, dst IP, zero, protocol=6, TCP length) in addition to the
// TCP header + data, per RFC 793. Returns the checksum in HOST byte
// order; caller must htons() before writing it into the header.
uint16_t tcp_checksum(uint32_t src_addr, uint32_t dst_addr,
                      const uint8_t* tcp_segment, size_t tcp_segment_len);

// The eleven TCP connection states from RFC 793 / RFC 9293.
enum class TCPState {
    CLOSED,
    LISTEN,
    SYN_SENT,
    SYN_RCVD,
    ESTABLISHED,
    FIN_WAIT_1,
    FIN_WAIT_2,
    CLOSING,
    TIME_WAIT,
    CLOSE_WAIT,
    LAST_ACK,
};

const char* tcp_state_name(TCPState state);

// A segment we've sent that hasn't been acked yet, kept so it can be
// retransmitted with exponential backoff if no ACK arrives in time.
struct UnackedSegment {
    uint32_t seq;
    uint8_t flags;
    std::vector<uint8_t> data;
    std::chrono::steady_clock::time_point sent_at;
    std::chrono::milliseconds rto;
    int retry_count;
};

// The full per-connection state ("protocol control block" in RFC
// terms): current state, sequence-number bookkeeping, windows, the
// retransmission queue, the out-of-order reassembly buffer, and the
// in-order bytes already delivered to (but not yet read by) the
// application.
struct TCPConnection {
    TCPState state = TCPState::CLOSED;

    uint32_t local_addr = 0;
    uint32_t remote_addr = 0;
    uint16_t local_port = 0;
    uint16_t remote_port = 0;

    uint32_t iss = 0;       // initial send sequence number
    uint32_t snd_una = 0;   // oldest unacknowledged sequence number
    uint32_t snd_nxt = 0;   // next sequence number we will send
    uint32_t snd_wnd = 65535;  // remote's last-advertised receive window

    uint32_t irs = 0;       // initial receive sequence number
    uint32_t rcv_nxt = 0;   // next sequence number expected from remote

    std::deque<UnackedSegment> retransmit_queue;
    std::map<uint32_t, std::vector<uint8_t>> ooo_buffer;  // seq -> payload

    std::vector<uint8_t> recv_buffer;  // in-order data awaiting application read
    std::vector<uint8_t> send_pending; // app data not yet sent (window-limited)

    std::chrono::steady_clock::time_point time_wait_deadline;

    // Defaults match the stack's original hardcoded limits; tunable
    // per-connection via SO_RCVBUF/SO_SNDBUF (see socket_api.h).
    static constexpr size_t kDefaultRecvBufferCap = 65536;
    static constexpr size_t kDefaultSendBufferCap = 1u << 20;

    size_t recv_buffer_cap = kDefaultRecvBufferCap;
    size_t send_pending_cap = kDefaultSendBufferCap;
};

using TCPConnPtr = std::shared_ptr<TCPConnection>;

// Entry point analogous to handle_icmp/handle_udp: demuxes the
// segment to an existing connection or a listening port, and
// advances that connection's state machine by one step.
void handle_tcp(int tun_fd, const IPHeader& ip_hdr, const uint8_t* payload,
                 size_t payload_len, bool trace);

// Called periodically (independent of incoming packets) to check
// retransmission timers and TIME_WAIT expiry across all connections
// tracked by this process.
void tcp_tick(int tun_fd, bool trace);

// --- Socket-level operations, used by socket_api.cpp ---

TCPConnPtr tcp_create();

// Marks (local_addr, local_port) as listening; completed connections
// arriving on it become available via tcp_accept(). Returns false
// without changing any state if that exact (local_addr, local_port)
// is occupied by a live (non-CLOSED) connection — or, unless
// `reuse_addr` is set, one sitting in TIME_WAIT. Re-issuing
// tcp_listen() on a port already in LISTEN is always a no-op success,
// since there is no connection there to conflict with.
bool tcp_listen(uint32_t local_addr, uint16_t local_port, bool reuse_addr = false);

// Pops one ESTABLISHED, not-yet-accepted connection for the given
// listening (local_addr, local_port), or nullptr if none is ready.
TCPConnPtr tcp_accept(uint32_t local_addr, uint16_t local_port);

// Active open: allocates an ephemeral local port, sends SYN, and
// registers the connection (in SYN_SENT) in the connection table.
bool tcp_connect(TCPConnPtr conn, int tun_fd, uint32_t local_addr,
                  uint32_t remote_addr, uint16_t remote_port, bool trace);

// Queues `len` bytes for transmission (segmented to a fixed MSS) and
// sends what the current window allows immediately. Returns the
// number of bytes accepted (always `len` in this implementation —
// the rest of the reliability layer handles pacing).
size_t tcp_send(TCPConnPtr conn, int tun_fd, const uint8_t* data, size_t len,
                bool trace);

// Copies up to `maxlen` bytes of already-delivered, in-order data
// into `buf` and removes them from the connection's receive buffer.
// Returns the number of bytes copied (0 if none available yet).
size_t tcp_recv(TCPConnPtr conn, uint8_t* buf, size_t maxlen);

// Initiates graceful close (sends FIN if applicable).
void tcp_close(TCPConnPtr conn, int tun_fd, bool trace);

bool tcp_is_established(const TCPConnPtr& conn);
bool tcp_is_closed(const TCPConnPtr& conn);

// Looks up a connection by its 4-tuple without consuming it from any
// accept queue. Exists for tests that need to inspect/drive TCP
// internals directly (e.g. reading the server's chosen ISN to craft
// a follow-up segment) — application code should use the
// minitcp_socket_api.h wrappers instead, never this.
TCPConnPtr tcp_lookup(uint32_t local_addr, uint16_t local_port, uint32_t remote_addr,
                      uint16_t remote_port);

}  // namespace minitcp
