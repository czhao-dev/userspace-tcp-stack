#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <vector>

#include "ip.h"

namespace minitcp {

struct UDPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;    // header + data, in bytes
    uint16_t checksum;
};

constexpr size_t kUdpHeaderLen = 8;

// One datagram sitting in a bound UDP socket's receive queue, plus the
// sender's address so it can be reported back via minitcp_recvfrom().
struct UDPDatagram {
    uint32_t src_addr = 0;  // host order
    uint16_t src_port = 0;
    std::vector<uint8_t> data;
};

// Per-socket state for an application-level UDP socket bound to
// (bind_addr, bind_port). Much simpler than TCPConnection: no sequence
// numbers or retransmission, just a bounded queue of datagrams
// addressed to this (addr, port) waiting to be read.
struct UDPSocket {
    uint32_t bind_addr = 0;  // host order
    uint16_t bind_port = 0;
    bool bound = false;

    std::deque<UDPDatagram> recv_queue;
    size_t recv_queue_cap_bytes = 65536;  // tunable via SO_RCVBUF
};

using UDPSocketPtr = std::shared_ptr<UDPSocket>;

// Registers `sock` as bound to (addr, port), used by handle_udp() to
// route incoming datagrams to it instead of the default auto-echo.
// Fails if that exact (addr, port) is already bound by a different
// live UDPSocket, unless `reuse_addr` is set (in which case the old
// binding is simply replaced).
bool udp_bind(UDPSocketPtr sock, uint32_t addr, uint16_t port, bool reuse_addr);

// Removes `sock`'s binding, if any (called from minitcp_close()).
void udp_unbind(const UDPSocketPtr& sock);

// Builds one UDP/IP packet (src_addr,src_port) -> (dst_addr,dst_port)
// carrying `data` and sends it via tun_fd. Used both by handle_udp()'s
// auto-echo fallback and by minitcp_sendto().
void udp_send_datagram(int tun_fd, uint32_t src_addr, uint16_t src_port,
                       uint32_t dst_addr, uint16_t dst_port,
                       const uint8_t* data, size_t data_len);

// Handles one received UDP datagram contained in `payload` (the IP
// payload, length `payload_len`), where `ip_hdr` is the already-parsed
// IP header of the packet that carried it. If an application socket is
// bound to the exact (ip_hdr.dst_addr, dst_port) destination, the
// datagram is queued for that socket; otherwise it's echoed back to
// the sender's (src_addr, src_port), exactly as before.
void handle_udp(int tun_fd, const IPHeader& ip_hdr, const uint8_t* payload,
                 size_t payload_len, bool trace);

}  // namespace minitcp
