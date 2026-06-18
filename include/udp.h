#pragma once

#include <cstddef>
#include <cstdint>

#include "ip.h"

namespace minitcp {

struct UDPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;    // header + data, in bytes
    uint16_t checksum;
};

constexpr size_t kUdpHeaderLen = 8;

// Handles one received UDP datagram contained in `payload` (the IP
// payload, length `payload_len`), where `ip_hdr` is the already-parsed
// IP header of the packet that carried it. Echoes the data back to
// the sender's (src_addr, src_port).
void handle_udp(int tun_fd, const IPHeader& ip_hdr, const uint8_t* payload,
                 size_t payload_len, bool trace);

}  // namespace minitcp
