#pragma once

#include <cstddef>
#include <cstdint>

#include "ip.h"

namespace minitcp {

constexpr uint8_t kIcmpEchoRequest = 8;
constexpr uint8_t kIcmpEchoReply = 0;

struct ICMPHeader {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t sequence;
};

constexpr size_t kIcmpHeaderLen = 8;

// Handles one received ICMP message contained in `payload` (the IP
// payload, length `payload_len`), where `ip_hdr` is the already-parsed
// IP header of the packet that carried it. If it's an Echo Request,
// builds and sends an Echo Reply (same id/seq/payload, swapped
// src/dst) out through tun_fd. No-op for other ICMP types.
void handle_icmp(int tun_fd, const IPHeader& ip_hdr, const uint8_t* payload,
                  size_t payload_len, bool trace);

}  // namespace minitcp
