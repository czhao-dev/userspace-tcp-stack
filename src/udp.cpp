#include "udp.h"

#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <vector>

namespace minitcp {

namespace {

// Builds the 12-byte UDP pseudo-header (RFC 768) into `out`, used only
// as scratch input to checksum16 — it's never actually transmitted.
void build_pseudo_header(uint32_t src_addr, uint32_t dst_addr,
                          uint16_t udp_length, uint8_t* out) {
    uint32_t src_n = htonl(src_addr);
    uint32_t dst_n = htonl(dst_addr);
    std::memcpy(out, &src_n, 4);
    std::memcpy(out + 4, &dst_n, 4);
    out[8] = 0;
    out[9] = 17;  // protocol = UDP
    uint16_t len_n = htons(udp_length);
    std::memcpy(out + 10, &len_n, 2);
}

}  // namespace

void handle_udp(int tun_fd, const IPHeader& ip_hdr, const uint8_t* payload,
                 size_t payload_len, bool trace) {
    if (payload_len < kUdpHeaderLen) {
        return;
    }

    uint16_t src_port_n, dst_port_n;
    std::memcpy(&src_port_n, payload, 2);
    std::memcpy(&dst_port_n, payload + 2, 2);
    uint16_t src_port = ntohs(src_port_n);
    uint16_t dst_port = ntohs(dst_port_n);

    size_t data_len = payload_len - kUdpHeaderLen;

    if (trace) {
        std::printf("[UDP ] recv  %u -> %u  len=%zu\n", src_port, dst_port,
                    data_len);
    }

    uint16_t reply_udp_len = static_cast<uint16_t>(kUdpHeaderLen + data_len);

    // Build pseudo-header + UDP header + data into one scratch buffer
    // so the checksum can be computed with a single checksum16 call
    // rather than incremental partial sums.
    std::vector<uint8_t> scratch(12 + reply_udp_len);
    build_pseudo_header(ip_hdr.dst_addr, ip_hdr.src_addr, reply_udp_len,
                         scratch.data());

    uint8_t* udp_part = scratch.data() + 12;
    uint16_t reply_src_port_n = htons(dst_port);  // we reply from the original dst port
    uint16_t reply_dst_port_n = htons(src_port);  // back to the original sender
    std::memcpy(udp_part, &reply_src_port_n, 2);
    std::memcpy(udp_part + 2, &reply_dst_port_n, 2);
    uint16_t reply_udp_len_n = htons(reply_udp_len);
    std::memcpy(udp_part + 4, &reply_udp_len_n, 2);
    udp_part[6] = 0;  // checksum placeholder
    udp_part[7] = 0;
    if (data_len > 0) {
        std::memcpy(udp_part + kUdpHeaderLen, payload + kUdpHeaderLen, data_len);
    }

    uint16_t csum = checksum16(scratch.data(), scratch.size());
    uint16_t csum_n = htons(csum);
    std::memcpy(udp_part + 6, &csum_n, 2);

    IPHeader reply_hdr = ip_hdr;
    reply_hdr.src_addr = ip_hdr.dst_addr;
    reply_hdr.dst_addr = ip_hdr.src_addr;
    reply_hdr.protocol = 17;
    reply_hdr.ttl = 64;
    reply_hdr.ihl = 5;
    reply_hdr.total_length = static_cast<uint16_t>(kIPHeaderLen + reply_udp_len);
    reply_hdr.flags = 0;
    reply_hdr.fragment_offset = 0;

    std::vector<uint8_t> packet(kIPHeaderLen + reply_udp_len);
    build_ip_header(reply_hdr, packet.data());
    std::memcpy(packet.data() + kIPHeaderLen, udp_part, reply_udp_len);

    send_ip_packet(tun_fd, packet.data(), packet.size());

    if (trace) {
        std::printf("[UDP ] send  %u -> %u  len=%zu\n", dst_port, src_port,
                    data_len);
    }
}

}  // namespace minitcp
