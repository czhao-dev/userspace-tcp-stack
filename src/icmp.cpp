#include "icmp.h"

#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace minitcp {

namespace {

std::string addr_to_string(uint32_t host_order_addr) {
    struct in_addr a;
    a.s_addr = htonl(host_order_addr);
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    return std::string(buf);
}

}  // namespace

void handle_icmp(int tun_fd, const IPHeader& ip_hdr, const uint8_t* payload,
                  size_t payload_len, bool trace) {
    if (payload_len < kIcmpHeaderLen) {
        return;
    }

    uint8_t type = payload[0];
    uint8_t code = payload[1];
    uint16_t id_n, seq_n;
    std::memcpy(&id_n, payload + 4, 2);
    std::memcpy(&seq_n, payload + 6, 2);
    uint16_t identifier = ntohs(id_n);
    uint16_t sequence = ntohs(seq_n);

    if (trace) {
        std::printf("[ICMP] recv  type=%u code=%u id=%u seq=%u\n", type, code,
                     identifier, sequence);
    }

    if (type != kIcmpEchoRequest) {
        return;
    }

    // Build the Echo Reply: same identifier/sequence/payload as the
    // request, type changed to 0, checksum recomputed.
    size_t icmp_total_len = payload_len;
    std::vector<uint8_t> icmp_buf(icmp_total_len);
    icmp_buf[0] = kIcmpEchoReply;
    icmp_buf[1] = 0;
    icmp_buf[2] = 0;  // checksum placeholder
    icmp_buf[3] = 0;
    std::memcpy(icmp_buf.data() + 4, payload + 4, 2);  // identifier
    std::memcpy(icmp_buf.data() + 6, payload + 6, 2);  // sequence
    if (icmp_total_len > kIcmpHeaderLen) {
        std::memcpy(icmp_buf.data() + kIcmpHeaderLen, payload + kIcmpHeaderLen,
                    icmp_total_len - kIcmpHeaderLen);
    }

    // ICMP checksum covers the ICMP header + data only, no pseudo-header.
    uint16_t csum = checksum16(icmp_buf.data(), icmp_buf.size());
    uint16_t csum_n = htons(csum);
    std::memcpy(icmp_buf.data() + 2, &csum_n, 2);

    IPHeader reply_hdr = ip_hdr;
    reply_hdr.src_addr = ip_hdr.dst_addr;
    reply_hdr.dst_addr = ip_hdr.src_addr;
    reply_hdr.protocol = 1;
    reply_hdr.ttl = 64;
    reply_hdr.ihl = 5;
    reply_hdr.total_length = static_cast<uint16_t>(kIPHeaderLen + icmp_total_len);
    reply_hdr.flags = 0;
    reply_hdr.fragment_offset = 0;

    std::vector<uint8_t> packet(kIPHeaderLen + icmp_total_len);
    build_ip_header(reply_hdr, packet.data());
    std::memcpy(packet.data() + kIPHeaderLen, icmp_buf.data(), icmp_total_len);

    send_ip_packet(tun_fd, packet.data(), packet.size());

    if (trace) {
        std::printf("[ICMP] send  type=%u code=0 id=%u seq=%u  -> %s\n",
                     kIcmpEchoReply, identifier, sequence,
                     addr_to_string(reply_hdr.dst_addr).c_str());
    }
}

}  // namespace minitcp
