#include "dispatch.h"

#include <arpa/inet.h>
#include <cstdio>
#include <string>

#include "icmp.h"
#include "ip.h"
#include "tcp.h"
#include "udp.h"

namespace minitcp {

namespace {

std::string addr_to_string(uint32_t host_order_addr) {
    struct in_addr a;
    a.s_addr = htonl(host_order_addr);
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    return std::string(buf);
}

const char* protocol_name(uint8_t protocol) {
    switch (protocol) {
        case 1: return "ICMP";
        case 6: return "TCP";
        case 17: return "UDP";
        default: return "?";
    }
}

}  // namespace

void dispatch_ip_packet(int tun_fd, const uint8_t* buf, size_t n, bool trace) {
    IPHeader ip_hdr;
    if (!parse_ip_header(buf, n, ip_hdr)) {
        return;
    }
    if (!verify_ip_checksum(buf, n)) {
        if (trace) std::printf("[IP  ] recv  bad checksum, dropping packet\n");
        return;
    }

    if (trace) {
        std::printf("[IP  ] recv  %s -> %s   proto=%s  len=%d\n",
                    addr_to_string(ip_hdr.src_addr).c_str(),
                    addr_to_string(ip_hdr.dst_addr).c_str(), protocol_name(ip_hdr.protocol),
                    static_cast<int>(n));
    }

    size_t header_bytes = static_cast<size_t>(ip_hdr.ihl) * 4;
    if (header_bytes > n) {
        return;
    }
    const uint8_t* payload = buf + header_bytes;
    size_t payload_len = n - header_bytes;

    switch (ip_hdr.protocol) {
        case 1:
            handle_icmp(tun_fd, ip_hdr, payload, payload_len, trace);
            break;
        case 17:
            handle_udp(tun_fd, ip_hdr, payload, payload_len, trace);
            break;
        case 6:
            handle_tcp(tun_fd, ip_hdr, payload, payload_len, trace);
            break;
        default:
            break;
    }
}

}  // namespace minitcp
