#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <string>

#include "icmp.h"
#include "ip.h"
#include "tun.h"
#include "udp.h"

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
        case 1:
            return "ICMP";
        case 6:
            return "TCP";
        case 17:
            return "UDP";
        default:
            return "?";
    }
}

}  // namespace

int main(int argc, char** argv) {
    bool trace = false;
    std::string dev_name = "tun0";

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--trace") == 0) {
            trace = true;
        }
    }

    int fd = minitcp::tun_alloc(dev_name);
    if (fd < 0) {
        std::perror("tun_alloc");
        return 1;
    }
    std::printf("MiniTCP listening on %s%s\n", dev_name.c_str(),
                trace ? " (trace enabled)" : "");

    uint8_t buf[2048];
    while (true) {
        ssize_t n = minitcp::tun_read(fd, buf, sizeof(buf));
        if (n <= 0) {
            continue;
        }

        minitcp::IPHeader ip_hdr;
        if (!minitcp::parse_ip_header(buf, static_cast<size_t>(n), ip_hdr)) {
            continue;
        }

        if (!minitcp::verify_ip_checksum(buf, static_cast<size_t>(n))) {
            if (trace) {
                std::printf("[IP  ] recv  bad checksum, dropping packet\n");
            }
            continue;
        }

        if (trace) {
            std::printf("[IP  ] recv  %s -> %s   proto=%s  len=%d\n",
                        addr_to_string(ip_hdr.src_addr).c_str(),
                        addr_to_string(ip_hdr.dst_addr).c_str(),
                        protocol_name(ip_hdr.protocol), static_cast<int>(n));
        }

        size_t header_bytes = static_cast<size_t>(ip_hdr.ihl) * 4;
        if (header_bytes > static_cast<size_t>(n)) {
            continue;
        }
        const uint8_t* payload = buf + header_bytes;
        size_t payload_len = static_cast<size_t>(n) - header_bytes;

        switch (ip_hdr.protocol) {
            case 1:  // ICMP
                minitcp::handle_icmp(fd, ip_hdr, payload, payload_len, trace);
                break;
            case 17:  // UDP
                minitcp::handle_udp(fd, ip_hdr, payload, payload_len, trace);
                break;
            case 6:  // TCP — Phase 4
                break;
            default:
                break;
        }
    }

    return 0;
}
