#include "udp.h"

#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <map>
#include <utility>
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

// (addr, port) -> the application socket bound there, if any. Mirrors
// tcp.cpp's g_listeners/g_accept_queues: the registry lives next to
// the protocol handler that needs to query it.
std::map<std::pair<uint32_t, uint16_t>, UDPSocketPtr> g_udp_binds;

void deliver_to_socket(const UDPSocketPtr& sock, uint32_t src_addr, uint16_t src_port,
                        const uint8_t* data, size_t data_len) {
    size_t used = 0;
    for (const auto& dg : sock->recv_queue) used += dg.data.size();
    if (used + data_len > sock->recv_queue_cap_bytes) {
        // SO_RCVBUF full — drop the new datagram, mirroring a kernel
        // dropping on a full receive buffer.
        return;
    }
    UDPDatagram dg;
    dg.src_addr = src_addr;
    dg.src_port = src_port;
    dg.data.assign(data, data + data_len);
    sock->recv_queue.push_back(std::move(dg));
}

}  // namespace

bool udp_bind(UDPSocketPtr sock, uint32_t addr, uint16_t port, bool reuse_addr) {
    auto key = std::make_pair(addr, port);
    auto it = g_udp_binds.find(key);
    if (it != g_udp_binds.end() && it->second != sock && !reuse_addr) {
        return false;
    }
    sock->bind_addr = addr;
    sock->bind_port = port;
    sock->bound = true;
    g_udp_binds[key] = sock;
    return true;
}

void udp_unbind(const UDPSocketPtr& sock) {
    if (!sock || !sock->bound) return;
    auto key = std::make_pair(sock->bind_addr, sock->bind_port);
    auto it = g_udp_binds.find(key);
    if (it != g_udp_binds.end() && it->second == sock) {
        g_udp_binds.erase(it);
    }
    sock->bound = false;
}

void udp_send_datagram(int tun_fd, uint32_t src_addr, uint16_t src_port,
                       uint32_t dst_addr, uint16_t dst_port,
                       const uint8_t* data, size_t data_len) {
    uint16_t udp_len = static_cast<uint16_t>(kUdpHeaderLen + data_len);

    // Build pseudo-header + UDP header + data into one scratch buffer
    // so the checksum can be computed with a single checksum16 call
    // rather than incremental partial sums.
    std::vector<uint8_t> scratch(12 + udp_len);
    build_pseudo_header(src_addr, dst_addr, udp_len, scratch.data());

    uint8_t* udp_part = scratch.data() + 12;
    uint16_t src_port_n = htons(src_port);
    uint16_t dst_port_n = htons(dst_port);
    std::memcpy(udp_part, &src_port_n, 2);
    std::memcpy(udp_part + 2, &dst_port_n, 2);
    uint16_t udp_len_n = htons(udp_len);
    std::memcpy(udp_part + 4, &udp_len_n, 2);
    udp_part[6] = 0;  // checksum placeholder
    udp_part[7] = 0;
    if (data_len > 0) {
        std::memcpy(udp_part + kUdpHeaderLen, data, data_len);
    }

    uint16_t csum = checksum16(scratch.data(), scratch.size());
    uint16_t csum_n = htons(csum);
    std::memcpy(udp_part + 6, &csum_n, 2);

    IPHeader hdr{};
    hdr.version = 4;
    hdr.src_addr = src_addr;
    hdr.dst_addr = dst_addr;
    hdr.protocol = 17;
    hdr.ttl = 64;
    hdr.ihl = 5;
    hdr.total_length = static_cast<uint16_t>(kIPHeaderLen + udp_len);
    hdr.flags = 0;
    hdr.fragment_offset = 0;

    std::vector<uint8_t> packet(kIPHeaderLen + udp_len);
    build_ip_header(hdr, packet.data());
    std::memcpy(packet.data() + kIPHeaderLen, udp_part, udp_len);

    send_ip_packet(tun_fd, packet.data(), packet.size());
}

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
    const uint8_t* data = payload + kUdpHeaderLen;

    if (trace) {
        std::printf("[UDP ] recv  %u -> %u  len=%zu\n", src_port, dst_port,
                    data_len);
    }

    auto it = g_udp_binds.find({ip_hdr.dst_addr, dst_port});
    if (it != g_udp_binds.end()) {
        deliver_to_socket(it->second, ip_hdr.src_addr, src_port, data, data_len);
        if (trace) {
            std::printf("[UDP ] deliver -> bound app socket on port %u\n", dst_port);
        }
        return;
    }

    // No application socket bound on this port — auto-echo back to
    // the sender, exactly as before this socket API existed.
    udp_send_datagram(tun_fd, ip_hdr.dst_addr, dst_port, ip_hdr.src_addr, src_port,
                      data, data_len);
    if (trace) {
        std::printf("[UDP ] send  %u -> %u  len=%zu\n", dst_port, src_port,
                    data_len);
    }
}

}  // namespace minitcp
