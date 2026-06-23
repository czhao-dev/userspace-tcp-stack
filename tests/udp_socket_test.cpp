// Drives udp.h/tcp.h directly — no TUN device needed, same approach as
// tcp_state_test.cpp. Covers the three pieces of socket-API plumbing
// that don't require a real blocking event loop: UDP sendto/recvfrom
// delivery to a bound socket, the auto-echo fallback when nothing is
// bound, and the SO_REUSEADDR listen guard.
#include <arpa/inet.h>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

#include "ip.h"
#include "tcp.h"
#include "udp.h"

using namespace minitcp;

namespace {

constexpr uint32_t kServerAddr = 0x0A0B0001;  // 10.11.0.1
constexpr uint32_t kClientAddr = 0x0A0B0002;  // 10.11.0.2

std::vector<uint8_t> build_udp_packet(uint16_t src_port, uint16_t dst_port,
                                      const std::string& data) {
    uint16_t udp_len = static_cast<uint16_t>(kUdpHeaderLen + data.size());
    std::vector<uint8_t> pkt(udp_len);
    uint16_t src_n = htons(src_port);
    uint16_t dst_n = htons(dst_port);
    uint16_t len_n = htons(udp_len);
    std::memcpy(pkt.data() + 0, &src_n, 2);
    std::memcpy(pkt.data() + 2, &dst_n, 2);
    std::memcpy(pkt.data() + 4, &len_n, 2);
    pkt[6] = 0;  // checksum not validated by handle_udp
    pkt[7] = 0;
    if (!data.empty()) {
        std::memcpy(pkt.data() + kUdpHeaderLen, data.data(), data.size());
    }
    return pkt;
}

IPHeader make_ip_header() {
    IPHeader hdr{};
    hdr.version = 4;
    hdr.ihl = 5;
    hdr.protocol = 17;
    hdr.ttl = 64;
    hdr.src_addr = kClientAddr;
    hdr.dst_addr = kServerAddr;
    return hdr;
}

std::vector<uint8_t> build_tcp_segment(uint16_t src_port, uint16_t dst_port, uint32_t seq,
                                       uint32_t ack, uint8_t flags, uint32_t src_addr,
                                       uint32_t dst_addr) {
    TCPHeader hdr{};
    hdr.src_port = src_port;
    hdr.dst_port = dst_port;
    hdr.seq_num = seq;
    hdr.ack_num = ack;
    hdr.data_offset_reserved = static_cast<uint8_t>(5 << 4);
    hdr.flags = flags;
    hdr.window = 65535;

    std::vector<uint8_t> seg(kTcpHeaderLen);
    build_tcp_header(hdr, seg.data());
    uint16_t csum = tcp_checksum(src_addr, dst_addr, seg.data(), seg.size());
    uint16_t csum_n = htons(csum);
    std::memcpy(seg.data() + 16, &csum_n, 2);
    return seg;
}

void test_sendto_recvfrom_round_trip() {
    auto sock = std::make_shared<UDPSocket>();
    assert(udp_bind(sock, kServerAddr, 9000, false));

    IPHeader ip_hdr = make_ip_header();
    auto pkt = build_udp_packet(41000, 9000, "hello");

    int dummy_fd = open("/dev/null", O_WRONLY);
    assert(dummy_fd >= 0);
    handle_udp(dummy_fd, ip_hdr, pkt.data(), pkt.size(), false);

    assert(sock->recv_queue.size() == 1);
    assert(sock->recv_queue.front().src_addr == kClientAddr);
    assert(sock->recv_queue.front().src_port == 41000);
    std::string got(reinterpret_cast<char*>(sock->recv_queue.front().data.data()),
                    sock->recv_queue.front().data.size());
    assert(got == "hello");

    udp_unbind(sock);
    close(dummy_fd);
    std::printf("udp_socket_test: sendto/recvfrom round trip OK\n");
}

void test_recv_queue_cap_drops_oversized_datagram() {
    auto sock = std::make_shared<UDPSocket>();
    sock->recv_queue_cap_bytes = 4;  // smaller than the 5-byte datagram below
    assert(udp_bind(sock, kServerAddr, 9100, false));

    IPHeader ip_hdr = make_ip_header();
    int dummy_fd = open("/dev/null", O_WRONLY);
    assert(dummy_fd >= 0);

    auto too_big = build_udp_packet(41010, 9100, "12345");
    handle_udp(dummy_fd, ip_hdr, too_big.data(), too_big.size(), false);
    assert(sock->recv_queue.empty());  // dropped: exceeds the cap

    auto fits = build_udp_packet(41010, 9100, "ok");
    handle_udp(dummy_fd, ip_hdr, fits.data(), fits.size(), false);
    assert(sock->recv_queue.size() == 1);  // within the cap: delivered

    udp_unbind(sock);
    close(dummy_fd);
    std::printf("udp_socket_test: SO_RCVBUF cap drops oversized datagrams OK\n");
}

void test_echo_fallback_when_unbound() {
    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, fds) == 0);

    IPHeader ip_hdr = make_ip_header();
    auto pkt = build_udp_packet(41001, 9001, "ping");  // nothing bound to 9001
    handle_udp(fds[1], ip_hdr, pkt.data(), pkt.size(), false);

    uint8_t buf[256];
    ssize_t n = read(fds[0], buf, sizeof(buf));
    assert(n > 0);

    IPHeader reply_hdr{};
    assert(parse_ip_header(buf, static_cast<size_t>(n), reply_hdr));
    assert(reply_hdr.dst_addr == kClientAddr);
    assert(reply_hdr.src_addr == kServerAddr);

    std::string reply_data(reinterpret_cast<char*>(buf) + kIPHeaderLen + kUdpHeaderLen,
                           static_cast<size_t>(n) - kIPHeaderLen - kUdpHeaderLen);
    assert(reply_data == "ping");

    close(fds[0]);
    close(fds[1]);
    std::printf("udp_socket_test: echo fallback when unbound OK\n");
}

void test_so_reuseaddr_listen_guard() {
    constexpr uint16_t kListenPort = 9500;
    constexpr uint32_t kRemoteClientAddr = 0x0A0B0003;  // 10.11.0.3
    constexpr uint16_t kRemotePort = 7000;

    // Re-issuing tcp_listen on a port already in LISTEN is a no-op
    // success (this is what keeps retransmission_test.cpp's
    // multi-trial-same-port pattern working).
    assert(tcp_listen(kServerAddr, kListenPort, false) == true);
    assert(tcp_listen(kServerAddr, kListenPort, false) == true);

    // Occupy a fresh local port via an *outgoing* connection
    // (tcp_connect, not tcp_listen) so the port under test was never
    // registered as a listener — the realistic case the SO_REUSEADDR
    // guard is meant for: a port whose only history is a now-dead
    // connection, not an active listener.
    int dummy_fd = open("/dev/null", O_WRONLY);
    assert(dummy_fd >= 0);

    TCPConnPtr conn = tcp_create();
    tcp_connect(conn, dummy_fd, kServerAddr, kRemoteClientAddr, kRemotePort, false);
    uint16_t local_port = conn->local_port;
    uint32_t client_iss = conn->iss;

    IPHeader ip_hdr{};
    ip_hdr.version = 4;
    ip_hdr.ihl = 5;
    ip_hdr.protocol = 6;
    ip_hdr.ttl = 64;
    ip_hdr.src_addr = kRemoteClientAddr;
    ip_hdr.dst_addr = kServerAddr;

    // Remote completes the handshake (SYN,ACK -> ESTABLISHED).
    uint32_t remote_seq = 8000;
    auto syn_ack = build_tcp_segment(kRemotePort, local_port, remote_seq, client_iss + 1,
                                     kTcpSyn | kTcpAck, kRemoteClientAddr, kServerAddr);
    handle_tcp(dummy_fd, ip_hdr, syn_ack.data(), syn_ack.size(), false);
    assert(conn->state == TCPState::ESTABLISHED);

    // Local side closes -> FIN_WAIT_1, then remote ACKs+FINs in one
    // segment -> straight to TIME_WAIT.
    tcp_close(conn, dummy_fd, false);
    assert(conn->state == TCPState::FIN_WAIT_1);

    remote_seq += 1;
    auto fin_ack = build_tcp_segment(kRemotePort, local_port, remote_seq, conn->snd_nxt,
                                     kTcpFin | kTcpAck, kRemoteClientAddr, kServerAddr);
    handle_tcp(dummy_fd, ip_hdr, fin_ack.data(), fin_ack.size(), false);
    assert(conn->state == TCPState::TIME_WAIT);

    // A fresh listen on that exact (addr, port) is blocked by the
    // TIME_WAIT connection unless reuse_addr is set.
    assert(tcp_listen(kServerAddr, local_port, false) == false);
    assert(tcp_listen(kServerAddr, local_port, true) == true);

    close(dummy_fd);
    std::printf("udp_socket_test: SO_REUSEADDR listen guard OK\n");
}

}  // namespace

int main() {
    test_sendto_recvfrom_round_trip();
    test_recv_queue_cap_drops_oversized_datagram();
    test_echo_fallback_when_unbound();
    test_so_reuseaddr_listen_guard();
    std::printf("udp_socket_test: all tests passed\n");
    return 0;
}
