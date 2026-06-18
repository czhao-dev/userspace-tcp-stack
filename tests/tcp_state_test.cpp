// Drives the TCP state machine directly with hand-crafted segments —
// no TUN device needed. handle_tcp() is called exactly as it would
// be from the real event loop; only the "wire" (a /dev/null fd, since
// we never need to inspect what the server sends back) is fake.
#include <arpa/inet.h>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <unistd.h>

#include "ip.h"
#include "tcp.h"

using namespace minitcp;

namespace {

constexpr uint32_t kServerAddr = 0x0A0A0001;  // 10.10.0.1
constexpr uint32_t kClientAddr = 0x0A0A0002;  // 10.10.0.2
constexpr uint16_t kServerPort = 9292;
constexpr uint16_t kClientPort = 41000;

std::vector<uint8_t> build_segment(uint16_t src_port, uint16_t dst_port, uint32_t seq,
                                   uint32_t ack, uint8_t flags, const std::string& data,
                                   uint32_t src_addr, uint32_t dst_addr) {
    TCPHeader hdr{};
    hdr.src_port = src_port;
    hdr.dst_port = dst_port;
    hdr.seq_num = seq;
    hdr.ack_num = ack;
    hdr.data_offset_reserved = static_cast<uint8_t>(5 << 4);
    hdr.flags = flags;
    hdr.window = 65535;
    hdr.checksum = 0;
    hdr.urgent_ptr = 0;

    std::vector<uint8_t> seg(kTcpHeaderLen + data.size());
    build_tcp_header(hdr, seg.data());
    if (!data.empty()) {
        std::memcpy(seg.data() + kTcpHeaderLen, data.data(), data.size());
    }
    uint16_t csum = tcp_checksum(src_addr, dst_addr, seg.data(), seg.size());
    uint16_t csum_n = htons(csum);
    std::memcpy(seg.data() + 16, &csum_n, 2);
    return seg;
}

}  // namespace

int main() {
    int dummy_fd = open("/dev/null", O_WRONLY);
    assert(dummy_fd >= 0);

    tcp_listen(kServerAddr, kServerPort);

    IPHeader ip_hdr{};
    ip_hdr.version = 4;
    ip_hdr.ihl = 5;
    ip_hdr.src_addr = kClientAddr;
    ip_hdr.dst_addr = kServerAddr;
    ip_hdr.protocol = 6;
    ip_hdr.ttl = 64;

    // 1. SYN -> server should create a SYN_RCVD connection.
    uint32_t client_seq = 1000;
    auto syn = build_segment(kClientPort, kServerPort, client_seq, 0, kTcpSyn, "", kClientAddr,
                             kServerAddr);
    handle_tcp(dummy_fd, ip_hdr, syn.data(), syn.size(), false);

    TCPConnPtr server_conn = tcp_lookup(kServerAddr, kServerPort, kClientAddr, kClientPort);
    assert(server_conn != nullptr);
    assert(server_conn->state == TCPState::SYN_RCVD);
    uint32_t server_iss = server_conn->iss;

    // 2. Final ACK of the handshake -> ESTABLISHED.
    client_seq += 1;
    auto ack = build_segment(kClientPort, kServerPort, client_seq, server_iss + 1, kTcpAck, "",
                             kClientAddr, kServerAddr);
    handle_tcp(dummy_fd, ip_hdr, ack.data(), ack.size(), false);
    assert(server_conn->state == TCPState::ESTABLISHED);

    TCPConnPtr accepted = tcp_accept(kServerAddr, kServerPort);
    assert(accepted == server_conn);

    // 3. Three 5-byte data segments, delivered OUT OF ORDER: C, A, B.
    auto seg_a = build_segment(kClientPort, kServerPort, client_seq, server_iss + 1,
                               kTcpAck | kTcpPsh, "AAAAA", kClientAddr, kServerAddr);
    auto seg_b = build_segment(kClientPort, kServerPort, client_seq + 5, server_iss + 1,
                               kTcpAck | kTcpPsh, "BBBBB", kClientAddr, kServerAddr);
    auto seg_c = build_segment(kClientPort, kServerPort, client_seq + 10, server_iss + 1,
                               kTcpAck | kTcpPsh, "CCCCC", kClientAddr, kServerAddr);

    handle_tcp(dummy_fd, ip_hdr, seg_c.data(), seg_c.size(), false);  // arrives first, buffered
    handle_tcp(dummy_fd, ip_hdr, seg_a.data(), seg_a.size(), false);  // in-order, but gap remains
    handle_tcp(dummy_fd, ip_hdr, seg_b.data(), seg_b.size(), false);  // fills gap: A,B,C splice in

    uint8_t buf[64];
    size_t n = tcp_recv(accepted, buf, sizeof(buf));
    std::string result(reinterpret_cast<char*>(buf), n);
    assert(result == "AAAAABBBBBCCCCC");
    std::printf("tcp_state_test: out-of-order delivery correct: \"%s\"\n", result.c_str());

    // 4. Remote FIN -> CLOSE_WAIT, local close() -> LAST_ACK -> CLOSED.
    uint32_t client_seq_after_data = client_seq + 15;
    auto fin = build_segment(kClientPort, kServerPort, client_seq_after_data, server_iss + 1,
                             kTcpFin | kTcpAck, "", kClientAddr, kServerAddr);
    handle_tcp(dummy_fd, ip_hdr, fin.data(), fin.size(), false);
    assert(accepted->state == TCPState::CLOSE_WAIT);

    tcp_close(accepted, dummy_fd, false);
    assert(accepted->state == TCPState::LAST_ACK);

    auto final_ack = build_segment(kClientPort, kServerPort, client_seq_after_data + 1,
                                   accepted->snd_nxt, kTcpAck, "", kClientAddr, kServerAddr);
    handle_tcp(dummy_fd, ip_hdr, final_ack.data(), final_ack.size(), false);
    assert(accepted->state == TCPState::CLOSED);

    std::printf("tcp_state_test: all tests passed\n");
    close(dummy_fd);
    return 0;
}
