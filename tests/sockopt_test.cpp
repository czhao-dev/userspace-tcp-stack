// Exercises minitcp_setsockopt/getsockopt end to end, including
// SO_RCVTIMEO actually causing a blocking call to return instead of
// hanging forever. Uses minitcp_init_with_fd() with a socketpair
// standing in for the TUN fd (the same technique
// retransmission_test.cpp uses for TCP), since minitcp_init() opens a
// real TUN device and needs root/CAP_NET_ADMIN, which a ctest sandbox
// doesn't have.
#include <arpa/inet.h>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <sys/socket.h>
#include <unistd.h>

#include "socket_api.h"

using namespace minitcp;

namespace {

constexpr uint32_t kSelfAddr = 0x0A0C0001;  // 10.12.0.1

void test_so_rcvtimeo_actually_times_out() {
    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, fds) == 0);
    minitcp_init_with_fd(fds[0], kSelfAddr, false);

    Socket* sock = minitcp_udp_socket();
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9000);
    addr.sin_addr.s_addr = htonl(kSelfAddr);
    assert(minitcp_bind(sock, &addr));

    struct timeval tv{};
    tv.tv_sec = 0;
    tv.tv_usec = 200000;  // 200ms
    assert(minitcp_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)));

    uint8_t buf[64];
    auto start = std::chrono::steady_clock::now();
    ssize_t n = minitcp_recvfrom(sock, buf, sizeof(buf), nullptr);
    auto elapsed = std::chrono::steady_clock::now() - start;

    assert(n == kMinitcpTimeout);
    assert(elapsed < std::chrono::seconds(2));

    minitcp_close(sock);
    close(fds[0]);
    close(fds[1]);
    std::printf("sockopt_test: SO_RCVTIMEO times out on an idle socket OK\n");
}

void test_getsockopt_round_trip() {
    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, fds) == 0);
    minitcp_init_with_fd(fds[0], kSelfAddr, false);

    Socket* sock = minitcp_udp_socket();

    int reuse = 1;
    assert(minitcp_setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)));
    int got_reuse = 0;
    socklen_t len = sizeof(got_reuse);
    assert(minitcp_getsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &got_reuse, &len));
    assert(got_reuse == 1);

    int rcvbuf = 32768;
    assert(minitcp_setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)));
    int got_rcvbuf = 0;
    len = sizeof(got_rcvbuf);
    assert(minitcp_getsockopt(sock, SOL_SOCKET, SO_RCVBUF, &got_rcvbuf, &len));
    assert(got_rcvbuf == 32768);

    int sndbuf = 16384;
    assert(minitcp_setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)));
    int got_sndbuf = 0;
    len = sizeof(got_sndbuf);
    assert(minitcp_getsockopt(sock, SOL_SOCKET, SO_SNDBUF, &got_sndbuf, &len));
    assert(got_sndbuf == 16384);

    // Unsupported (level, optname) combinations are rejected, not
    // silently accepted.
    int dummy = 0;
    assert(!minitcp_setsockopt(sock, IPPROTO_TCP, 9999, &dummy, sizeof(dummy)));

    minitcp_close(sock);
    close(fds[0]);
    close(fds[1]);
    std::printf("sockopt_test: setsockopt/getsockopt round trip OK\n");
}

}  // namespace

int main() {
    test_so_rcvtimeo_actually_times_out();
    test_getsockopt_round_trip();
    std::printf("sockopt_test: all tests passed\n");
    return 0;
}
