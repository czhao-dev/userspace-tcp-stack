#include "socket_api.h"

#include <algorithm>
#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <poll.h>
#include <utility>

#include "dispatch.h"
#include "tcp.h"
#include "tun.h"
#include "udp.h"

namespace minitcp {

namespace {

int g_tun_fd = -1;
uint32_t g_self_addr = 0;
bool g_trace = false;
uint16_t g_next_udp_ephemeral_port = 51000;  // separate counter from TCP's

// Reads one packet from the TUN fd (if any arrived within
// `timeout_ms`), dispatches it, and always advances TCP's
// retransmission/TIME_WAIT timers — the same two things minitcp's own
// main.cpp loop does, just packaged so blocking socket calls can pump
// the event loop themselves while waiting for a condition.
void pump_once(int timeout_ms) {
    struct pollfd pfd{};
    pfd.fd = g_tun_fd;
    pfd.events = POLLIN;

    int ready = poll(&pfd, 1, timeout_ms);
    if (ready > 0 && (pfd.revents & POLLIN)) {
        uint8_t buf[2048];
        ssize_t n = tun_read(g_tun_fd, buf, sizeof(buf));
        if (n > 0) {
            dispatch_ip_packet(g_tun_fd, buf, static_cast<size_t>(n), g_trace);
        }
    }
    tcp_tick(g_tun_fd, g_trace);
}

// Wall-clock deadline helper shared by every blocking call that honors
// SO_RCVTIMEO. `has_timeout=false` means block forever (today's
// default behavior, unchanged).
bool deadline_elapsed(bool has_timeout, std::chrono::steady_clock::time_point start,
                       const struct timeval& tv) {
    if (!has_timeout) return false;
    auto timeout = std::chrono::seconds(tv.tv_sec) + std::chrono::microseconds(tv.tv_usec);
    return std::chrono::steady_clock::now() - start >= timeout;
}

}  // namespace

enum class SocketKind { kUninitialized, kTcp, kUdp };

// Per-socket option storage. A plain struct rather than a generic
// option map, since only four options are supported.
struct SocketOptions {
    bool has_rcvtimeo = false;
    struct timeval rcvtimeo {};  // SO_RCVTIMEO; ignored unless has_rcvtimeo
    bool reuse_addr = false;     // SO_REUSEADDR
    int rcvbuf = -1;             // SO_RCVBUF; -1 = use protocol default
    int sndbuf = -1;             // SO_SNDBUF; -1 = use protocol default (TCP only)
};

struct Socket {
    SocketKind kind = SocketKind::kUninitialized;

    TCPConnPtr conn;
    bool is_listener = false;
    uint32_t listen_addr = 0;
    uint16_t listen_port = 0;

    UDPSocketPtr udp;

    SocketOptions opts;
};

namespace {

// Applies any sockopts set on `sock` before a TCPConnPtr existed
// (SO_RCVBUF/SO_SNDBUF) onto the freshly-attached connection, so
// option-then-connect and connect-then-option both work.
void apply_pending_opts_to_conn(Socket* sock) {
    if (!sock->conn) return;
    if (sock->opts.rcvbuf > 0) sock->conn->recv_buffer_cap = static_cast<size_t>(sock->opts.rcvbuf);
    if (sock->opts.sndbuf > 0) sock->conn->send_pending_cap = static_cast<size_t>(sock->opts.sndbuf);
}

}  // namespace

bool minitcp_init(const std::string& tun_dev_name, uint32_t self_addr, bool trace) {
    std::string dev = tun_dev_name;
    g_tun_fd = tun_alloc(dev);
    g_self_addr = self_addr;
    g_trace = trace;
    return g_tun_fd >= 0;
}

void minitcp_init_with_fd(int fd, uint32_t self_addr, bool trace) {
    g_tun_fd = fd;
    g_self_addr = self_addr;
    g_trace = trace;
}

Socket* minitcp_socket() {
    Socket* s = new Socket();
    s->kind = SocketKind::kTcp;
    return s;
}

bool minitcp_listen(Socket* sock, uint16_t port) {
    if (!sock) return false;
    sock->is_listener = true;
    sock->listen_addr = g_self_addr;
    sock->listen_port = port;
    return tcp_listen(g_self_addr, port, sock->opts.reuse_addr);
}

Socket* minitcp_accept(Socket* listener, bool* timed_out) {
    if (timed_out) *timed_out = false;
    if (!listener || !listener->is_listener) return nullptr;
    auto start = std::chrono::steady_clock::now();
    while (true) {
        TCPConnPtr conn = tcp_accept(listener->listen_addr, listener->listen_port);
        if (conn) {
            Socket* s = new Socket();
            s->kind = SocketKind::kTcp;
            s->conn = conn;
            apply_pending_opts_to_conn(s);
            return s;
        }
        if (deadline_elapsed(listener->opts.has_rcvtimeo, start, listener->opts.rcvtimeo)) {
            if (timed_out) *timed_out = true;
            return nullptr;
        }
        pump_once(100);
    }
}

bool minitcp_connect(Socket* sock, uint32_t remote_addr, uint16_t remote_port) {
    if (!sock) return false;
    sock->conn = tcp_create();
    apply_pending_opts_to_conn(sock);
    tcp_connect(sock->conn, g_tun_fd, g_self_addr, remote_addr, remote_port, g_trace);

    // The connection's own retransmit queue keeps resending the SYN on
    // timeout; we just pump the loop until it resolves one way or the
    // other, with a generous overall cap so a truly unreachable peer
    // doesn't hang forever.
    for (int i = 0; i < 300; ++i) {
        if (tcp_is_established(sock->conn)) return true;
        if (tcp_is_closed(sock->conn)) return false;
        pump_once(100);
    }
    return false;
}

ssize_t minitcp_send(Socket* sock, const void* data, size_t len) {
    if (!sock || !sock->conn) return -1;
    return static_cast<ssize_t>(
        tcp_send(sock->conn, g_tun_fd, static_cast<const uint8_t*>(data), len, g_trace));
}

ssize_t minitcp_recv(Socket* sock, void* buf, size_t maxlen) {
    if (!sock || !sock->conn) return -1;
    auto start = std::chrono::steady_clock::now();
    while (true) {
        size_t n = tcp_recv(sock->conn, static_cast<uint8_t*>(buf), maxlen);
        if (n > 0) return static_cast<ssize_t>(n);

        TCPState state = sock->conn->state;
        bool remote_closed_no_more_data = state == TCPState::CLOSE_WAIT ||
                                          state == TCPState::LAST_ACK ||
                                          state == TCPState::CLOSED ||
                                          state == TCPState::TIME_WAIT;
        if (remote_closed_no_more_data) {
            return 0;
        }
        if (deadline_elapsed(sock->opts.has_rcvtimeo, start, sock->opts.rcvtimeo)) {
            return kMinitcpTimeout;
        }
        pump_once(100);
    }
}

void minitcp_close(Socket* sock) {
    if (!sock) return;
    if (sock->kind == SocketKind::kUdp) {
        udp_unbind(sock->udp);
    } else if (sock->conn) {
        tcp_close(sock->conn, g_tun_fd, g_trace);

        // Linger briefly, pumping the event loop, so a process that
        // calls close() and immediately exits still completes the
        // FIN/ACK teardown instead of abandoning it mid-handshake —
        // unlike a kernel-resident TCP stack, nothing is left to
        // answer retransmits once this process is gone.
        for (int i = 0; i < 50 && !tcp_is_closed(sock->conn); ++i) {
            pump_once(100);
        }
    }
    delete sock;
}

// --- UDP socket API ---

Socket* minitcp_udp_socket() {
    Socket* s = new Socket();
    s->kind = SocketKind::kUdp;
    s->udp = std::make_shared<UDPSocket>();
    return s;
}

bool minitcp_bind(Socket* sock, const struct sockaddr_in* addr) {
    if (!sock || sock->kind != SocketKind::kUdp || !addr) return false;
    uint32_t bind_addr = ntohl(addr->sin_addr.s_addr);
    uint16_t bind_port = ntohs(addr->sin_port);
    if (bind_addr == 0) bind_addr = g_self_addr;  // INADDR_ANY -> this process's address
    if (sock->opts.rcvbuf > 0) {
        sock->udp->recv_queue_cap_bytes = static_cast<size_t>(sock->opts.rcvbuf);
    }
    return udp_bind(sock->udp, bind_addr, bind_port, sock->opts.reuse_addr);
}

ssize_t minitcp_sendto(Socket* sock, const void* data, size_t len,
                        const struct sockaddr_in* dest) {
    if (!sock || sock->kind != SocketKind::kUdp || !dest) return -1;
    if (!sock->udp->bound) {
        // Implicit bind to an ephemeral port on first send, mirroring
        // POSIX UDP sendto()-without-bind semantics.
        udp_bind(sock->udp, g_self_addr, g_next_udp_ephemeral_port++, sock->opts.reuse_addr);
    }
    uint32_t dst_addr = ntohl(dest->sin_addr.s_addr);
    uint16_t dst_port = ntohs(dest->sin_port);
    udp_send_datagram(g_tun_fd, sock->udp->bind_addr, sock->udp->bind_port, dst_addr, dst_port,
                      static_cast<const uint8_t*>(data), len);
    return static_cast<ssize_t>(len);
}

ssize_t minitcp_recvfrom(Socket* sock, void* buf, size_t maxlen, struct sockaddr_in* src_addr) {
    if (!sock || sock->kind != SocketKind::kUdp) return -1;
    auto start = std::chrono::steady_clock::now();
    while (true) {
        if (!sock->udp->recv_queue.empty()) {
            UDPDatagram dg = std::move(sock->udp->recv_queue.front());
            sock->udp->recv_queue.pop_front();
            size_t n = std::min(maxlen, dg.data.size());
            std::memcpy(buf, dg.data.data(), n);
            if (src_addr) {
                std::memset(src_addr, 0, sizeof(*src_addr));
                src_addr->sin_family = AF_INET;
                src_addr->sin_port = htons(dg.src_port);
                src_addr->sin_addr.s_addr = htonl(dg.src_addr);
            }
            return static_cast<ssize_t>(n);
        }
        if (deadline_elapsed(sock->opts.has_rcvtimeo, start, sock->opts.rcvtimeo)) {
            return kMinitcpTimeout;
        }
        pump_once(100);
    }
}

// --- Socket options ---

bool minitcp_setsockopt(Socket* sock, int level, int optname, const void* optval,
                         socklen_t optlen) {
    if (!sock || level != SOL_SOCKET || !optval) return false;
    switch (optname) {
        case SO_RCVTIMEO: {
            if (optlen < sizeof(struct timeval)) return false;
            std::memcpy(&sock->opts.rcvtimeo, optval, sizeof(struct timeval));
            sock->opts.has_rcvtimeo =
                sock->opts.rcvtimeo.tv_sec != 0 || sock->opts.rcvtimeo.tv_usec != 0;
            return true;
        }
        case SO_REUSEADDR: {
            if (optlen < sizeof(int)) return false;
            int v;
            std::memcpy(&v, optval, sizeof(int));
            sock->opts.reuse_addr = (v != 0);
            return true;
        }
        case SO_RCVBUF: {
            if (optlen < sizeof(int)) return false;
            int v;
            std::memcpy(&v, optval, sizeof(int));
            if (v <= 0) return false;
            sock->opts.rcvbuf = v;
            if (sock->kind == SocketKind::kTcp && sock->conn) {
                sock->conn->recv_buffer_cap = static_cast<size_t>(v);
            } else if (sock->kind == SocketKind::kUdp && sock->udp) {
                sock->udp->recv_queue_cap_bytes = static_cast<size_t>(v);
            }
            return true;
        }
        case SO_SNDBUF: {
            if (optlen < sizeof(int)) return false;
            int v;
            std::memcpy(&v, optval, sizeof(int));
            if (v <= 0) return false;
            sock->opts.sndbuf = v;
            if (sock->kind == SocketKind::kTcp && sock->conn) {
                sock->conn->send_pending_cap = static_cast<size_t>(v);
            }
            return true;
        }
        default:
            return false;
    }
}

bool minitcp_getsockopt(Socket* sock, int level, int optname, void* optval, socklen_t* optlen) {
    if (!sock || level != SOL_SOCKET || !optval || !optlen) return false;
    switch (optname) {
        case SO_RCVTIMEO: {
            if (*optlen < sizeof(struct timeval)) return false;
            std::memcpy(optval, &sock->opts.rcvtimeo, sizeof(struct timeval));
            *optlen = sizeof(struct timeval);
            return true;
        }
        case SO_REUSEADDR: {
            if (*optlen < sizeof(int)) return false;
            int v = sock->opts.reuse_addr ? 1 : 0;
            std::memcpy(optval, &v, sizeof(int));
            *optlen = sizeof(int);
            return true;
        }
        case SO_RCVBUF: {
            if (*optlen < sizeof(int)) return false;
            int v = sock->opts.rcvbuf > 0 ? sock->opts.rcvbuf
                                           : static_cast<int>(TCPConnection::kDefaultRecvBufferCap);
            std::memcpy(optval, &v, sizeof(int));
            *optlen = sizeof(int);
            return true;
        }
        case SO_SNDBUF: {
            if (*optlen < sizeof(int)) return false;
            int v = sock->opts.sndbuf > 0 ? sock->opts.sndbuf
                                           : static_cast<int>(TCPConnection::kDefaultSendBufferCap);
            std::memcpy(optval, &v, sizeof(int));
            *optlen = sizeof(int);
            return true;
        }
        default:
            return false;
    }
}

}  // namespace minitcp
