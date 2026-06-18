#include "socket_api.h"

#include <poll.h>

#include "dispatch.h"
#include "tcp.h"
#include "tun.h"

namespace minitcp {

namespace {

int g_tun_fd = -1;
uint32_t g_self_addr = 0;
bool g_trace = false;

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

}  // namespace

struct Socket {
    TCPConnPtr conn;
    bool is_listener = false;
    uint32_t listen_addr = 0;
    uint16_t listen_port = 0;
};

bool minitcp_init(const std::string& tun_dev_name, uint32_t self_addr, bool trace) {
    std::string dev = tun_dev_name;
    g_tun_fd = tun_alloc(dev);
    g_self_addr = self_addr;
    g_trace = trace;
    return g_tun_fd >= 0;
}

Socket* minitcp_socket() {
    return new Socket();
}

bool minitcp_listen(Socket* sock, uint16_t port) {
    if (!sock) return false;
    sock->is_listener = true;
    sock->listen_addr = g_self_addr;
    sock->listen_port = port;
    tcp_listen(g_self_addr, port);
    return true;
}

Socket* minitcp_accept(Socket* listener) {
    if (!listener || !listener->is_listener) return nullptr;
    while (true) {
        TCPConnPtr conn = tcp_accept(listener->listen_addr, listener->listen_port);
        if (conn) {
            Socket* s = new Socket();
            s->conn = conn;
            return s;
        }
        pump_once(100);
    }
}

bool minitcp_connect(Socket* sock, uint32_t remote_addr, uint16_t remote_port) {
    if (!sock) return false;
    sock->conn = tcp_create();
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
        pump_once(100);
    }
}

void minitcp_close(Socket* sock) {
    if (!sock) return;
    if (sock->conn) {
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

}  // namespace minitcp
