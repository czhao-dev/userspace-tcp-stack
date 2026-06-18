// Simulates packet loss on the "wire" between two in-process TCP
// endpoints (no TUN device needed) and verifies that a full
// handshake -> data transfer -> teardown cycle still completes
// correctly at 0%, 10%, and 30% simulated loss, exercising the real
// retransmission-timer / exponential-backoff code path in tcp.cpp.
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <random>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "ip.h"
#include "tcp.h"

using namespace minitcp;
using namespace std::chrono;

namespace {

constexpr uint32_t kServerAddr = 0x0A090001;  // 10.9.0.1
constexpr uint32_t kClientAddr = 0x0A090002;  // 10.9.0.2
constexpr uint16_t kServerPort = 9191;

struct Pipe {
    int read_fd;
    int write_fd;
};

// A datagram (not stream) socketpair, so each tun_write() on one end
// shows up as exactly one read() on the other — matching a real TUN
// device's one-packet-per-read semantics. A plain pipe() does NOT
// have this property: it's a byte stream, so two small segments
// written back-to-back can coalesce into a single read(), which would
// get misparsed as one (corrupt) packet. That bug bit the very first
// version of this test.
Pipe make_nonblocking_pipe() {
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, fds) != 0) {
        std::perror("socketpair");
        std::exit(1);
    }
    fcntl(fds[0], F_SETFL, O_NONBLOCK);
    return {fds[0], fds[1]};
}

// Drains any packets waiting on `from_read_fd` and, with probability
// `drop_rate`, discards each one instead of feeding it into the other
// side's handle_tcp() — the actual packet-loss simulation.
void forward_packets(int from_read_fd, int to_tun_fd, double drop_rate, std::mt19937& rng,
                     int& dropped_count) {
    uint8_t buf[2048];
    std::uniform_real_distribution<double> dist(0.0, 1.0);
    while (true) {
        ssize_t n = read(from_read_fd, buf, sizeof(buf));
        if (n <= 0) break;
        if (dist(rng) < drop_rate) {
            dropped_count++;
            continue;
        }
        IPHeader ip_hdr;
        if (!parse_ip_header(buf, static_cast<size_t>(n), ip_hdr)) continue;
        size_t header_bytes = static_cast<size_t>(ip_hdr.ihl) * 4;
        if (header_bytes > static_cast<size_t>(n)) continue;
        handle_tcp(to_tun_fd, ip_hdr, buf + header_bytes, static_cast<size_t>(n) - header_bytes,
                  false);
    }
}

void run_one_trial(double drop_rate) {
    std::mt19937 rng(12345u + static_cast<unsigned>(drop_rate * 1000));

    Pipe client_wire = make_nonblocking_pipe();
    Pipe server_wire = make_nonblocking_pipe();

    tcp_listen(kServerAddr, kServerPort);

    TCPConnPtr client = tcp_create();
    tcp_connect(client, client_wire.write_fd, kClientAddr, kServerAddr, kServerPort, false);

    const char* message = "hello from minitcp client";
    size_t message_len = std::strlen(message);

    TCPConnPtr server;
    std::vector<uint8_t> received;
    bool sent_data = false;
    bool client_closed = false;
    bool server_closed = false;
    int dropped_count = 0;

    auto deadline = steady_clock::now() + seconds(20);
    while (steady_clock::now() < deadline) {
        forward_packets(client_wire.read_fd, server_wire.write_fd, drop_rate, rng, dropped_count);
        forward_packets(server_wire.read_fd, client_wire.write_fd, drop_rate, rng, dropped_count);
        tcp_tick(client_wire.write_fd, false);
        tcp_tick(server_wire.write_fd, false);

        if (!server) {
            server = tcp_accept(kServerAddr, kServerPort);
        }

        if (server && tcp_is_established(client) && !sent_data) {
            tcp_send(client, client_wire.write_fd, reinterpret_cast<const uint8_t*>(message),
                    message_len, false);
            sent_data = true;
        }

        if (server && sent_data && received.size() < message_len) {
            uint8_t chunk[256];
            size_t n = tcp_recv(server, chunk, sizeof(chunk));
            if (n > 0) received.insert(received.end(), chunk, chunk + n);
        }

        // Both sides close once the message has been fully delivered —
        // the server's close (replying to the client's eventual FIN
        // with its own) is what lets the client ever leave FIN_WAIT_2.
        if (sent_data && received.size() == message_len && !client_closed) {
            tcp_close(client, client_wire.write_fd, false);
            client_closed = true;
        }
        if (server && received.size() == message_len && !server_closed) {
            tcp_close(server, server_wire.write_fd, false);
            server_closed = true;
        }

        if (client_closed && server_closed && tcp_is_closed(client) && tcp_is_closed(server)) {
            break;
        }

        std::this_thread::sleep_for(milliseconds(5));
    }

    assert(server != nullptr && "server connection never completed accept");
    assert(received.size() == message_len && "data never fully delivered");
    assert(std::memcmp(received.data(), message, message_len) == 0 && "delivered data corrupted");
    assert(tcp_is_closed(client) && "client connection never reached CLOSED");
    assert(tcp_is_closed(server) && "server connection never reached CLOSED");

    std::printf(
        "retransmission_test: drop_rate=%3.0f%%  completed OK  (simulated drops: %d, data: "
        "\"%.*s\")\n",
        drop_rate * 100.0, dropped_count, static_cast<int>(received.size()),
        reinterpret_cast<const char*>(received.data()));

    close(client_wire.read_fd);
    close(client_wire.write_fd);
    close(server_wire.read_fd);
    close(server_wire.write_fd);
}

}  // namespace

int main() {
    run_one_trial(0.0);
    run_one_trial(0.10);
    run_one_trial(0.30);
    std::printf("retransmission_test: all trials passed\n");
    return 0;
}
