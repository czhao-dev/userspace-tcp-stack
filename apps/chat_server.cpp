// Minimal chat server built entirely on the minitcp_* socket API —
// no direct access to TCPConnection/TCPState. Doubles as the curl
// cross-validation target: any request that looks like an HTTP verb
// gets a canned 200 OK instead of being echoed as chat.
#include "socket_api.h"

#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace {

uint32_t parse_addr(const char* s) {
    struct in_addr a;
    if (inet_pton(AF_INET, s, &a) != 1) {
        std::fprintf(stderr, "invalid address: %s\n", s);
        std::exit(1);
    }
    return ntohl(a.s_addr);
}

bool looks_like_http(const char* buf, ssize_t n) {
    if (n < 4) return false;
    return std::memcmp(buf, "GET ", 4) == 0 || std::memcmp(buf, "POST", 4) == 0 ||
          std::memcmp(buf, "HEAD", 4) == 0 || std::memcmp(buf, "PUT ", 4) == 0;
}

}  // namespace

int main(int argc, char** argv) {
    uint16_t port = 8080;
    std::string tun_dev = "tun0";
    std::string self_addr_str = "10.0.0.2";
    bool trace = false;

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = static_cast<uint16_t>(std::atoi(argv[++i]));
        } else if (std::strcmp(argv[i], "--tun") == 0 && i + 1 < argc) {
            tun_dev = argv[++i];
        } else if (std::strcmp(argv[i], "--addr") == 0 && i + 1 < argc) {
            self_addr_str = argv[++i];
        } else if (std::strcmp(argv[i], "--trace") == 0) {
            trace = true;
        }
    }

    uint32_t self_addr = parse_addr(self_addr_str.c_str());
    if (!minitcp::minitcp_init(tun_dev, self_addr, trace)) {
        std::perror("minitcp_init");
        return 1;
    }

    minitcp::Socket* listener = minitcp::minitcp_socket();
    minitcp::minitcp_listen(listener, port);
    std::printf("chat_server: listening on port %u (self=%s, tun=%s)\n", port,
               self_addr_str.c_str(), tun_dev.c_str());

    while (true) {
        minitcp::Socket* conn = minitcp::minitcp_accept(listener);
        std::printf("chat_server: client connected\n");

        char buf[4096];
        ssize_t n = minitcp::minitcp_recv(conn, buf, sizeof(buf));
        while (n > 0) {
            if (looks_like_http(buf, n)) {
                static const char response[] =
                    "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nhello\n";
                minitcp::minitcp_send(conn, response, sizeof(response) - 1);
                break;
            }
            std::fwrite(buf, 1, static_cast<size_t>(n), stdout);
            std::fflush(stdout);
            minitcp::minitcp_send(conn, buf, static_cast<size_t>(n));  // echo back as the "chat"
            n = minitcp::minitcp_recv(conn, buf, sizeof(buf));
        }

        std::printf("chat_server: client disconnected\n");
        minitcp::minitcp_close(conn);
    }
}
