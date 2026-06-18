// Minimal chat client built entirely on the minitcp_* socket API.
// Reads lines from stdin, sends each to chat_server, prints the
// echoed reply. Runs on its own TUN device (default tun1) so it can
// genuinely connect to chat_server (on tun0) through the kernel's own
// IP forwarding between the two — a real two-party conversation over
// our own TCP implementation, not just against external tools.
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

}  // namespace

int main(int argc, char** argv) {
    uint16_t port = 8080;
    std::string tun_dev = "tun1";
    std::string self_addr_str = "10.0.1.2";
    std::string server_addr_str = "10.0.0.2";
    bool trace = false;

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = static_cast<uint16_t>(std::atoi(argv[++i]));
        } else if (std::strcmp(argv[i], "--tun") == 0 && i + 1 < argc) {
            tun_dev = argv[++i];
        } else if (std::strcmp(argv[i], "--addr") == 0 && i + 1 < argc) {
            self_addr_str = argv[++i];
        } else if (std::strcmp(argv[i], "--server") == 0 && i + 1 < argc) {
            server_addr_str = argv[++i];
        } else if (std::strcmp(argv[i], "--trace") == 0) {
            trace = true;
        }
    }

    uint32_t self_addr = parse_addr(self_addr_str.c_str());
    uint32_t server_addr = parse_addr(server_addr_str.c_str());

    if (!minitcp::minitcp_init(tun_dev, self_addr, trace)) {
        std::perror("minitcp_init");
        return 1;
    }

    minitcp::Socket* sock = minitcp::minitcp_socket();
    if (!minitcp::minitcp_connect(sock, server_addr, port)) {
        std::fprintf(stderr, "chat_client: failed to connect to %s:%u\n",
                     server_addr_str.c_str(), port);
        return 1;
    }
    std::printf("chat_client: connected to %s:%u -- type messages, Ctrl+D to quit\n",
               server_addr_str.c_str(), port);

    char line[1024];
    while (std::fgets(line, sizeof(line), stdin)) {
        size_t len = std::strlen(line);
        minitcp::minitcp_send(sock, line, len);

        char buf[2048];
        ssize_t n = minitcp::minitcp_recv(sock, buf, sizeof(buf));
        if (n <= 0) {
            std::printf("chat_client: server closed the connection\n");
            break;
        }
        std::fwrite(buf, 1, static_cast<size_t>(n), stdout);
        std::fflush(stdout);
    }

    minitcp::minitcp_close(sock);
    return 0;
}
