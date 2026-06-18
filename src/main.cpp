#include <cstring>
#include <poll.h>
#include <string>

#include "dispatch.h"
#include "tcp.h"
#include "tun.h"

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

    // Poll with a timeout (rather than blocking forever on tun_read)
    // so tcp_tick() runs periodically to drive retransmission timers
    // and TIME_WAIT expiry even when no packets are arriving.
    struct pollfd pfd{};
    pfd.fd = fd;
    pfd.events = POLLIN;

    uint8_t buf[2048];
    while (true) {
        int ready = poll(&pfd, 1, 200);
        if (ready > 0 && (pfd.revents & POLLIN)) {
            ssize_t n = minitcp::tun_read(fd, buf, sizeof(buf));
            if (n > 0) {
                minitcp::dispatch_ip_packet(fd, buf, static_cast<size_t>(n), trace);
            }
        }
        minitcp::tcp_tick(fd, trace);
    }

    return 0;
}
