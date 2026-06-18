#include "tun.h"

#include <cstring>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <unistd.h>

namespace minitcp {

int tun_alloc(std::string& dev_name) {
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        return -1;
    }

    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (!dev_name.empty()) {
        std::strncpy(ifr.ifr_name, dev_name.c_str(), IFNAMSIZ - 1);
    }

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        close(fd);
        return -1;
    }

    dev_name = ifr.ifr_name;
    return fd;
}

ssize_t tun_read(int fd, uint8_t* buf, size_t buf_len) {
    return read(fd, buf, buf_len);
}

ssize_t tun_write(int fd, const uint8_t* buf, size_t len) {
    return write(fd, buf, len);
}

}  // namespace minitcp
