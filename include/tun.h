#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <sys/types.h>

namespace minitcp {

// Opens /dev/net/tun and configures it via ioctl(TUNSETIFF) with
// IFF_TUN | IFF_NO_PI (raw IP packets, no 4-byte packet-info prefix).
// dev_name: desired interface name (e.g. "tun0"); pass an empty string
// to let the kernel auto-assign a name, in which case dev_name is
// updated with the assigned name on return.
// Returns the open file descriptor, or -1 on failure (check errno).
int tun_alloc(std::string& dev_name);

// Reads one raw IP packet from the TUN fd into buf (max buf_len bytes).
// Returns number of bytes read, 0 on EOF, or -1 on error.
ssize_t tun_read(int fd, uint8_t* buf, size_t buf_len);

// Writes one raw IP packet (header + payload, already serialized) to
// the TUN fd. Returns number of bytes written, or -1 on error.
ssize_t tun_write(int fd, const uint8_t* buf, size_t len);

}  // namespace minitcp
