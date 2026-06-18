#pragma once

#include <cstddef>
#include <cstdint>

namespace minitcp {

// Parses one raw IP packet read from a TUN fd, verifies its header
// checksum, and dispatches it to the matching protocol handler
// (ICMP/UDP/TCP) by protocol field. Shared by minitcp's own trace
// event loop (main.cpp) and the socket API's internal pump loop
// (socket_api.cpp) so both stay behaviorally identical.
void dispatch_ip_packet(int tun_fd, const uint8_t* buf, size_t n, bool trace);

}  // namespace minitcp
