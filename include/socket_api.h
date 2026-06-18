#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <sys/types.h>

namespace minitcp {

// Opens (or attaches to) the named TUN device and remembers `self_addr`
// as this process's own IP address for outgoing connections created
// via minitcp_connect(). Must be called once before any other
// minitcp_* function. Returns false on failure (check errno).
bool minitcp_init(const std::string& tun_dev_name, uint32_t self_addr, bool trace);

// Opaque socket handle — application code never sees TCPConnection,
// TCPState, or any other TCP-internal type, only this pointer.
struct Socket;

Socket* minitcp_socket();

// Marks the socket as listening on `port` (on this process's self_addr).
bool minitcp_listen(Socket* sock, uint16_t port);

// Blocks, pumping the event loop, until a connection completes on a
// listening socket. Returns a new Socket for the accepted connection.
Socket* minitcp_accept(Socket* listener);

// Active open: sends a SYN and blocks until the handshake completes
// or fails. Returns false on failure (e.g. RST or repeated timeout).
bool minitcp_connect(Socket* sock, uint32_t remote_addr, uint16_t remote_port);

// Queues `len` bytes for transmission. Returns bytes accepted (-1 on
// a closed/invalid socket).
ssize_t minitcp_send(Socket* sock, const void* data, size_t len);

// Blocks, pumping the event loop, until at least one byte is
// available or the peer has closed. Returns 0 on a clean EOF, -1 on
// an invalid socket.
ssize_t minitcp_recv(Socket* sock, void* buf, size_t maxlen);

// Initiates a graceful close (sends FIN if applicable) and frees the
// Socket handle. Does not block waiting for the final teardown ACKs.
void minitcp_close(Socket* sock);

}  // namespace minitcp
