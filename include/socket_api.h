#pragma once

#include <cstddef>
#include <cstdint>
#include <netinet/in.h>  // struct sockaddr_in
#include <string>
#include <sys/socket.h>  // SOL_SOCKET, SO_*, socklen_t
#include <sys/types.h>

namespace minitcp {

// Opens (or attaches to) the named TUN device and remembers `self_addr`
// as this process's own IP address for outgoing connections created
// via minitcp_connect(). Must be called once before any other
// minitcp_* function. Returns false on failure (check errno).
bool minitcp_init(const std::string& tun_dev_name, uint32_t self_addr, bool trace);

// Like minitcp_init, but uses an already-open fd instead of opening a
// TUN device. Exists for tests that want to exercise the blocking
// socket calls (which all go through this module's internal
// pump_once()/the fd set here) over an in-process socketpair instead
// of a real TUN device (which requires root/CAP_NET_ADMIN). Production
// code should use minitcp_init().
void minitcp_init_with_fd(int fd, uint32_t self_addr, bool trace);

// Opaque socket handle — application code never sees TCPConnection,
// TCPState, or any other TCP-internal type, only this pointer.
struct Socket;

Socket* minitcp_socket();

// Marks the socket as listening on `port` (on this process's
// self_addr). Returns false if that (self_addr, port) is already
// occupied by a live connection — see minitcp_setsockopt(SO_REUSEADDR).
bool minitcp_listen(Socket* sock, uint16_t port);

// Blocks, pumping the event loop, until a connection completes on a
// listening socket, or SO_RCVTIMEO elapses. Returns a new Socket for
// the accepted connection, or nullptr (with *timed_out set to true,
// if non-null) on timeout.
Socket* minitcp_accept(Socket* listener, bool* timed_out = nullptr);

// Active open: sends a SYN and blocks until the handshake completes
// or fails. Returns false on failure (e.g. RST or repeated timeout).
bool minitcp_connect(Socket* sock, uint32_t remote_addr, uint16_t remote_port);

// Queues `len` bytes for transmission. Returns bytes accepted, which
// may be fewer than `len` if SO_SNDBUF is full (-1 on a closed/invalid
// socket).
ssize_t minitcp_send(Socket* sock, const void* data, size_t len);

// Blocks, pumping the event loop, until at least one byte is
// available, the peer has closed, or SO_RCVTIMEO elapses. Returns 0 on
// a clean EOF, -1 on an invalid socket, kMinitcpTimeout on timeout.
ssize_t minitcp_recv(Socket* sock, void* buf, size_t maxlen);

// Initiates a graceful close (sends FIN if applicable) and frees the
// Socket handle. Does not block waiting for the final teardown ACKs.
void minitcp_close(Socket* sock);

// --- UDP socket API ---

// Creates a new UDP-flavored socket. Distinct from minitcp_socket()
// (TCP-only) so existing TCP call sites are unaffected.
Socket* minitcp_udp_socket();

// Binds the socket to `addr` (sin_family must be AF_INET; sin_port and
// sin_addr in network byte order, per POSIX). A zero sin_addr
// (INADDR_ANY) binds to this process's own address. Subsequent
// datagrams addressed to this exact (addr, port) are queued for
// minitcp_recvfrom() instead of being auto-echoed. Returns false if
// the address is already bound by another live UDP socket and
// SO_REUSEADDR has not been set (see minitcp_setsockopt).
bool minitcp_bind(Socket* sock, const struct sockaddr_in* addr);

// Sends `len` bytes to `dest` (same sockaddr_in convention as
// minitcp_bind). If the socket has not been bound yet, an ephemeral
// local UDP port is auto-assigned first (mirrors POSIX's implicit
// bind-on-sendto). Returns bytes sent, or -1 on an invalid socket.
ssize_t minitcp_sendto(Socket* sock, const void* data, size_t len,
                        const struct sockaddr_in* dest);

// Blocks, pumping the event loop, until a datagram is available or
// SO_RCVTIMEO elapses. Copies up to maxlen bytes into buf and, if
// src_addr is non-null, fills it with the sender's address. Returns
// the number of bytes copied, -1 on an invalid socket, or
// kMinitcpTimeout on timeout.
ssize_t minitcp_recvfrom(Socket* sock, void* buf, size_t maxlen,
                          struct sockaddr_in* src_addr);

// --- Socket options ---

// Returned by minitcp_recv/minitcp_recvfrom when SO_RCVTIMEO elapses
// with nothing available — distinct from the existing -1 (invalid
// socket) and 0 (clean EOF) conventions.
constexpr ssize_t kMinitcpTimeout = -2;

// Mirror POSIX setsockopt(2)/getsockopt(2). Only level == SOL_SOCKET
// and optname in {SO_RCVTIMEO, SO_REUSEADDR, SO_RCVBUF, SO_SNDBUF} are
// supported; anything else returns false. optval for SO_RCVTIMEO is a
// `struct timeval`; for the other three it's an `int`.
bool minitcp_setsockopt(Socket* sock, int level, int optname,
                         const void* optval, socklen_t optlen);
bool minitcp_getsockopt(Socket* sock, int level, int optname,
                         void* optval, socklen_t* optlen);

}  // namespace minitcp
