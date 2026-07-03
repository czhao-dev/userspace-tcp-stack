//! The application-facing socket API (BSD-socket-style) plus the
//! `Stack` type that owns every piece of protocol state. Replaces the
//! original's opaque `Socket*` handle + free-function API
//! (`minitcp_*`) with an owned `Stack` and inherent methods taking a
//! `Copy`-able `SocketId`.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::unix::io::RawFd;
use std::time::{Duration, Instant};

use crate::icmp;
use crate::ip;
use crate::tcp::{self, ConnectionKey, TcpTable};
use crate::tun;
use crate::udp::{self, UdpTable};

/// Returned by `recv`/`recvfrom` when SO_RCVTIMEO elapses with nothing
/// available — distinct from 0 (clean EOF) and -1 (invalid socket).
pub const TIMEOUT: isize = -2;

/// Opaque socket handle — application code never sees `TcpConnection`,
/// `TcpState`, or any other protocol-internal type, only this id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SocketId(u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SocketKind {
    Tcp,
    Udp,
}

/// Per-socket option storage. A plain struct rather than a generic
/// option map, since only four options are supported.
#[derive(Debug, Clone, Copy, Default)]
struct SocketOptions {
    rcvtimeo: Option<Duration>, // SO_RCVTIMEO; None = block forever
    reuse_addr: bool,           // SO_REUSEADDR
    rcvbuf: Option<usize>,      // SO_RCVBUF; None = use protocol default
    sndbuf: Option<usize>,      // SO_SNDBUF; None = use protocol default (TCP only)
}

/// One of the four sockopts this stack understands. Replaces the
/// original's `(level, optname, void*, optlen)` POSIX-mirroring
/// signature — nothing here talks to a real OS `setsockopt(2)`, so a
/// closed enum is both safer and clearer than reimplementing raw
/// option-byte marshaling for no benefit.
#[derive(Debug, Clone, Copy)]
pub enum SockOpt {
    /// A zero `Duration` disables the timeout (reverts to blocking
    /// forever), mirroring the original's `tv_sec==0 && tv_usec==0`
    /// convention for POSIX's `SO_RCVTIMEO`.
    RcvTimeo(Duration),
    ReuseAddr(bool),
    RcvBuf(usize),
    SndBuf(usize),
}

struct Socket {
    kind: SocketKind,

    // TCP
    conn_key: Option<ConnectionKey>,
    is_listener: bool,
    listen_addr: u32,
    listen_port: u16,

    // UDP
    udp_key: Option<(u32, u16)>,

    opts: SocketOptions,
}

impl Socket {
    fn new(kind: SocketKind) -> Self {
        Socket {
            kind,
            conn_key: None,
            is_listener: false,
            listen_addr: 0,
            listen_port: 0,
            udp_key: None,
            opts: SocketOptions::default(),
        }
    }
}

/// Owns every piece of protocol state for one MiniTCP instance: the
/// TUN fd, the TCP connection table, the UDP bind table, and the
/// application-level socket table. There is no global mutable state
/// anywhere in this crate — everything lives here, threaded through as
/// `&mut self`.
pub struct Stack {
    tun_fd: RawFd,
    self_addr: u32,
    trace: bool,
    next_udp_ephemeral_port: u16,

    tcp: TcpTable,
    udp: UdpTable,

    sockets: HashMap<SocketId, Socket>,
    next_socket_id: u64,
}

impl Stack {
    /// Opens (or attaches to) the named TUN device and remembers
    /// `self_addr` as this process's own IP address for outgoing
    /// connections created via `connect()`. Returns `None` on failure
    /// (check `std::io::Error::last_os_error()`).
    pub fn init(tun_dev_name: &str, self_addr: u32, trace: bool) -> Option<Stack> {
        let mut dev = tun_dev_name.to_string();
        let fd = tun::tun_alloc(&mut dev);
        if fd < 0 {
            return None;
        }
        Some(Stack::new(fd, self_addr, trace))
    }

    /// Test-only: bypasses `tun_alloc()`, for tests that want a real
    /// socketpair standing in for a TUN device (no root/CAP_NET_ADMIN
    /// needed). Production code should use `Stack::init()`.
    pub fn init_with_fd(fd: RawFd, self_addr: u32, trace: bool) -> Stack {
        Stack::new(fd, self_addr, trace)
    }

    fn new(tun_fd: RawFd, self_addr: u32, trace: bool) -> Stack {
        Stack {
            tun_fd,
            self_addr,
            trace,
            next_udp_ephemeral_port: 51000, // separate counter from TCP's
            tcp: TcpTable::new(),
            udp: UdpTable::new(),
            sockets: HashMap::new(),
            next_socket_id: 1,
        }
    }

    fn alloc_socket(&mut self, kind: SocketKind) -> SocketId {
        let id = SocketId(self.next_socket_id);
        self.next_socket_id += 1;
        self.sockets.insert(id, Socket::new(kind));
        id
    }

    /// Parses one raw IP packet, verifies its header checksum, and
    /// dispatches it to the matching protocol handler (ICMP/UDP/TCP) by
    /// protocol field. Shared by `minitcp`'s own trace event loop and
    /// this module's internal `pump_once` so both stay behaviorally
    /// identical.
    fn dispatch_ip_packet(&mut self, buf: &[u8]) {
        let Some(ip_hdr) = ip::parse_ip_header(buf) else {
            return;
        };
        if !ip::verify_ip_checksum(buf) {
            if self.trace {
                println!("[IP  ] recv  bad checksum, dropping packet");
            }
            return;
        }

        if self.trace {
            let src = Ipv4Addr::from(ip_hdr.src_addr);
            let dst = Ipv4Addr::from(ip_hdr.dst_addr);
            let proto = match ip_hdr.protocol {
                1 => "ICMP",
                6 => "TCP",
                17 => "UDP",
                _ => "?",
            };
            println!("[IP  ] recv  {src} -> {dst}   proto={proto}  len={}", buf.len());
        }

        let header_bytes = (ip_hdr.ihl as usize) * 4;
        if header_bytes > buf.len() {
            return;
        }
        let payload = &buf[header_bytes..];

        let tun_fd = self.tun_fd;
        let trace = self.trace;
        match ip_hdr.protocol {
            1 => icmp::handle_icmp(tun_fd, &ip_hdr, payload, trace),
            17 => self.udp.handle_datagram(tun_fd, &ip_hdr, payload, trace),
            6 => self.tcp.handle_segment(tun_fd, &ip_hdr, payload, trace),
            _ => {}
        }
    }

    /// Reads one packet from the TUN fd (if any arrived within
    /// `timeout_ms`), dispatches it, and always advances TCP's
    /// retransmission/TIME_WAIT timers. This is the entire body of the
    /// standalone `minitcp` binary's event loop (see
    /// `src/bin/minitcp.rs`) — blocking socket calls below reuse it
    /// verbatim while waiting on a condition, so the two stay
    /// behaviorally identical by construction rather than by convention.
    pub fn pump_once(&mut self, timeout_ms: i32) {
        let mut pfd = libc::pollfd {
            fd: self.tun_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if ready > 0 && (pfd.revents & libc::POLLIN) != 0 {
            let mut buf = [0u8; 2048];
            let n = tun::tun_read(self.tun_fd, &mut buf);
            if n > 0 {
                self.dispatch_ip_packet(&buf[..n as usize]);
            }
        }
        let tun_fd = self.tun_fd;
        let trace = self.trace;
        self.tcp.tick(tun_fd, trace);
    }

    fn deadline_elapsed(has_timeout: Option<Duration>, start: Instant) -> bool {
        match has_timeout {
            Some(timeout) => start.elapsed() >= timeout,
            None => false,
        }
    }

    /// True once the connection has reached a state where the remote
    /// can no longer send data (mirrors the original's check for
    /// CLOSE_WAIT/LAST_ACK/CLOSED/TIME_WAIT, generalized to "connection
    /// reaped" for the case where it's since been cleaned up).
    fn tcp_remote_closed_no_more_data(&self, key: ConnectionKey) -> bool {
        match self.tcp.lookup(key) {
            None => true,
            Some(c) => matches!(
                c.state,
                tcp::TcpState::CloseWait | tcp::TcpState::LastAck | tcp::TcpState::Closed | tcp::TcpState::TimeWait
            ),
        }
    }

    // --- TCP socket API ---

    pub fn socket(&mut self) -> SocketId {
        self.alloc_socket(SocketKind::Tcp)
    }

    /// Marks the socket as listening on `port` (on this process's
    /// self_addr). Returns false if that (self_addr, port) is already
    /// occupied by a live connection (see `SockOpt::ReuseAddr`).
    pub fn listen(&mut self, id: SocketId, port: u16) -> bool {
        let self_addr = self.self_addr;
        let reuse_addr = match self.sockets.get(&id) {
            Some(s) => s.opts.reuse_addr,
            None => return false,
        };
        if let Some(sock) = self.sockets.get_mut(&id) {
            sock.is_listener = true;
            sock.listen_addr = self_addr;
            sock.listen_port = port;
        }
        self.tcp.listen(self_addr, port, reuse_addr)
    }

    /// Blocks, pumping the event loop, until a connection completes on
    /// a listening socket, or SO_RCVTIMEO elapses. Returns the new
    /// socket id for the accepted connection, plus whether the call
    /// timed out instead.
    pub fn accept(&mut self, listener: SocketId) -> (Option<SocketId>, bool) {
        let (listen_addr, listen_port, rcvtimeo, rcvbuf, sndbuf) = {
            let Some(l) = self.sockets.get(&listener) else {
                return (None, false);
            };
            if !l.is_listener {
                return (None, false);
            }
            (l.listen_addr, l.listen_port, l.opts.rcvtimeo, l.opts.rcvbuf, l.opts.sndbuf)
        };

        let start = Instant::now();
        loop {
            if let Some(key) = self.tcp.accept(listen_addr, listen_port) {
                if let Some(v) = rcvbuf {
                    self.tcp.set_recv_cap(key, v);
                }
                if let Some(v) = sndbuf {
                    self.tcp.set_send_cap(key, v);
                }
                let id = self.alloc_socket(SocketKind::Tcp);
                self.sockets.get_mut(&id).unwrap().conn_key = Some(key);
                return (Some(id), false);
            }
            if Self::deadline_elapsed(rcvtimeo, start) {
                return (None, true);
            }
            self.pump_once(100);
        }
    }

    /// Active open: sends a SYN and blocks until the handshake
    /// completes or fails. Returns false on failure (e.g. RST or
    /// repeated timeout).
    pub fn connect(&mut self, id: SocketId, remote_addr: u32, remote_port: u16) -> bool {
        let self_addr = self.self_addr;
        let tun_fd = self.tun_fd;
        let trace = self.trace;
        let (rcvbuf, sndbuf) = {
            let Some(sock) = self.sockets.get(&id) else {
                return false;
            };
            (sock.opts.rcvbuf, sock.opts.sndbuf)
        };

        let key = self.tcp.connect(tun_fd, self_addr, remote_addr, remote_port, trace);
        if let Some(sock) = self.sockets.get_mut(&id) {
            sock.conn_key = Some(key);
        }
        if let Some(v) = rcvbuf {
            self.tcp.set_recv_cap(key, v);
        }
        if let Some(v) = sndbuf {
            self.tcp.set_send_cap(key, v);
        }

        // The connection's own retransmit queue keeps resending the SYN
        // on timeout; we just pump the loop until it resolves one way
        // or the other, with a generous overall cap so a truly
        // unreachable peer doesn't hang forever.
        for _ in 0..300 {
            if self.tcp.is_established(key) {
                return true;
            }
            if self.tcp.is_closed(key) {
                return false;
            }
            self.pump_once(100);
        }
        false
    }

    /// Queues `data` for transmission. Returns bytes accepted, which
    /// may be fewer than `data.len()` if SO_SNDBUF is full (-1 on a
    /// closed/invalid socket).
    pub fn send(&mut self, id: SocketId, data: &[u8]) -> isize {
        let Some(key) = self.sockets.get(&id).and_then(|s| s.conn_key) else {
            return -1;
        };
        let tun_fd = self.tun_fd;
        let trace = self.trace;
        self.tcp.send(key, tun_fd, data, trace) as isize
    }

    /// Blocks, pumping the event loop, until at least one byte is
    /// available, the peer has closed, or SO_RCVTIMEO elapses. Returns
    /// 0 on a clean EOF, -1 on an invalid socket, `TIMEOUT` on timeout.
    pub fn recv(&mut self, id: SocketId, buf: &mut [u8]) -> isize {
        let (key, rcvtimeo) = {
            let Some(sock) = self.sockets.get(&id) else {
                return -1;
            };
            let Some(key) = sock.conn_key else {
                return -1;
            };
            (key, sock.opts.rcvtimeo)
        };

        let start = Instant::now();
        loop {
            let n = self.tcp.recv(key, buf);
            if n > 0 {
                return n as isize;
            }
            if self.tcp_remote_closed_no_more_data(key) {
                return 0;
            }
            if Self::deadline_elapsed(rcvtimeo, start) {
                return TIMEOUT;
            }
            self.pump_once(100);
        }
    }

    /// Initiates a graceful close (sends FIN if applicable) and frees
    /// the socket. Does not block waiting for the final teardown ACKs
    /// beyond a brief best-effort linger (see below).
    pub fn close(&mut self, id: SocketId) {
        let Some(sock) = self.sockets.remove(&id) else {
            return;
        };
        match sock.kind {
            SocketKind::Udp => {
                if let Some(key) = sock.udp_key {
                    self.udp.unbind(key);
                }
            }
            SocketKind::Tcp => {
                if let Some(key) = sock.conn_key {
                    let tun_fd = self.tun_fd;
                    let trace = self.trace;
                    self.tcp.close(key, tun_fd, trace);

                    // Linger briefly, pumping the event loop, so a
                    // process that calls close() and immediately exits
                    // still completes the FIN/ACK teardown instead of
                    // abandoning it mid-handshake — unlike a
                    // kernel-resident TCP stack, nothing is left to
                    // answer retransmits once this process is gone.
                    for _ in 0..50 {
                        if self.tcp.is_closed(key) {
                            break;
                        }
                        self.pump_once(100);
                    }
                }
            }
        }
    }

    // --- UDP socket API ---

    /// Creates a new UDP-flavored socket. Distinct from `socket()`
    /// (TCP-only) so existing TCP call sites are unaffected.
    pub fn udp_socket(&mut self) -> SocketId {
        self.alloc_socket(SocketKind::Udp)
    }

    /// Binds the socket to `addr`. An unspecified (`0.0.0.0`) address
    /// binds to this process's own address. Subsequent datagrams
    /// addressed to this exact (addr, port) are queued for
    /// `recvfrom()` instead of being auto-echoed. Returns false if the
    /// address is already bound and `SockOpt::ReuseAddr` has not been set.
    pub fn bind(&mut self, id: SocketId, addr: SocketAddrV4) -> bool {
        let (kind, reuse_addr, rcvbuf) = {
            let Some(sock) = self.sockets.get(&id) else {
                return false;
            };
            (sock.kind, sock.opts.reuse_addr, sock.opts.rcvbuf)
        };
        if kind != SocketKind::Udp {
            return false;
        }

        let mut bind_addr = u32::from(*addr.ip());
        if bind_addr == 0 {
            bind_addr = self.self_addr; // unspecified address -> this process's address
        }
        let bind_port = addr.port();
        let cap = rcvbuf.unwrap_or(udp::DEFAULT_RECV_QUEUE_CAP_BYTES);

        let ok = self.udp.bind(bind_addr, bind_port, reuse_addr, cap);
        if ok {
            if let Some(sock) = self.sockets.get_mut(&id) {
                sock.udp_key = Some((bind_addr, bind_port));
            }
        }
        ok
    }

    /// Sends `data` to `dest`. If the socket has not been bound yet, an
    /// ephemeral local UDP port is auto-assigned first (mirrors POSIX
    /// UDP sendto()-without-bind semantics). Returns bytes sent, or -1
    /// on an invalid socket.
    pub fn sendto(&mut self, id: SocketId, data: &[u8], dest: SocketAddrV4) -> isize {
        let (kind, existing_key, reuse_addr, rcvbuf) = {
            let Some(sock) = self.sockets.get(&id) else {
                return -1;
            };
            (sock.kind, sock.udp_key, sock.opts.reuse_addr, sock.opts.rcvbuf)
        };
        if kind != SocketKind::Udp {
            return -1;
        }

        let key = if let Some(k) = existing_key {
            k
        } else {
            let self_addr = self.self_addr;
            let port = self.next_udp_ephemeral_port;
            self.next_udp_ephemeral_port = self.next_udp_ephemeral_port.wrapping_add(1);
            let cap = rcvbuf.unwrap_or(udp::DEFAULT_RECV_QUEUE_CAP_BYTES);
            self.udp.bind(self_addr, port, reuse_addr, cap);
            if let Some(sock) = self.sockets.get_mut(&id) {
                sock.udp_key = Some((self_addr, port));
            }
            (self_addr, port)
        };

        let dst_addr = u32::from(*dest.ip());
        let dst_port = dest.port();
        udp::send_datagram(self.tun_fd, key.0, key.1, dst_addr, dst_port, data);
        data.len() as isize
    }

    /// Blocks, pumping the event loop, until a datagram is available or
    /// SO_RCVTIMEO elapses. Returns the number of bytes copied (up to
    /// `buf.len()`) and the sender's address, -1 (and `None`) on an
    /// invalid socket, or `TIMEOUT` (and `None`) on timeout.
    pub fn recvfrom(&mut self, id: SocketId, buf: &mut [u8]) -> (isize, Option<SocketAddrV4>) {
        let (kind, udp_key, rcvtimeo) = {
            let Some(sock) = self.sockets.get(&id) else {
                return (-1, None);
            };
            (sock.kind, sock.udp_key, sock.opts.rcvtimeo)
        };
        if kind != SocketKind::Udp {
            return (-1, None);
        }

        let start = Instant::now();
        loop {
            if let Some(key) = udp_key {
                if let Some(dg) = self.udp.recv(key) {
                    let n = buf.len().min(dg.data.len());
                    buf[..n].copy_from_slice(&dg.data[..n]);
                    let src = SocketAddrV4::new(Ipv4Addr::from(dg.src_addr), dg.src_port);
                    return (n as isize, Some(src));
                }
            }
            if Self::deadline_elapsed(rcvtimeo, start) {
                return (TIMEOUT, None);
            }
            self.pump_once(100);
        }
    }

    // --- Socket options ---

    pub fn setsockopt(&mut self, id: SocketId, opt: SockOpt) -> bool {
        let (kind, conn_key, udp_key) = match self.sockets.get(&id) {
            Some(s) => (s.kind, s.conn_key, s.udp_key),
            None => return false,
        };

        let Some(sock) = self.sockets.get_mut(&id) else {
            return false;
        };
        match opt {
            SockOpt::RcvTimeo(d) => {
                sock.opts.rcvtimeo = if d.is_zero() { None } else { Some(d) };
                true
            }
            SockOpt::ReuseAddr(v) => {
                sock.opts.reuse_addr = v;
                true
            }
            SockOpt::RcvBuf(v) => {
                if v == 0 {
                    return false;
                }
                sock.opts.rcvbuf = Some(v);
                match kind {
                    SocketKind::Tcp => {
                        if let Some(key) = conn_key {
                            self.tcp.set_recv_cap(key, v);
                        }
                    }
                    SocketKind::Udp => {
                        if let Some(key) = udp_key {
                            self.udp.set_recv_cap(key, v);
                        }
                    }
                }
                true
            }
            SockOpt::SndBuf(v) => {
                if v == 0 {
                    return false;
                }
                sock.opts.sndbuf = Some(v);
                if kind == SocketKind::Tcp {
                    if let Some(key) = conn_key {
                        self.tcp.set_send_cap(key, v);
                    }
                }
                true
            }
        }
    }

    pub fn get_rcvtimeo(&self, id: SocketId) -> Option<Duration> {
        self.sockets.get(&id).and_then(|s| s.opts.rcvtimeo)
    }

    pub fn get_reuse_addr(&self, id: SocketId) -> bool {
        self.sockets.get(&id).is_some_and(|s| s.opts.reuse_addr)
    }

    pub fn get_rcvbuf(&self, id: SocketId) -> usize {
        self.sockets
            .get(&id)
            .and_then(|s| s.opts.rcvbuf)
            .unwrap_or(tcp::DEFAULT_RECV_BUFFER_CAP)
    }

    pub fn get_sndbuf(&self, id: SocketId) -> usize {
        self.sockets
            .get(&id)
            .and_then(|s| s.opts.sndbuf)
            .unwrap_or(tcp::DEFAULT_SEND_BUFFER_CAP)
    }
}
