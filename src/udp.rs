use std::collections::{HashMap, VecDeque};
use std::os::unix::io::RawFd;

use crate::ip::{self, IpHeader, IP_HEADER_LEN};

pub const UDP_HEADER_LEN: usize = 8;

/// One datagram sitting in a bound UDP socket's receive queue, plus
/// the sender's address so it can be reported back via recvfrom().
#[derive(Debug, Clone)]
pub struct UdpDatagram {
    pub src_addr: u32, // host order
    pub src_port: u16,
    pub data: Vec<u8>,
}

/// Per-binding state for an application-level UDP socket bound to
/// (bind_addr, bind_port). Much simpler than a TCP connection: no
/// sequence numbers or retransmission, just a bounded queue of
/// datagrams addressed to this (addr, port) waiting to be read.
#[derive(Debug)]
pub struct UdpBinding {
    pub recv_queue: VecDeque<UdpDatagram>,
    pub recv_queue_cap_bytes: usize,
}

pub const DEFAULT_RECV_QUEUE_CAP_BYTES: usize = 65536;

/// (addr, port) -> the binding registered there, if any. This table is
/// the sole owner of every bound socket's receive queue; application
/// code (see `stack.rs`) refers to a binding only by its `(addr, port)`
/// key, never by a shared pointer to the data itself.
#[derive(Default)]
pub struct UdpTable {
    binds: HashMap<(u32, u16), UdpBinding>,
}

impl UdpTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a binding at (addr, port), used by `handle_datagram()`
    /// to route incoming datagrams to it instead of the default
    /// auto-echo. Fails if that exact (addr, port) is already bound,
    /// unless `reuse_addr` is set (in which case the old binding is
    /// simply replaced). Returns the initial receive-queue byte cap to
    /// use (the caller's SO_RCVBUF override if any, else the default).
    pub fn bind(&mut self, addr: u32, port: u16, reuse_addr: bool, recv_cap_bytes: usize) -> bool {
        let key = (addr, port);
        if self.binds.contains_key(&key) && !reuse_addr {
            return false;
        }
        self.binds.insert(
            key,
            UdpBinding {
                recv_queue: VecDeque::new(),
                recv_queue_cap_bytes: recv_cap_bytes,
            },
        );
        true
    }

    /// Removes the binding at `key`, if any (called from Stack::close()).
    pub fn unbind(&mut self, key: (u32, u16)) {
        self.binds.remove(&key);
    }

    pub fn set_recv_cap(&mut self, key: (u32, u16), cap_bytes: usize) {
        if let Some(b) = self.binds.get_mut(&key) {
            b.recv_queue_cap_bytes = cap_bytes;
        }
    }

    pub fn binding(&self, key: (u32, u16)) -> Option<&UdpBinding> {
        self.binds.get(&key)
    }

    pub fn is_bound(&self, key: (u32, u16)) -> bool {
        self.binds.contains_key(&key)
    }

    /// Pops the oldest queued datagram for `key`, if any.
    pub fn recv(&mut self, key: (u32, u16)) -> Option<UdpDatagram> {
        self.binds.get_mut(&key).and_then(|b| b.recv_queue.pop_front())
    }

    fn deliver(&mut self, key: (u32, u16), src_addr: u32, src_port: u16, data: &[u8]) {
        let Some(binding) = self.binds.get_mut(&key) else {
            return;
        };
        let used: usize = binding.recv_queue.iter().map(|dg| dg.data.len()).sum();
        if used + data.len() > binding.recv_queue_cap_bytes {
            // SO_RCVBUF full — drop the new datagram, mirroring a
            // kernel dropping on a full receive buffer.
            return;
        }
        binding.recv_queue.push_back(UdpDatagram {
            src_addr,
            src_port,
            data: data.to_vec(),
        });
    }

    /// Handles one received UDP datagram contained in `payload` (the IP
    /// payload), where `ip_hdr` is the already-parsed IP header of the
    /// packet that carried it. If a binding exists for the exact
    /// (ip_hdr.dst_addr, dst_port) destination, the datagram is queued
    /// for it; otherwise it's echoed back to the sender's
    /// (src_addr, src_port), exactly as before this socket API existed.
    pub fn handle_datagram(&mut self, tun_fd: RawFd, ip_hdr: &IpHeader, payload: &[u8], trace: bool) {
        if payload.len() < UDP_HEADER_LEN {
            return;
        }

        let src_port = u16::from_be_bytes([payload[0], payload[1]]);
        let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
        let data = &payload[UDP_HEADER_LEN..];

        if trace {
            println!("[UDP ] recv  {src_port} -> {dst_port}  len={}", data.len());
        }

        let key = (ip_hdr.dst_addr, dst_port);
        if self.is_bound(key) {
            self.deliver(key, ip_hdr.src_addr, src_port, data);
            if trace {
                println!("[UDP ] deliver -> bound app socket on port {dst_port}");
            }
            return;
        }

        // No application socket bound on this port — auto-echo back to
        // the sender, exactly as before this socket API existed.
        send_datagram(tun_fd, ip_hdr.dst_addr, dst_port, ip_hdr.src_addr, src_port, data);
        if trace {
            println!("[UDP ] send  {dst_port} -> {src_port}  len={}", data.len());
        }
    }
}

impl Default for UdpBinding {
    fn default() -> Self {
        UdpBinding {
            recv_queue: VecDeque::new(),
            recv_queue_cap_bytes: DEFAULT_RECV_QUEUE_CAP_BYTES,
        }
    }
}

/// Builds the 12-byte UDP pseudo-header (RFC 768), used only as
/// scratch input to `checksum16` — it's never actually transmitted.
fn build_pseudo_header(src_addr: u32, dst_addr: u32, udp_length: u16, out: &mut [u8]) {
    out[0..4].copy_from_slice(&src_addr.to_be_bytes());
    out[4..8].copy_from_slice(&dst_addr.to_be_bytes());
    out[8] = 0;
    out[9] = 17; // protocol = UDP
    out[10..12].copy_from_slice(&udp_length.to_be_bytes());
}

/// Builds one UDP/IP packet (src_addr, src_port) -> (dst_addr, dst_port)
/// carrying `data` and sends it via `tun_fd`. Used both by
/// `handle_datagram()`'s auto-echo fallback and by `Stack::sendto()`.
pub fn send_datagram(
    tun_fd: RawFd,
    src_addr: u32,
    src_port: u16,
    dst_addr: u32,
    dst_port: u16,
    data: &[u8],
) {
    let udp_len = (UDP_HEADER_LEN + data.len()) as u16;

    // Build pseudo-header + UDP header + data into one scratch buffer
    // so the checksum can be computed with a single checksum16 call
    // rather than incremental partial sums.
    let mut scratch = vec![0u8; 12 + udp_len as usize];
    build_pseudo_header(src_addr, dst_addr, udp_len, &mut scratch[..12]);

    let udp_part = &mut scratch[12..];
    udp_part[0..2].copy_from_slice(&src_port.to_be_bytes());
    udp_part[2..4].copy_from_slice(&dst_port.to_be_bytes());
    udp_part[4..6].copy_from_slice(&udp_len.to_be_bytes());
    udp_part[6] = 0; // checksum placeholder
    udp_part[7] = 0;
    if !data.is_empty() {
        udp_part[UDP_HEADER_LEN..].copy_from_slice(data);
    }

    let csum = ip::checksum16(&scratch);
    scratch[12 + 6..12 + 8].copy_from_slice(&csum.to_be_bytes());

    let hdr = IpHeader {
        version: 4,
        ihl: 5,
        tos: 0,
        total_length: (IP_HEADER_LEN as u16) + udp_len,
        identification: 0,
        flags: 0,
        fragment_offset: 0,
        ttl: 64,
        protocol: 17,
        header_checksum: 0,
        src_addr,
        dst_addr,
    };

    let mut packet = vec![0u8; IP_HEADER_LEN + udp_len as usize];
    ip::build_ip_header(&hdr, &mut packet);
    packet[IP_HEADER_LEN..].copy_from_slice(&scratch[12..]);

    ip::send_ip_packet(tun_fd, &packet);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp::{self, TcpTable, TCP_ACK, TCP_FIN, TCP_SYN};
    use std::os::fd::AsRawFd;

    const SERVER_ADDR: u32 = 0x0A0B_0001; // 10.11.0.1
    const CLIENT_ADDR: u32 = 0x0A0B_0002; // 10.11.0.2

    fn build_udp_packet(src_port: u16, dst_port: u16, data: &[u8]) -> Vec<u8> {
        let udp_len = (UDP_HEADER_LEN + data.len()) as u16;
        let mut pkt = vec![0u8; udp_len as usize];
        pkt[0..2].copy_from_slice(&src_port.to_be_bytes());
        pkt[2..4].copy_from_slice(&dst_port.to_be_bytes());
        pkt[4..6].copy_from_slice(&udp_len.to_be_bytes());
        // pkt[6..8] checksum left zero — not validated by handle_datagram.
        if !data.is_empty() {
            pkt[UDP_HEADER_LEN..].copy_from_slice(data);
        }
        pkt
    }

    fn make_ip_header() -> IpHeader {
        IpHeader {
            version: 4,
            ihl: 5,
            protocol: 17,
            ttl: 64,
            src_addr: CLIENT_ADDR,
            dst_addr: SERVER_ADDR,
            ..Default::default()
        }
    }

    fn dev_null_fd() -> RawFd {
        std::fs::File::create("/dev/null").unwrap().as_raw_fd()
    }

    #[test]
    fn sendto_recvfrom_round_trip() {
        let mut table = UdpTable::new();
        assert!(table.bind(SERVER_ADDR, 9000, false, DEFAULT_RECV_QUEUE_CAP_BYTES));

        let ip_hdr = make_ip_header();
        let pkt = build_udp_packet(41000, 9000, b"hello");
        table.handle_datagram(dev_null_fd(), &ip_hdr, &pkt, false);

        let dg = table.recv((SERVER_ADDR, 9000)).expect("datagram queued");
        assert_eq!(dg.src_addr, CLIENT_ADDR);
        assert_eq!(dg.src_port, 41000);
        assert_eq!(dg.data, b"hello");
    }

    #[test]
    fn recv_queue_cap_drops_oversized_datagram() {
        let mut table = UdpTable::new();
        assert!(table.bind(SERVER_ADDR, 9100, false, 4)); // smaller than the 5-byte datagram below

        let ip_hdr = make_ip_header();
        let fd = dev_null_fd();

        let too_big = build_udp_packet(41010, 9100, b"12345");
        table.handle_datagram(fd, &ip_hdr, &too_big, false);
        assert!(table.recv((SERVER_ADDR, 9100)).is_none()); // dropped: exceeds the cap

        let fits = build_udp_packet(41010, 9100, b"ok");
        table.handle_datagram(fd, &ip_hdr, &fits, false);
        assert!(table.recv((SERVER_ADDR, 9100)).is_some()); // within the cap: delivered
    }

    #[test]
    fn echo_fallback_when_unbound() {
        let mut fds = [0 as RawFd; 2];
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) },
            0
        );

        let mut table = UdpTable::new();
        let ip_hdr = make_ip_header();
        let pkt = build_udp_packet(41001, 9001, b"ping"); // nothing bound to 9001
        table.handle_datagram(fds[1], &ip_hdr, &pkt, false);

        let mut buf = [0u8; 256];
        let n = unsafe { libc::read(fds[0], buf.as_mut_ptr() as *mut _, buf.len()) };
        assert!(n > 0);
        let n = n as usize;

        let reply_hdr = ip::parse_ip_header(&buf[..n]).expect("valid IP header");
        assert_eq!(reply_hdr.dst_addr, CLIENT_ADDR);
        assert_eq!(reply_hdr.src_addr, SERVER_ADDR);

        let reply_data = &buf[IP_HEADER_LEN + UDP_HEADER_LEN..n];
        assert_eq!(reply_data, b"ping");

        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
    }

    #[test]
    fn so_reuseaddr_listen_guard() {
        const LISTEN_PORT: u16 = 9500;
        const REMOTE_CLIENT_ADDR: u32 = 0x0A0B_0003; // 10.11.0.3
        const REMOTE_PORT: u16 = 7000;

        let mut tcp = TcpTable::new();
        let fd = dev_null_fd();

        // Re-issuing listen on a port already in LISTEN is a no-op
        // success (this is what keeps the retransmission test's
        // multi-trial-same-port pattern working).
        assert!(tcp.listen(SERVER_ADDR, LISTEN_PORT, false));
        assert!(tcp.listen(SERVER_ADDR, LISTEN_PORT, false));

        // Occupy a fresh local port via an *outgoing* connection
        // (connect, not listen) so the port under test was never
        // registered as a listener — the realistic case the
        // SO_REUSEADDR guard is meant for: a port whose only history is
        // a now-dead connection, not an active listener.
        let key = tcp.connect(fd, SERVER_ADDR, REMOTE_CLIENT_ADDR, REMOTE_PORT, false);
        let local_port = key.local_port;
        let client_iss = tcp.lookup(key).unwrap().iss;

        let ip_hdr = IpHeader {
            version: 4,
            ihl: 5,
            protocol: 6,
            ttl: 64,
            src_addr: REMOTE_CLIENT_ADDR,
            dst_addr: SERVER_ADDR,
            ..Default::default()
        };

        // Remote completes the handshake (SYN,ACK -> ESTABLISHED).
        let remote_seq = 8000u32;
        let syn_ack = tcp::test_support::build_segment(
            REMOTE_PORT,
            local_port,
            remote_seq,
            client_iss.wrapping_add(1),
            TCP_SYN | TCP_ACK,
            b"",
            REMOTE_CLIENT_ADDR,
            SERVER_ADDR,
        );
        tcp.handle_segment(fd, &ip_hdr, &syn_ack, false);
        assert_eq!(tcp.lookup(key).unwrap().state, tcp::TcpState::Established);

        // Local side closes -> FIN_WAIT_1, then remote ACKs+FINs in one
        // segment -> straight to TIME_WAIT.
        tcp.close(key, fd, false);
        assert_eq!(tcp.lookup(key).unwrap().state, tcp::TcpState::FinWait1);

        let remote_seq = remote_seq + 1;
        let snd_nxt = tcp.lookup(key).unwrap().snd_nxt;
        let fin_ack = tcp::test_support::build_segment(
            REMOTE_PORT,
            local_port,
            remote_seq,
            snd_nxt,
            TCP_FIN | TCP_ACK,
            b"",
            REMOTE_CLIENT_ADDR,
            SERVER_ADDR,
        );
        tcp.handle_segment(fd, &ip_hdr, &fin_ack, false);
        assert_eq!(tcp.lookup(key).unwrap().state, tcp::TcpState::TimeWait);

        // A fresh listen on that exact (addr, port) is blocked by the
        // TIME_WAIT connection unless reuse_addr is set.
        assert!(!tcp.listen(SERVER_ADDR, local_port, false));
        assert!(tcp.listen(SERVER_ADDR, local_port, true));
    }
}
