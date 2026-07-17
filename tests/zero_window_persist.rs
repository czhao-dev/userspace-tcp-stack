//! Verifies the zero-window persist timer (RFC 9293 §3.8.6.1): if the peer
//! advertises a zero receive window while we still have data queued, we
//! must keep probing rather than stalling forever waiting for a
//! window-reopening ACK that might never come (e.g. because it was lost).
//!
//! Only one real `TcpTable` is involved (the client under test); the
//! "server" side is a handful of hand-crafted segments fed straight into
//! `handle_segment()`, since all we need to observe is what the client
//! transmits on its own wire — the same approach `src/tcp.rs`'s own unit
//! tests use, just from outside the crate, so only `pub` items are
//! available (unlike `src/tcp.rs`'s `mod tests`, which can also reach
//! `pub(crate)` items like `test_support::build_segment`).
use std::os::unix::io::RawFd;
use std::thread;
use std::time::{Duration, Instant};

use minitcp::ip::{self, IpHeader, IP_HEADER_LEN};
use minitcp::tcp::{self, TcpHeader, TcpTable, TCP_ACK, TCP_HEADER_LEN, TCP_SYN};

const SERVER_ADDR: u32 = 0x0A0C_0001; // 10.12.0.1
const CLIENT_ADDR: u32 = 0x0A0C_0002; // 10.12.0.2
const SERVER_PORT: u16 = 9393;
const SERVER_ISS: u32 = 9000;

/// A datagram socketpair, matching a real TUN device's one-packet-per-read
/// semantics (see `tests/retransmission.rs` for why this matters over a
/// plain byte-stream pipe).
fn make_nonblocking_pipe() -> (RawFd, RawFd) {
    let mut fds = [0 as RawFd; 2];
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
    assert_eq!(rc, 0, "socketpair failed: {}", std::io::Error::last_os_error());
    unsafe {
        libc::fcntl(fds[0], libc::F_SETFL, libc::O_NONBLOCK);
    }
    (fds[0], fds[1]) // (read_fd, write_fd)
}

fn build_tcp_segment(
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    data: &[u8],
    src_addr: u32,
    dst_addr: u32,
) -> Vec<u8> {
    let hdr = TcpHeader {
        src_port,
        dst_port,
        seq_num: seq,
        ack_num: ack,
        data_offset_reserved: 5 << 4,
        flags,
        window,
        checksum: 0,
        urgent_ptr: 0,
    };
    let mut seg = vec![0u8; TCP_HEADER_LEN + data.len()];
    tcp::build_tcp_header(&hdr, &mut seg);
    if !data.is_empty() {
        seg[TCP_HEADER_LEN..].copy_from_slice(data);
    }
    let csum = tcp::tcp_checksum(src_addr, dst_addr, &seg);
    seg[16..18].copy_from_slice(&csum.to_be_bytes());
    seg
}

fn make_ip_header(src_addr: u32, dst_addr: u32) -> IpHeader {
    IpHeader {
        version: 4,
        ihl: 5,
        protocol: 6,
        ttl: 64,
        src_addr,
        dst_addr,
        ..Default::default()
    }
}

/// Reads and discards every packet currently queued on `fd` (non-blocking),
/// returning the ones successfully read.
fn drain_all(fd: RawFd) -> Vec<Vec<u8>> {
    let mut packets = Vec::new();
    let mut buf = [0u8; 2048];
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= 0 {
            break;
        }
        packets.push(buf[..n as usize].to_vec());
    }
    packets
}

/// Same as `drain_all`, but polls for up to `timeout` before giving up —
/// used for the one packet (the persist probe) that isn't already sitting
/// in the socket buffer when we look.
fn drain_all_with_wait(fd: RawFd, timeout: Duration) -> Vec<Vec<u8>> {
    let deadline = Instant::now() + timeout;
    loop {
        let packets = drain_all(fd);
        if !packets.is_empty() || Instant::now() >= deadline {
            return packets;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn zero_window_triggers_persist_probe() {
    let (client_read, client_write) = make_nonblocking_pipe();
    let tun_fd = client_write;

    let mut client = TcpTable::new();
    let key = client.connect(tun_fd, CLIENT_ADDR, SERVER_ADDR, SERVER_PORT, false);

    // 1. Pull the client's own SYN off the wire to learn its ISS and
    // ephemeral source port (needed to address the fake reply).
    let syn_pkts = drain_all_with_wait(client_read, Duration::from_secs(1));
    assert_eq!(syn_pkts.len(), 1, "expected exactly one SYN");
    let syn_ip = ip::parse_ip_header(&syn_pkts[0]).expect("valid IP header");
    let syn_seg = tcp::parse_tcp_header(&syn_pkts[0][IP_HEADER_LEN..]).expect("valid TCP header");
    assert_eq!(syn_seg.flags, TCP_SYN);
    let client_iss = syn_seg.seq_num;
    let client_port = syn_seg.src_port;
    assert_eq!(syn_ip.dst_addr, SERVER_ADDR);

    // 2. Reply with a SYN,ACK that advertises a *zero* window from the
    // start, so the client has nothing to send into once it tries.
    let synack = build_tcp_segment(
        SERVER_PORT,
        client_port,
        SERVER_ISS,
        client_iss.wrapping_add(1),
        TCP_SYN | TCP_ACK,
        0,
        b"",
        SERVER_ADDR,
        CLIENT_ADDR,
    );
    let server_ip_hdr = make_ip_header(SERVER_ADDR, CLIENT_ADDR);
    client.handle_segment(tun_fd, &server_ip_hdr, &synack, false);
    assert!(client.is_established(key));
    drain_all(client_read); // the handshake's own final ACK, not data

    // 3. Queue data. With snd_wnd == 0, flush_send() can't send any of it
    // and must arm the persist timer instead of silently giving up.
    let accepted = client.send(key, tun_fd, b"hello", false);
    assert_eq!(accepted, 5);

    // Nothing should go out yet — the window is closed.
    let idle_packets = drain_all(client_read);
    assert!(
        idle_packets.is_empty(),
        "no data should be sent while snd_wnd == 0, got {} packet(s)",
        idle_packets.len()
    );

    // 4. Wait past INITIAL_RTO (500ms, with slack) and tick — this is the
    // real-time-based part, matching the style of tests/retransmission.rs.
    thread::sleep(Duration::from_millis(700));
    client.tick(tun_fd, false);

    // 5. The persist probe should have gone out: a 1-byte segment resending
    // the last already-used sequence number (client_iss, the SYN's own
    // seq — since snd_una is client_iss+1 once the handshake completes).
    let probe_pkts = drain_all_with_wait(client_read, Duration::from_secs(1));
    assert!(!probe_pkts.is_empty(), "expected a persist probe after INITIAL_RTO elapsed");

    let (probe, probe_pkt_len) = probe_pkts
        .iter()
        .find_map(|pkt| tcp::parse_tcp_header(&pkt[IP_HEADER_LEN..]).map(|h| (h, pkt.len())))
        .expect("at least one parsable TCP segment");

    assert_eq!(probe.flags, TCP_ACK, "probe should carry only ACK, no PSH/SYN/FIN");
    assert_eq!(probe.seq_num, client_iss, "probe should resend the last already-used sequence number");
    assert_eq!(probe.ack_num, SERVER_ISS.wrapping_add(1));
    assert_eq!(
        probe_pkt_len - IP_HEADER_LEN - TCP_HEADER_LEN,
        1,
        "persist probe should carry exactly 1 byte"
    );

    unsafe {
        libc::close(client_read);
        libc::close(client_write);
    }
}
