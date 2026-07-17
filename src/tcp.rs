use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::os::unix::io::RawFd;
use std::time::{Duration, Instant};

use crate::ip::{self, IpHeader, IP_HEADER_LEN};

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;
pub const TCP_URG: u8 = 0x20;

pub const TCP_HEADER_LEN: usize = 20;

const MSS: usize = 1400;
const INITIAL_RTO: Duration = Duration::from_millis(500);
const MAX_RTO: Duration = Duration::from_millis(8000);
const MAX_RETRIES: u32 = 6;
const TIME_WAIT_DURATION: Duration = Duration::from_secs(4); // shortened 2*MSL for demo purposes

pub const DEFAULT_RECV_BUFFER_CAP: usize = 65536;
pub const DEFAULT_SEND_BUFFER_CAP: usize = 1 << 20;

#[derive(Debug, Clone, Copy, Default)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub data_offset_reserved: u8, // top nibble = data offset, in 32-bit words
    pub flags: u8,
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
}

/// Parses the first 20 bytes of `bytes` into a TcpHeader, converting
/// multi-byte fields to host byte order. Returns None if shorter than 20 bytes.
pub fn parse_tcp_header(bytes: &[u8]) -> Option<TcpHeader> {
    if bytes.len() < TCP_HEADER_LEN {
        return None;
    }
    Some(TcpHeader {
        src_port: u16::from_be_bytes([bytes[0], bytes[1]]),
        dst_port: u16::from_be_bytes([bytes[2], bytes[3]]),
        seq_num: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        ack_num: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        data_offset_reserved: bytes[12],
        flags: bytes[13],
        window: u16::from_be_bytes([bytes[14], bytes[15]]),
        checksum: u16::from_be_bytes([bytes[16], bytes[17]]),
        urgent_ptr: u16::from_be_bytes([bytes[18], bytes[19]]),
    })
}

/// Serializes `hdr` (host byte order) into out[0..19].
pub fn build_tcp_header(hdr: &TcpHeader, out: &mut [u8]) {
    out[0..2].copy_from_slice(&hdr.src_port.to_be_bytes());
    out[2..4].copy_from_slice(&hdr.dst_port.to_be_bytes());
    out[4..8].copy_from_slice(&hdr.seq_num.to_be_bytes());
    out[8..12].copy_from_slice(&hdr.ack_num.to_be_bytes());
    out[12] = hdr.data_offset_reserved;
    out[13] = hdr.flags;
    out[14..16].copy_from_slice(&hdr.window.to_be_bytes());
    out[16..18].copy_from_slice(&hdr.checksum.to_be_bytes());
    out[18..20].copy_from_slice(&hdr.urgent_ptr.to_be_bytes());
}

/// TCP checksum, which (unlike ICMP) covers a 12-byte pseudo-header of
/// (src IP, dst IP, zero, protocol=6, TCP length) in addition to the
/// TCP header + data, per RFC 793.
pub fn tcp_checksum(src_addr: u32, dst_addr: u32, tcp_segment: &[u8]) -> u16 {
    let mut buf = vec![0u8; 12 + tcp_segment.len()];
    buf[0..4].copy_from_slice(&src_addr.to_be_bytes());
    buf[4..8].copy_from_slice(&dst_addr.to_be_bytes());
    buf[8] = 0;
    buf[9] = 6; // protocol = TCP
    buf[10..12].copy_from_slice(&(tcp_segment.len() as u16).to_be_bytes());
    buf[12..].copy_from_slice(tcp_segment);
    ip::checksum16(&buf)
}

/// The eleven TCP connection states from RFC 793 / RFC 9293.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynRcvd,
    Established,
    FinWait1,
    FinWait2,
    Closing,
    TimeWait,
    CloseWait,
    LastAck,
}

impl TcpState {
    pub fn name(&self) -> &'static str {
        match self {
            TcpState::Closed => "CLOSED",
            TcpState::Listen => "LISTEN",
            TcpState::SynSent => "SYN_SENT",
            TcpState::SynRcvd => "SYN_RCVD",
            TcpState::Established => "ESTABLISHED",
            TcpState::FinWait1 => "FIN_WAIT_1",
            TcpState::FinWait2 => "FIN_WAIT_2",
            TcpState::Closing => "CLOSING",
            TcpState::TimeWait => "TIME_WAIT",
            TcpState::CloseWait => "CLOSE_WAIT",
            TcpState::LastAck => "LAST_ACK",
        }
    }
}

/// A TCP connection's identity: its 4-tuple. This is the key into
/// `TcpTable::connections`, the sole owner of connection state — every
/// other reference to a connection (accept queues, the application's
/// `Socket`) stores this `Copy` key, never a shared pointer to the data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionKey {
    pub local_addr: u32,
    pub local_port: u16,
    pub remote_addr: u32,
    pub remote_port: u16,
}

/// A segment we've sent that hasn't been acked yet, kept so it can be
/// retransmitted with exponential backoff if no ACK arrives in time.
struct UnackedSegment {
    seq: u32,
    flags: u8,
    data: Vec<u8>,
    sent_at: Instant,
    rto: Duration,
    retry_count: u32,
}

/// The full per-connection state ("protocol control block" in RFC
/// terms): current state, sequence-number bookkeeping, windows, the
/// retransmission queue, the out-of-order reassembly buffer, and the
/// in-order bytes already delivered to (but not yet read by) the
/// application. Owned exclusively by `TcpTable::connections`.
pub struct TcpConnection {
    pub(crate) state: TcpState,

    pub(crate) local_addr: u32,
    pub(crate) remote_addr: u32,
    pub(crate) local_port: u16,
    pub(crate) remote_port: u16,

    pub(crate) iss: u32,     // initial send sequence number
    pub(crate) snd_una: u32, // oldest unacknowledged sequence number
    pub(crate) snd_nxt: u32, // next sequence number we will send
    pub(crate) snd_wnd: u32, // remote's last-advertised receive window

    pub(crate) irs: u32,     // initial receive sequence number
    pub(crate) rcv_nxt: u32, // next sequence number expected from remote

    retransmit_queue: VecDeque<UnackedSegment>,
    ooo_buffer: BTreeMap<u32, Vec<u8>>, // seq -> payload

    recv_buffer: Vec<u8>,  // in-order data awaiting application read
    send_pending: Vec<u8>, // app data not yet sent (window-limited)

    time_wait_deadline: Instant,

    /// Armed when the peer's advertised window drops to 0 while we still
    /// have unsent data — RFC 9293 §3.8.6.1's persist timer, so a lost
    /// window-reopening ACK doesn't stall the connection forever. Cleared
    /// once `process_ack` sees a nonzero window again.
    probe_deadline: Option<Instant>,
    probe_rto: Duration,

    /// Set by `close()` when it's called while `send_pending` still has
    /// undrained bytes: FIN is deferred (not sent immediately) so queued
    /// app data isn't abandoned. `flush_send()` sends the FIN once
    /// `send_pending` empties out.
    pending_close: bool,

    pub(crate) recv_buffer_cap: usize,
    pub(crate) send_pending_cap: usize,
}

impl TcpConnection {
    fn new() -> Self {
        TcpConnection {
            state: TcpState::Closed,
            local_addr: 0,
            remote_addr: 0,
            local_port: 0,
            remote_port: 0,
            iss: 0,
            snd_una: 0,
            snd_nxt: 0,
            snd_wnd: 65535,
            irs: 0,
            rcv_nxt: 0,
            retransmit_queue: VecDeque::new(),
            ooo_buffer: BTreeMap::new(),
            recv_buffer: Vec::new(),
            send_pending: Vec::new(),
            time_wait_deadline: Instant::now(),
            probe_deadline: None,
            probe_rto: INITIAL_RTO,
            pending_close: false,
            recv_buffer_cap: DEFAULT_RECV_BUFFER_CAP,
            send_pending_cap: DEFAULT_SEND_BUFFER_CAP,
        }
    }
}

fn flags_to_string(flags: u8) -> String {
    let mut parts = Vec::new();
    if flags & TCP_SYN != 0 {
        parts.push("SYN");
    }
    if flags & TCP_ACK != 0 {
        parts.push("ACK");
    }
    if flags & TCP_FIN != 0 {
        parts.push("FIN");
    }
    if flags & TCP_RST != 0 {
        parts.push("RST");
    }
    if flags & TCP_PSH != 0 {
        parts.push("PSH");
    }
    if flags & TCP_URG != 0 {
        parts.push("URG");
    }
    if parts.is_empty() {
        "-".to_string()
    } else {
        parts.join(",")
    }
}

fn generate_iss() -> u32 {
    rand::random()
}

/// Total bytes currently held for this connection's receiver side:
/// in-order data awaiting an application read, plus whatever's sitting in
/// the out-of-order reassembly buffer. Both count against `recv_buffer_cap`
/// / SO_RCVBUF, or the cap doesn't actually bound memory under reordering.
fn buffered_bytes(conn: &TcpConnection) -> usize {
    conn.recv_buffer.len() + conn.ooo_buffer.values().map(|v| v.len()).sum::<usize>()
}

fn advertise_window(conn: &TcpConnection) -> u16 {
    let used = buffered_bytes(conn);
    let cap = conn.recv_buffer_cap;
    if used >= cap {
        return 0;
    }
    (cap - used).min(65535) as u16
}

fn send_segment(conn: &TcpConnection, tun_fd: RawFd, flags: u8, seq: u32, data: &[u8], trace: bool) {
    let hdr = TcpHeader {
        src_port: conn.local_port,
        dst_port: conn.remote_port,
        seq_num: seq,
        ack_num: if flags & TCP_ACK != 0 { conn.rcv_nxt } else { 0 },
        data_offset_reserved: 5 << 4,
        flags,
        window: advertise_window(conn),
        checksum: 0,
        urgent_ptr: 0,
    };

    let mut segment = vec![0u8; TCP_HEADER_LEN + data.len()];
    build_tcp_header(&hdr, &mut segment);
    if !data.is_empty() {
        segment[TCP_HEADER_LEN..].copy_from_slice(data);
    }

    let csum = tcp_checksum(conn.local_addr, conn.remote_addr, &segment);
    segment[16..18].copy_from_slice(&csum.to_be_bytes());

    let iphdr = IpHeader {
        version: 4,
        ihl: 5,
        tos: 0,
        total_length: (IP_HEADER_LEN + segment.len()) as u16,
        identification: 0,
        flags: 0,
        fragment_offset: 0,
        ttl: 64,
        protocol: 6,
        header_checksum: 0,
        src_addr: conn.local_addr,
        dst_addr: conn.remote_addr,
    };

    let mut packet = vec![0u8; IP_HEADER_LEN + segment.len()];
    ip::build_ip_header(&iphdr, &mut packet);
    packet[IP_HEADER_LEN..].copy_from_slice(&segment);
    ip::send_ip_packet(tun_fd, &packet);

    if trace {
        println!(
            "[TCP ] send  {:<11} seq={} ack={} win={} len={}",
            flags_to_string(flags),
            seq,
            hdr.ack_num,
            hdr.window,
            data.len()
        );
    }
}

fn queue_and_send(conn: &mut TcpConnection, tun_fd: RawFd, flags: u8, data: &[u8], trace: bool) {
    let seq = conn.snd_nxt;
    send_segment(conn, tun_fd, flags, seq, data, trace);

    conn.retransmit_queue.push_back(UnackedSegment {
        seq,
        flags,
        data: data.to_vec(),
        sent_at: Instant::now(),
        rto: INITIAL_RTO,
        retry_count: 0,
    });

    let mut consumed = data.len() as u32;
    if flags & TCP_SYN != 0 {
        consumed = consumed.wrapping_add(1);
    }
    if flags & TCP_FIN != 0 {
        consumed = consumed.wrapping_add(1);
    }
    conn.snd_nxt = conn.snd_nxt.wrapping_add(consumed);
}

fn send_ack_only(conn: &TcpConnection, tun_fd: RawFd, trace: bool) {
    send_segment(conn, tun_fd, TCP_ACK, conn.snd_nxt, &[], trace);
}

fn remove_acked(conn: &mut TcpConnection, new_una: u32) {
    while let Some(front) = conn.retransmit_queue.front() {
        let mut end = front.seq.wrapping_add(front.data.len() as u32);
        if front.flags & TCP_SYN != 0 {
            end = end.wrapping_add(1);
        }
        if front.flags & TCP_FIN != 0 {
            end = end.wrapping_add(1);
        }
        // Not wraparound-safe (matches the original's documented limitation).
        if end <= new_una {
            conn.retransmit_queue.pop_front();
        } else {
            break;
        }
    }
}

fn process_ack(conn: &mut TcpConnection, seg: &TcpHeader) {
    if seg.flags & TCP_ACK == 0 {
        return;
    }
    if seg.ack_num > conn.snd_una {
        conn.snd_una = seg.ack_num;
        remove_acked(conn, conn.snd_una);
    }
    conn.snd_wnd = seg.window as u32;
    if conn.snd_wnd != 0 {
        conn.probe_deadline = None;
        conn.probe_rto = INITIAL_RTO;
    }
}

fn flush_send(conn: &mut TcpConnection, tun_fd: RawFd, trace: bool) {
    if conn.state != TcpState::Established && conn.state != TcpState::CloseWait {
        return;
    }
    if conn.snd_wnd == 0 && !conn.send_pending.is_empty() {
        // Peer's window is closed and we still have data queued: arm the
        // persist timer (RFC 9293 §3.8.6.1) so we don't stall forever if
        // the window-reopening ACK gets lost. tick() sends the probes.
        conn.probe_deadline.get_or_insert(Instant::now() + INITIAL_RTO);
    }
    while !conn.send_pending.is_empty() {
        let bytes_in_flight = conn.snd_nxt.wrapping_sub(conn.snd_una);
        if bytes_in_flight >= conn.snd_wnd {
            break;
        }
        let available = (conn.snd_wnd - bytes_in_flight) as usize;
        let chunk_len = MSS.min(available).min(conn.send_pending.len());
        if chunk_len == 0 {
            break;
        }
        let chunk: Vec<u8> = conn.send_pending[..chunk_len].to_vec();
        queue_and_send(conn, tun_fd, TCP_ACK | TCP_PSH, &chunk, trace);
        conn.send_pending.drain(..chunk_len);
    }

    // close() may have deferred the FIN because send_pending wasn't empty
    // yet. Now that we've drained as much as the window allows, send it if
    // the backlog is actually gone.
    if conn.pending_close && conn.send_pending.is_empty() {
        match conn.state {
            TcpState::Established => {
                queue_and_send(conn, tun_fd, TCP_FIN | TCP_ACK, &[], trace);
                conn.state = TcpState::FinWait1;
            }
            TcpState::CloseWait => {
                queue_and_send(conn, tun_fd, TCP_FIN | TCP_ACK, &[], trace);
                conn.state = TcpState::LastAck;
            }
            _ => {}
        }
        conn.pending_close = false;
    }
}

/// Handles in-order/out-of-order data delivery and FIN consumption for
/// any state where the remote may still be sending data (ESTABLISHED,
/// FIN_WAIT_1, FIN_WAIT_2). Sends an ACK if anything was new. Returns
/// true if the remote's FIN was just consumed in sequence.
fn receive_data_and_maybe_fin(
    conn: &mut TcpConnection,
    tun_fd: RawFd,
    seg: &TcpHeader,
    payload: &[u8],
    trace: bool,
) -> bool {
    let mut fin_consumed = false;
    let has_fin = seg.flags & TCP_FIN != 0;
    let mut should_ack = false;

    if seg.seq_num == conn.rcv_nxt {
        if !payload.is_empty() {
            conn.recv_buffer.extend_from_slice(payload);
            conn.rcv_nxt = conn.rcv_nxt.wrapping_add(payload.len() as u32);
            should_ack = true;
        }
        // Splice in any out-of-order segments that are now contiguous.
        while let Some(data) = conn.ooo_buffer.remove(&conn.rcv_nxt) {
            conn.rcv_nxt = conn.rcv_nxt.wrapping_add(data.len() as u32);
            conn.recv_buffer.extend_from_slice(&data);
            should_ack = true;
        }
        if has_fin {
            conn.rcv_nxt = conn.rcv_nxt.wrapping_add(1);
            fin_consumed = true;
            should_ack = true;
        }
    } else if seg.seq_num > conn.rcv_nxt {
        // Out of order: buffer any data and send a duplicate ACK
        // advertising the byte we're actually still waiting for. Dropped
        // (not buffered) if it would push us past recv_buffer_cap — mirrors
        // UdpTable::deliver()'s cap check — the sender's own retransmit
        // timer will retry once recv() drains room.
        if !payload.is_empty() && buffered_bytes(conn) + payload.len() <= conn.recv_buffer_cap {
            conn.ooo_buffer.insert(seg.seq_num, payload.to_vec());
        }
        should_ack = true;
    } else {
        // seg.seq_num < rcv_nxt: old retransmitted data we already have.
        should_ack = !payload.is_empty() || has_fin;
    }

    if should_ack {
        send_ack_only(conn, tun_fd, trace);
    }
    fin_consumed
}

fn send_rst_for_unknown(tun_fd: RawFd, ip_hdr: &IpHeader, seg: &TcpHeader, data_len: usize, trace: bool) {
    let incoming_ack = seg.flags & TCP_ACK != 0;
    let (seq_num, flags, ack_num) = if incoming_ack {
        (seg.ack_num, TCP_RST, 0)
    } else {
        let mut consumed = data_len as u32;
        if seg.flags & TCP_SYN != 0 {
            consumed = consumed.wrapping_add(1);
        }
        if seg.flags & TCP_FIN != 0 {
            consumed = consumed.wrapping_add(1);
        }
        (0, TCP_RST | TCP_ACK, seg.seq_num.wrapping_add(consumed))
    };

    let rst = TcpHeader {
        src_port: seg.dst_port,
        dst_port: seg.src_port,
        seq_num,
        ack_num,
        data_offset_reserved: 5 << 4,
        flags,
        window: 0,
        checksum: 0,
        urgent_ptr: 0,
    };

    let mut segment = vec![0u8; TCP_HEADER_LEN];
    build_tcp_header(&rst, &mut segment);
    let csum = tcp_checksum(ip_hdr.dst_addr, ip_hdr.src_addr, &segment);
    segment[16..18].copy_from_slice(&csum.to_be_bytes());

    let iphdr = IpHeader {
        version: 4,
        ihl: 5,
        tos: 0,
        total_length: (IP_HEADER_LEN + segment.len()) as u16,
        identification: 0,
        flags: 0,
        fragment_offset: 0,
        ttl: 64,
        protocol: 6,
        header_checksum: 0,
        src_addr: ip_hdr.dst_addr,
        dst_addr: ip_hdr.src_addr,
    };

    let mut packet = vec![0u8; IP_HEADER_LEN + segment.len()];
    ip::build_ip_header(&iphdr, &mut packet);
    packet[IP_HEADER_LEN..].copy_from_slice(&segment);
    ip::send_ip_packet(tun_fd, &packet);

    if trace {
        println!("[TCP ] send  RST,ACK    -> port {} unreachable", seg.dst_port);
    }
}

/// The connection table: sole owner of every `TcpConnection`, plus the
/// listener set and per-listener accept queues (which reference
/// connections only by `ConnectionKey`, never by shared pointer).
#[derive(Default)]
pub struct TcpTable {
    connections: HashMap<ConnectionKey, TcpConnection>,
    listeners: HashSet<(u32, u16)>,
    accept_queues: HashMap<(u32, u16), VecDeque<ConnectionKey>>,
    next_ephemeral_port: u16,
}

impl TcpTable {
    pub fn new() -> Self {
        TcpTable {
            next_ephemeral_port: 49152,
            ..Default::default()
        }
    }

    /// Entry point analogous to `icmp::handle_icmp`/`UdpTable::handle_datagram`:
    /// demuxes the segment to an existing connection or a listening
    /// port, and advances that connection's state machine by one step.
    /// Public (not just crate-internal) because tests drive it
    /// directly over a simulated "wire", bypassing `Stack` entirely —
    /// mirroring the original's `handle_tcp()`, which was always a
    /// public function for exactly this reason.
    pub fn handle_segment(&mut self, tun_fd: RawFd, ip_hdr: &IpHeader, payload: &[u8], trace: bool) {
        if payload.len() < TCP_HEADER_LEN {
            return;
        }
        let Some(seg) = parse_tcp_header(payload) else {
            return;
        };

        let csum = tcp_checksum(ip_hdr.src_addr, ip_hdr.dst_addr, payload);
        if csum != 0 {
            if trace {
                println!("[TCP ] recv  bad checksum, dropping segment");
            }
            return;
        }

        let data = &payload[TCP_HEADER_LEN..];

        let key = ConnectionKey {
            local_addr: ip_hdr.dst_addr,
            local_port: seg.dst_port,
            remote_addr: ip_hdr.src_addr,
            remote_port: seg.src_port,
        };

        if self.connections.contains_key(&key) {
            self.process_segment(key, tun_fd, &seg, data, trace);
            self.cleanup_closed_connections();
            return;
        }

        let listen_key = (ip_hdr.dst_addr, seg.dst_port);
        if (seg.flags & TCP_SYN != 0) && (seg.flags & TCP_ACK == 0) && self.listeners.contains(&listen_key) {
            let mut conn = TcpConnection::new();
            conn.local_addr = ip_hdr.dst_addr;
            conn.local_port = seg.dst_port;
            conn.remote_addr = ip_hdr.src_addr;
            conn.remote_port = seg.src_port;
            conn.irs = seg.seq_num;
            conn.rcv_nxt = seg.seq_num.wrapping_add(1);
            conn.iss = generate_iss();
            conn.snd_una = conn.iss;
            conn.snd_nxt = conn.iss;
            conn.snd_wnd = seg.window as u32;
            conn.state = TcpState::SynRcvd;

            if trace {
                println!(
                    "[TCP ] recv  {:<11} seq={} ack={} win={} len={}  state=LISTEN",
                    flags_to_string(seg.flags),
                    seg.seq_num,
                    seg.ack_num,
                    seg.window,
                    data.len()
                );
                println!("[TCP ] state LISTEN -> SYN_RCVD");
            }

            self.connections.insert(key, conn);
            let conn = self.connections.get_mut(&key).unwrap();
            queue_and_send(conn, tun_fd, TCP_SYN | TCP_ACK, &[], trace);
            return;
        }

        if seg.flags & TCP_RST == 0 {
            send_rst_for_unknown(tun_fd, ip_hdr, &seg, data.len(), trace);
        }
    }

    fn process_segment(&mut self, key: ConnectionKey, tun_fd: RawFd, seg: &TcpHeader, payload: &[u8], trace: bool) {
        // Split-borrow: `connections` and `accept_queues` are disjoint
        // fields, so this destructure lets us hold a `&mut TcpConnection`
        // from one while still reaching the other (needed by the
        // SYN_RCVD arm's enqueue-on-accept below).
        let TcpTable {
            connections,
            accept_queues,
            ..
        } = self;
        let conn = connections.get_mut(&key).expect("connection must exist");

        if trace {
            println!(
                "[TCP ] recv  {:<11} seq={} ack={} win={} len={}  state={}",
                flags_to_string(seg.flags),
                seg.seq_num,
                seg.ack_num,
                seg.window,
                payload.len(),
                conn.state.name()
            );
        }

        let old_state = conn.state;

        // Uniform RST handling (RFC 9293 §3.10.7, general case): a RST in
        // any live state aborts the connection to CLOSED. Hoisted above the
        // per-state match so every post-handshake state gets this for free,
        // not just SYN_SENT/SYN_RCVD (which used to check it individually).
        // No sequence/ACK-number validation is added here — this preserves
        // the same unconditional acceptance the old SYN_SENT/SYN_RCVD checks
        // already had, just applied uniformly.
        if seg.flags & TCP_RST != 0 && !matches!(conn.state, TcpState::Closed | TcpState::Listen) {
            conn.state = TcpState::Closed;
        } else {
            match conn.state {
                TcpState::SynSent => {
                    if (seg.flags & TCP_SYN != 0) && (seg.flags & TCP_ACK != 0) && seg.ack_num == conn.snd_nxt {
                        conn.irs = seg.seq_num;
                        conn.rcv_nxt = seg.seq_num.wrapping_add(1);
                        conn.snd_una = seg.ack_num;
                        conn.snd_wnd = seg.window as u32;
                        remove_acked(conn, conn.snd_una);
                        conn.state = TcpState::Established;
                        send_ack_only(conn, tun_fd, trace);
                    }
                }
                TcpState::SynRcvd => {
                    if (seg.flags & TCP_ACK != 0) && seg.ack_num == conn.snd_nxt {
                        conn.snd_una = seg.ack_num;
                        remove_acked(conn, conn.snd_una);
                        conn.snd_wnd = seg.window as u32;
                        conn.state = TcpState::Established;
                        accept_queues
                            .entry((conn.local_addr, conn.local_port))
                            .or_default()
                            .push_back(key);
                        if !payload.is_empty() || (seg.flags & TCP_FIN != 0) {
                            let fin = receive_data_and_maybe_fin(conn, tun_fd, seg, payload, trace);
                            if fin {
                                conn.state = TcpState::CloseWait;
                            }
                        }
                    }
                }
                TcpState::Established => {
                    process_ack(conn, seg);
                    let fin = receive_data_and_maybe_fin(conn, tun_fd, seg, payload, trace);
                    if fin {
                        conn.state = TcpState::CloseWait;
                    }
                    flush_send(conn, tun_fd, trace);
                }
                TcpState::FinWait1 => {
                    process_ack(conn, seg);
                    let our_fin_acked = (seg.flags & TCP_ACK != 0) && seg.ack_num == conn.snd_nxt;
                    let fin = receive_data_and_maybe_fin(conn, tun_fd, seg, payload, trace);
                    if our_fin_acked && fin {
                        conn.state = TcpState::TimeWait;
                        conn.time_wait_deadline = Instant::now() + TIME_WAIT_DURATION;
                    } else if our_fin_acked {
                        conn.state = TcpState::FinWait2;
                    } else if fin {
                        conn.state = TcpState::Closing;
                    }
                }
                TcpState::FinWait2 => {
                    process_ack(conn, seg);
                    let fin = receive_data_and_maybe_fin(conn, tun_fd, seg, payload, trace);
                    if fin {
                        conn.state = TcpState::TimeWait;
                        conn.time_wait_deadline = Instant::now() + TIME_WAIT_DURATION;
                    }
                }
                TcpState::Closing => {
                    process_ack(conn, seg);
                    if (seg.flags & TCP_ACK != 0) && seg.ack_num == conn.snd_nxt {
                        conn.state = TcpState::TimeWait;
                        conn.time_wait_deadline = Instant::now() + TIME_WAIT_DURATION;
                    }
                }
                TcpState::CloseWait => {
                    process_ack(conn, seg);
                    flush_send(conn, tun_fd, trace);
                }
                TcpState::LastAck => {
                    process_ack(conn, seg);
                    if (seg.flags & TCP_ACK != 0) && seg.ack_num == conn.snd_nxt {
                        conn.state = TcpState::Closed;
                    }
                }
                TcpState::TimeWait => {
                    // The whole point of TIME_WAIT: if our final ACK was
                    // lost, the remote retransmits its FIN. Re-ACK it (and
                    // restart the timer) instead of silently ignoring it,
                    // or the remote will retransmit until it gives up.
                    if seg.flags & TCP_FIN != 0 {
                        send_ack_only(conn, tun_fd, trace);
                        conn.time_wait_deadline = Instant::now() + TIME_WAIT_DURATION;
                    }
                }
                TcpState::Closed | TcpState::Listen => {}
            }
        }

        if trace && conn.state != old_state {
            println!("[TCP ] state {} -> {}", old_state.name(), conn.state.name());
        }
    }

    /// Called periodically (independent of incoming packets) to check
    /// retransmission timers and TIME_WAIT expiry across all tracked
    /// connections.
    pub fn tick(&mut self, tun_fd: RawFd, trace: bool) {
        let now = Instant::now();

        for conn in self.connections.values_mut() {
            if conn.state == TcpState::TimeWait {
                if now >= conn.time_wait_deadline {
                    conn.state = TcpState::Closed;
                    if trace {
                        println!("[TCP ] state TIME_WAIT -> CLOSED");
                    }
                }
                continue;
            }

            let old_state = conn.state;

            if matches!(conn.state, TcpState::Established | TcpState::CloseWait) {
                if let Some(deadline) = conn.probe_deadline {
                    if now >= deadline {
                        // Zero-window persist probe (RFC 9293 §3.8.6.1): resend
                        // one already-used byte to force a fresh ACK/window
                        // update out of the peer. Not queue_and_send() — this
                        // must not consume new sequence space or enter the
                        // data-retransmit queue, and has no MAX_RETRIES-style
                        // give-up; it backs off until the window reopens.
                        let probe_seq = conn.snd_una.wrapping_sub(1);
                        if trace {
                            println!(
                                "[TCP ] persist probe seq={probe_seq} (rto={}ms)",
                                conn.probe_rto.as_millis()
                            );
                        }
                        send_segment(conn, tun_fd, TCP_ACK, probe_seq, &[0u8], trace);
                        conn.probe_rto = (conn.probe_rto * 2).min(MAX_RTO);
                        conn.probe_deadline = Some(now + conn.probe_rto);
                    }
                }
            } else {
                conn.probe_deadline = None; // left Established/CloseWait; stop persisting
            }

            if let Some(front) = conn.retransmit_queue.front() {
                if now.duration_since(front.sent_at) >= front.rto {
                    if front.retry_count >= MAX_RETRIES {
                        if trace {
                            println!(
                                "[TCP ] giving up after {} retries, dropping connection",
                                front.retry_count
                            );
                        }
                        conn.state = TcpState::Closed;
                        continue;
                    }

                    let (seq, flags, data, mut rto, retry_count) = {
                        let f = conn.retransmit_queue.front().unwrap();
                        (f.seq, f.flags, f.data.clone(), f.rto, f.retry_count)
                    };
                    if trace {
                        println!(
                            "[TCP ] retransmit seq={seq} (attempt {}, rto={}ms)",
                            retry_count + 1,
                            rto.as_millis()
                        );
                    }
                    send_segment(conn, tun_fd, flags, seq, &data, trace);
                    rto = (rto * 2).min(MAX_RTO);
                    let front = conn.retransmit_queue.front_mut().unwrap();
                    front.sent_at = now;
                    front.rto = rto;
                    front.retry_count += 1;
                }
            }

            flush_send(conn, tun_fd, trace);

            if trace && conn.state != old_state {
                println!("[TCP ] state {} -> {}", old_state.name(), conn.state.name());
            }
        }

        self.cleanup_closed_connections();
    }

    fn cleanup_closed_connections(&mut self) {
        self.connections.retain(|_, c| c.state != TcpState::Closed);
    }

    /// True if a new `listen()` on (addr, port) should be refused. A
    /// port already in LISTEN is *not* a conflict (re-listening is a
    /// no-op success) — only a live connection occupying that exact
    /// local (addr, port) blocks a fresh listen, and a TIME_WAIT one
    /// only blocks it when `reuse_addr` is false.
    fn address_in_use(&self, addr: u32, port: u16, reuse_addr: bool) -> bool {
        if self.listeners.contains(&(addr, port)) {
            return false;
        }
        for c in self.connections.values() {
            if c.local_addr != addr || c.local_port != port {
                continue;
            }
            if c.state == TcpState::Closed {
                continue;
            }
            if c.state == TcpState::TimeWait && reuse_addr {
                continue;
            }
            return true;
        }
        false
    }

    /// Marks (local_addr, local_port) as listening; completed
    /// connections arriving on it become available via `accept()`.
    pub fn listen(&mut self, local_addr: u32, local_port: u16, reuse_addr: bool) -> bool {
        if self.address_in_use(local_addr, local_port, reuse_addr) {
            return false;
        }
        self.listeners.insert((local_addr, local_port));
        true
    }

    /// Pops one ESTABLISHED, not-yet-accepted connection for the given
    /// listening (local_addr, local_port), or None if none is ready.
    pub fn accept(&mut self, local_addr: u32, local_port: u16) -> Option<ConnectionKey> {
        self.accept_queues.get_mut(&(local_addr, local_port))?.pop_front()
    }

    fn allocate_ephemeral_port(&mut self) -> u16 {
        let p = self.next_ephemeral_port;
        self.next_ephemeral_port = self.next_ephemeral_port.wrapping_add(1);
        p
    }

    /// Active open: allocates an ephemeral local port, sends SYN, and
    /// registers the new connection (in SYN_SENT).
    pub fn connect(&mut self, tun_fd: RawFd, local_addr: u32, remote_addr: u32, remote_port: u16, trace: bool) -> ConnectionKey {
        let local_port = self.allocate_ephemeral_port();
        let mut conn = TcpConnection::new();
        conn.local_addr = local_addr;
        conn.local_port = local_port;
        conn.remote_addr = remote_addr;
        conn.remote_port = remote_port;
        conn.iss = generate_iss();
        conn.snd_una = conn.iss;
        conn.snd_nxt = conn.iss;
        conn.state = TcpState::SynSent;

        let key = ConnectionKey {
            local_addr,
            local_port,
            remote_addr,
            remote_port,
        };

        if trace {
            println!("[TCP ] state CLOSED -> SYN_SENT (connecting to port {remote_port})");
        }

        self.connections.insert(key, conn);
        let conn = self.connections.get_mut(&key).unwrap();
        queue_and_send(conn, tun_fd, TCP_SYN, &[], trace);
        key
    }

    /// Queues `data` for transmission (segmented to a fixed MSS) and
    /// sends what the current window allows immediately. Returns the
    /// number of bytes accepted (0 if the connection is gone).
    pub fn send(&mut self, key: ConnectionKey, tun_fd: RawFd, data: &[u8], trace: bool) -> usize {
        let Some(conn) = self.connections.get_mut(&key) else {
            return 0;
        };
        let room = conn.send_pending_cap.saturating_sub(conn.send_pending.len());
        let accepted = data.len().min(room);
        conn.send_pending.extend_from_slice(&data[..accepted]);
        flush_send(conn, tun_fd, trace);
        accepted
    }

    /// Copies up to `buf.len()` bytes of already-delivered, in-order
    /// data into `buf` and removes them from the connection's receive
    /// buffer. Returns the number of bytes copied (0 if none available,
    /// including when the connection no longer exists).
    pub fn recv(&mut self, key: ConnectionKey, buf: &mut [u8]) -> usize {
        let Some(conn) = self.connections.get_mut(&key) else {
            return 0;
        };
        let n = buf.len().min(conn.recv_buffer.len());
        if n > 0 {
            buf[..n].copy_from_slice(&conn.recv_buffer[..n]);
            conn.recv_buffer.drain(..n);
        }
        n
    }

    /// Initiates graceful close: sends FIN once any data still queued in
    /// `send_pending` has actually been transmitted, rather than abandoning
    /// it. If nothing is queued, the FIN goes out immediately (same as
    /// before).
    pub fn close(&mut self, key: ConnectionKey, tun_fd: RawFd, trace: bool) {
        let Some(conn) = self.connections.get_mut(&key) else {
            return;
        };
        let old_state = conn.state;
        match conn.state {
            TcpState::Established | TcpState::CloseWait => {
                conn.pending_close = true;
                flush_send(conn, tun_fd, trace);
            }
            TcpState::SynSent | TcpState::Listen => {
                conn.state = TcpState::Closed;
            }
            _ => {}
        }
        if trace && conn.state != old_state {
            println!("[TCP ] state {} -> {}", old_state.name(), conn.state.name());
        }
    }

    pub(crate) fn set_recv_cap(&mut self, key: ConnectionKey, cap: usize) {
        if let Some(c) = self.connections.get_mut(&key) {
            c.recv_buffer_cap = cap;
        }
    }

    pub(crate) fn set_send_cap(&mut self, key: ConnectionKey, cap: usize) {
        if let Some(c) = self.connections.get_mut(&key) {
            c.send_pending_cap = cap;
        }
    }

    pub fn is_established(&self, key: ConnectionKey) -> bool {
        self.connections.get(&key).is_some_and(|c| c.state == TcpState::Established)
    }

    /// True if the connection is gone (fully torn down and reaped) or
    /// explicitly CLOSED — mirrors the original's "null shared_ptr or
    /// CLOSED state" check.
    pub fn is_closed(&self, key: ConnectionKey) -> bool {
        self.connections
            .get(&key)
            .is_none_or(|c| c.state == TcpState::Closed)
    }

    /// Looks up a connection by its 4-tuple without consuming it from
    /// any accept queue. Exists for tests that need to inspect/drive
    /// TCP internals directly — application code should use the
    /// `Stack` socket API instead, never this.
    pub(crate) fn lookup(&self, key: ConnectionKey) -> Option<&TcpConnection> {
        self.connections.get(&key)
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    pub(crate) fn build_segment(
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
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
            window: 65535,
            checksum: 0,
            urgent_ptr: 0,
        };
        let mut seg = vec![0u8; TCP_HEADER_LEN + data.len()];
        build_tcp_header(&hdr, &mut seg);
        if !data.is_empty() {
            seg[TCP_HEADER_LEN..].copy_from_slice(data);
        }
        let csum = tcp_checksum(src_addr, dst_addr, &seg);
        seg[16..18].copy_from_slice(&csum.to_be_bytes());
        seg
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::build_segment;
    use super::*;
    use std::os::fd::AsRawFd;

    const SERVER_ADDR: u32 = 0x0A0A_0001; // 10.10.0.1
    const CLIENT_ADDR: u32 = 0x0A0A_0002; // 10.10.0.2
    const SERVER_PORT: u16 = 9292;
    const CLIENT_PORT: u16 = 41000;

    fn dev_null_fd() -> RawFd {
        std::fs::File::create("/dev/null").unwrap().as_raw_fd()
    }

    #[test]
    fn full_lifecycle_handshake_ooo_and_close() {
        let fd = dev_null_fd();
        let mut table = TcpTable::new();
        assert!(table.listen(SERVER_ADDR, SERVER_PORT, false));

        let ip_hdr = IpHeader {
            version: 4,
            ihl: 5,
            src_addr: CLIENT_ADDR,
            dst_addr: SERVER_ADDR,
            protocol: 6,
            ttl: 64,
            ..Default::default()
        };

        // 1. SYN -> server should create a SYN_RCVD connection.
        let mut client_seq = 1000u32;
        let syn = build_segment(CLIENT_PORT, SERVER_PORT, client_seq, 0, TCP_SYN, b"", CLIENT_ADDR, SERVER_ADDR);
        table.handle_segment(fd, &ip_hdr, &syn, false);

        let key = ConnectionKey {
            local_addr: SERVER_ADDR,
            local_port: SERVER_PORT,
            remote_addr: CLIENT_ADDR,
            remote_port: CLIENT_PORT,
        };
        assert_eq!(table.lookup(key).unwrap().state, TcpState::SynRcvd);
        let server_iss = table.lookup(key).unwrap().iss;

        // 2. Final ACK of the handshake -> ESTABLISHED.
        client_seq += 1;
        let ack = build_segment(
            CLIENT_PORT,
            SERVER_PORT,
            client_seq,
            server_iss.wrapping_add(1),
            TCP_ACK,
            b"",
            CLIENT_ADDR,
            SERVER_ADDR,
        );
        table.handle_segment(fd, &ip_hdr, &ack, false);
        assert_eq!(table.lookup(key).unwrap().state, TcpState::Established);

        let accepted = table.accept(SERVER_ADDR, SERVER_PORT).unwrap();
        assert_eq!(accepted, key);

        // 3. Three 5-byte data segments, delivered OUT OF ORDER: C, A, B.
        let seg_a = build_segment(
            CLIENT_PORT,
            SERVER_PORT,
            client_seq,
            server_iss.wrapping_add(1),
            TCP_ACK | TCP_PSH,
            b"AAAAA",
            CLIENT_ADDR,
            SERVER_ADDR,
        );
        let seg_b = build_segment(
            CLIENT_PORT,
            SERVER_PORT,
            client_seq + 5,
            server_iss.wrapping_add(1),
            TCP_ACK | TCP_PSH,
            b"BBBBB",
            CLIENT_ADDR,
            SERVER_ADDR,
        );
        let seg_c = build_segment(
            CLIENT_PORT,
            SERVER_PORT,
            client_seq + 10,
            server_iss.wrapping_add(1),
            TCP_ACK | TCP_PSH,
            b"CCCCC",
            CLIENT_ADDR,
            SERVER_ADDR,
        );

        table.handle_segment(fd, &ip_hdr, &seg_c, false); // arrives first, buffered
        table.handle_segment(fd, &ip_hdr, &seg_a, false); // in-order, but gap remains
        table.handle_segment(fd, &ip_hdr, &seg_b, false); // fills gap: A,B,C splice in

        let mut buf = [0u8; 64];
        let n = table.recv(accepted, &mut buf);
        assert_eq!(&buf[..n], b"AAAAABBBBBCCCCC");

        // 4. Remote FIN -> CLOSE_WAIT, local close() -> LAST_ACK -> CLOSED.
        let client_seq_after_data = client_seq + 15;
        let fin = build_segment(
            CLIENT_PORT,
            SERVER_PORT,
            client_seq_after_data,
            server_iss.wrapping_add(1),
            TCP_FIN | TCP_ACK,
            b"",
            CLIENT_ADDR,
            SERVER_ADDR,
        );
        table.handle_segment(fd, &ip_hdr, &fin, false);
        assert_eq!(table.lookup(accepted).unwrap().state, TcpState::CloseWait);

        table.close(accepted, fd, false);
        assert_eq!(table.lookup(accepted).unwrap().state, TcpState::LastAck);

        let snd_nxt = table.lookup(accepted).unwrap().snd_nxt;
        let final_ack = build_segment(
            CLIENT_PORT,
            SERVER_PORT,
            client_seq_after_data + 1,
            snd_nxt,
            TCP_ACK,
            b"",
            CLIENT_ADDR,
            SERVER_ADDR,
        );
        table.handle_segment(fd, &ip_hdr, &final_ack, false);
        assert!(table.is_closed(accepted));
    }
}
