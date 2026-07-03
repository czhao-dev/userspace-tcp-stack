use std::net::Ipv4Addr;
use std::os::unix::io::RawFd;

use crate::ip::{self, IpHeader, IP_HEADER_LEN};

pub const ICMP_ECHO_REQUEST: u8 = 8;
pub const ICMP_ECHO_REPLY: u8 = 0;
pub const ICMP_HEADER_LEN: usize = 8;

/// Handles one received ICMP message contained in `payload` (the IP
/// payload), where `ip_hdr` is the already-parsed IP header of the
/// packet that carried it. If it's an Echo Request, builds and sends
/// an Echo Reply (same id/seq/payload, swapped src/dst) out through
/// `tun_fd`. No-op for other ICMP types.
pub fn handle_icmp(tun_fd: RawFd, ip_hdr: &IpHeader, payload: &[u8], trace: bool) {
    if payload.len() < ICMP_HEADER_LEN {
        return;
    }

    let icmp_type = payload[0];
    let code = payload[1];
    let identifier = u16::from_be_bytes([payload[4], payload[5]]);
    let sequence = u16::from_be_bytes([payload[6], payload[7]]);

    if trace {
        println!("[ICMP] recv  type={icmp_type} code={code} id={identifier} seq={sequence}");
    }

    if icmp_type != ICMP_ECHO_REQUEST {
        return;
    }

    // Build the Echo Reply: same identifier/sequence/payload as the
    // request, type changed to 0, checksum recomputed.
    let icmp_total_len = payload.len();
    let mut icmp_buf = vec![0u8; icmp_total_len];
    icmp_buf[0] = ICMP_ECHO_REPLY;
    icmp_buf[1] = 0;
    // icmp_buf[2..4] left as the checksum placeholder (zero) for now.
    icmp_buf[4..6].copy_from_slice(&payload[4..6]); // identifier
    icmp_buf[6..8].copy_from_slice(&payload[6..8]); // sequence
    if icmp_total_len > ICMP_HEADER_LEN {
        icmp_buf[ICMP_HEADER_LEN..].copy_from_slice(&payload[ICMP_HEADER_LEN..]);
    }

    // ICMP checksum covers the ICMP header + data only, no pseudo-header.
    let csum = ip::checksum16(&icmp_buf);
    icmp_buf[2..4].copy_from_slice(&csum.to_be_bytes());

    let mut reply_hdr = *ip_hdr;
    reply_hdr.src_addr = ip_hdr.dst_addr;
    reply_hdr.dst_addr = ip_hdr.src_addr;
    reply_hdr.protocol = 1;
    reply_hdr.ttl = 64;
    reply_hdr.ihl = 5;
    reply_hdr.total_length = (IP_HEADER_LEN + icmp_total_len) as u16;
    reply_hdr.flags = 0;
    reply_hdr.fragment_offset = 0;

    let mut packet = vec![0u8; IP_HEADER_LEN + icmp_total_len];
    ip::build_ip_header(&reply_hdr, &mut packet);
    packet[IP_HEADER_LEN..].copy_from_slice(&icmp_buf);

    ip::send_ip_packet(tun_fd, &packet);

    if trace {
        let dst = Ipv4Addr::from(reply_hdr.dst_addr);
        println!("[ICMP] send  type={ICMP_ECHO_REPLY} code=0 id={identifier} seq={sequence}  -> {dst}");
    }
}
