use std::os::unix::io::RawFd;

use crate::tun;

/// In-memory representation of an IPv4 header, always in HOST byte
/// order; conversion to/from network byte order happens only at the
/// parse_ip_header/build_ip_header boundary. No support for IP options
/// (assumes a 20-byte header, IHL == 5).
#[derive(Debug, Clone, Copy, Default)]
pub struct IpHeader {
    pub version: u8,
    pub ihl: u8,
    pub tos: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u16,           // top 3 bits of the flags/fragment-offset field
    pub fragment_offset: u16, // low 13 bits of the flags/fragment-offset field
    pub ttl: u8,
    pub protocol: u8, // 1 = ICMP, 6 = TCP, 17 = UDP
    pub header_checksum: u16,
    pub src_addr: u32,
    pub dst_addr: u32,
}

pub const IP_HEADER_LEN: usize = 20;

/// Parses the first 20 bytes of `bytes` into an IpHeader, converting
/// multi-byte fields to host byte order. Does NOT validate the
/// checksum (use verify_ip_checksum for that). Returns None if `bytes`
/// is shorter than 20 bytes or the version field isn't 4.
pub fn parse_ip_header(bytes: &[u8]) -> Option<IpHeader> {
    if bytes.len() < IP_HEADER_LEN {
        return None;
    }

    let version = bytes[0] >> 4;
    if version != 4 {
        return None;
    }

    let total_length = u16::from_be_bytes([bytes[2], bytes[3]]);
    let identification = u16::from_be_bytes([bytes[4], bytes[5]]);
    let flags_frag = u16::from_be_bytes([bytes[6], bytes[7]]);
    let header_checksum = u16::from_be_bytes([bytes[10], bytes[11]]);
    let src_addr = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    let dst_addr = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);

    Some(IpHeader {
        version,
        ihl: bytes[0] & 0x0F,
        tos: bytes[1],
        total_length,
        identification,
        flags: (flags_frag >> 13) & 0x7,
        fragment_offset: flags_frag & 0x1FFF,
        ttl: bytes[8],
        protocol: bytes[9],
        header_checksum,
        src_addr,
        dst_addr,
    })
}

/// Serializes `hdr` (host byte order) into out[0..19], converting
/// fields back to network byte order and computing+filling the header
/// checksum. `out` must have at least IP_HEADER_LEN bytes available.
pub fn build_ip_header(hdr: &IpHeader, out: &mut [u8]) {
    out[0] = (hdr.version << 4) | (hdr.ihl & 0x0F);
    out[1] = hdr.tos;
    out[2..4].copy_from_slice(&hdr.total_length.to_be_bytes());
    out[4..6].copy_from_slice(&hdr.identification.to_be_bytes());

    let flags_frag = ((hdr.flags & 0x7) << 13) | (hdr.fragment_offset & 0x1FFF);
    out[6..8].copy_from_slice(&flags_frag.to_be_bytes());

    out[8] = hdr.ttl;
    out[9] = hdr.protocol;

    // Checksum field must be zero before computing (RFC 1071): the
    // field is itself part of the summed range.
    out[10] = 0;
    out[11] = 0;

    out[12..16].copy_from_slice(&hdr.src_addr.to_be_bytes());
    out[16..20].copy_from_slice(&hdr.dst_addr.to_be_bytes());

    let csum = checksum16(&out[..IP_HEADER_LEN]);
    out[10..12].copy_from_slice(&csum.to_be_bytes());
}

/// Standard Internet checksum (RFC 1071) over `data`. Sums 16-bit
/// big-endian words, folds carries until they fit in 16 bits, and
/// returns the one's complement in HOST byte order. Callers must
/// convert the result to network byte order before writing it into a
/// header field on the wire. `data.len()` may be odd; the trailing
/// byte is treated as the high byte of a zero-padded word.
pub fn checksum16(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for word in &mut chunks {
        sum += u16::from_be_bytes([word[0], word[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }

    // Carry-fold loop: a single non-looping fold can leave a carry on
    // larger buffers, since the fold itself can overflow back into bit 16.
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

/// Returns true if the 20-byte header at `bytes` (checksum field
/// included, unmodified) has a valid IP header checksum.
pub fn verify_ip_checksum(bytes: &[u8]) -> bool {
    if bytes.len() < IP_HEADER_LEN {
        return false;
    }
    // A header (checksum field included, unmodified) sums to all-ones
    // (0xFFFF) before the complement, so checksum16 returns 0 for it.
    checksum16(&bytes[..IP_HEADER_LEN]) == 0
}

/// Sends a fully-built IP packet (header + payload already serialized
/// into `packet`) out through the TUN fd.
pub fn send_ip_packet(tun_fd: RawFd, packet: &[u8]) -> isize {
    tun::tun_write(tun_fd, packet)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vector() {
        // Classic RFC 1071 worked example.
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(checksum16(&data), 0x220d);
    }

    #[test]
    fn build_then_verify_round_trip() {
        let hdr = IpHeader {
            version: 4,
            ihl: 5,
            tos: 0,
            total_length: 20,
            identification: 0x1234,
            flags: 0,
            fragment_offset: 0,
            ttl: 64,
            protocol: 1,
            header_checksum: 0,
            src_addr: 0x0A00_0001, // 10.0.0.1
            dst_addr: 0x0A00_0002, // 10.0.0.2
        };

        let mut packet = vec![0u8; IP_HEADER_LEN];
        build_ip_header(&hdr, &mut packet);
        assert!(verify_ip_checksum(&packet));

        // Corrupting any byte should invalidate the checksum.
        packet[0] ^= 0xFF;
        assert!(!verify_ip_checksum(&packet));
    }

    #[test]
    fn odd_length() {
        let data = [0xABu8];
        // Single byte 0xAB treated as high byte of word 0xAB00; complement.
        assert_eq!(checksum16(&data), !0xAB00u16);
    }
}
