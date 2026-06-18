#pragma once

#include <cstddef>
#include <cstdint>
#include <sys/types.h>

namespace minitcp {

// In-memory representation of an IPv4 header. Fields are always in
// HOST byte order here; conversion to/from network byte order happens
// only at the parse_ip_header/build_ip_header boundary. No support for
// IP options (assumes a 20-byte header, IHL == 5).
struct IPHeader {
    uint8_t version;          // always 4
    uint8_t ihl;               // header length in 32-bit words (5, no options)
    uint8_t tos;
    uint16_t total_length;     // header + payload, in bytes
    uint16_t identification;
    uint16_t flags;            // top 3 bits of the flags/fragment-offset field
    uint16_t fragment_offset;  // low 13 bits of the flags/fragment-offset field
    uint8_t ttl;
    uint8_t protocol;          // 1 = ICMP, 6 = TCP, 17 = UDP
    uint16_t header_checksum;
    uint32_t src_addr;
    uint32_t dst_addr;
};

constexpr size_t kIPHeaderLen = 20;

// Parses the first 20 bytes of `bytes` into an IPHeader, converting
// multi-byte fields to host byte order. Does NOT validate the
// checksum (use verify_ip_checksum for that). Returns false if `len`
// < 20 or the version field isn't 4.
bool parse_ip_header(const uint8_t* bytes, size_t len, IPHeader& out);

// Serializes `hdr` (host byte order) into out_bytes[0..19], converting
// fields back to network byte order and computing+filling the header
// checksum. out_bytes must have at least kIPHeaderLen bytes available.
void build_ip_header(const IPHeader& hdr, uint8_t* out_bytes);

// Standard Internet checksum (RFC 1071) over [data, data+len). Sums
// 16-bit big-endian words (read explicitly byte-by-byte, independent
// of host endianness), folds carries until they fit in 16 bits, and
// returns the one's complement in HOST byte order. Callers must
// htons() the result before writing it into a header field on the
// wire. `len` may be odd; the trailing byte is treated as the high
// byte of a zero-padded word.
uint16_t checksum16(const uint8_t* data, size_t len);

// Returns true if the 20-byte header at `bytes` (checksum field
// included, unmodified) has a valid IP header checksum.
bool verify_ip_checksum(const uint8_t* bytes, size_t len);

// Sends a fully-built IP packet (header + payload already serialized
// into `packet`, total length total_len) out through the TUN fd.
ssize_t send_ip_packet(int tun_fd, const uint8_t* packet, size_t total_len);

}  // namespace minitcp
