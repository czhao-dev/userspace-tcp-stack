#include "ip.h"

#include <arpa/inet.h>
#include <cstring>

#include "tun.h"

namespace minitcp {

bool parse_ip_header(const uint8_t* bytes, size_t len, IPHeader& out) {
    if (len < kIPHeaderLen) {
        return false;
    }

    uint8_t version = bytes[0] >> 4;
    if (version != 4) {
        return false;
    }

    out.version = version;
    out.ihl = bytes[0] & 0x0F;
    out.tos = bytes[1];

    uint16_t total_length_n, id_n, flags_frag_n, checksum_n;
    std::memcpy(&total_length_n, bytes + 2, 2);
    std::memcpy(&id_n, bytes + 4, 2);
    std::memcpy(&flags_frag_n, bytes + 6, 2);
    std::memcpy(&checksum_n, bytes + 10, 2);

    out.total_length = ntohs(total_length_n);
    out.identification = ntohs(id_n);
    uint16_t flags_frag = ntohs(flags_frag_n);
    out.flags = (flags_frag >> 13) & 0x7;
    out.fragment_offset = flags_frag & 0x1FFF;

    out.ttl = bytes[8];
    out.protocol = bytes[9];
    out.header_checksum = ntohs(checksum_n);

    uint32_t src_n, dst_n;
    std::memcpy(&src_n, bytes + 12, 4);
    std::memcpy(&dst_n, bytes + 16, 4);
    out.src_addr = ntohl(src_n);
    out.dst_addr = ntohl(dst_n);

    return true;
}

void build_ip_header(const IPHeader& hdr, uint8_t* out) {
    out[0] = static_cast<uint8_t>((hdr.version << 4) | (hdr.ihl & 0x0F));
    out[1] = hdr.tos;

    uint16_t total_length_n = htons(hdr.total_length);
    std::memcpy(out + 2, &total_length_n, 2);

    uint16_t id_n = htons(hdr.identification);
    std::memcpy(out + 4, &id_n, 2);

    uint16_t flags_frag = static_cast<uint16_t>(((hdr.flags & 0x7) << 13) |
                                                 (hdr.fragment_offset & 0x1FFF));
    uint16_t flags_frag_n = htons(flags_frag);
    std::memcpy(out + 6, &flags_frag_n, 2);

    out[8] = hdr.ttl;
    out[9] = hdr.protocol;

    // Checksum field must be zero before computing (RFC 1071): the
    // field is itself part of the summed range.
    out[10] = 0;
    out[11] = 0;

    uint32_t src_n = htonl(hdr.src_addr);
    std::memcpy(out + 12, &src_n, 4);
    uint32_t dst_n = htonl(hdr.dst_addr);
    std::memcpy(out + 16, &dst_n, 4);

    uint16_t csum_n = htons(checksum16(out, kIPHeaderLen));
    std::memcpy(out + 10, &csum_n, 2);
}

uint16_t checksum16(const uint8_t* data, size_t len) {
    uint32_t sum = 0;
    size_t i = 0;

    for (; i + 1 < len; i += 2) {
        uint16_t word = static_cast<uint16_t>((data[i] << 8) | data[i + 1]);
        sum += word;
    }
    if (i < len) {
        // Odd trailing byte: treated as the high byte of a zero-padded word.
        sum += static_cast<uint16_t>(data[i] << 8);
    }

    // Carry-fold loop: a single non-looping fold can leave a carry on
    // larger buffers, since the fold itself can overflow back into bit 16.
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return static_cast<uint16_t>(~sum & 0xFFFF);
}

bool verify_ip_checksum(const uint8_t* bytes, size_t len) {
    if (len < kIPHeaderLen) {
        return false;
    }
    // A header (checksum field included, unmodified) sums to all-ones
    // (0xFFFF) before the complement, so checksum16 returns 0 for it.
    return checksum16(bytes, kIPHeaderLen) == 0;
}

ssize_t send_ip_packet(int tun_fd, const uint8_t* packet, size_t total_len) {
    return tun_write(tun_fd, packet, total_len);
}

}  // namespace minitcp
