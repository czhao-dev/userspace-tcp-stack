#include <cassert>
#include <cstdint>
#include <cstdio>
#include <vector>

#include "ip.h"

using minitcp::checksum16;
using minitcp::IPHeader;
using minitcp::build_ip_header;
using minitcp::verify_ip_checksum;
using minitcp::kIPHeaderLen;

namespace {

void test_known_vector() {
    // Classic RFC 1071 worked example.
    uint8_t data[] = {0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7};
    uint16_t result = checksum16(data, sizeof(data));
    assert(result == 0x220d);
}

void test_build_then_verify_round_trip() {
    IPHeader hdr{};
    hdr.version = 4;
    hdr.ihl = 5;
    hdr.tos = 0;
    hdr.total_length = 20;
    hdr.identification = 0x1234;
    hdr.flags = 0;
    hdr.fragment_offset = 0;
    hdr.ttl = 64;
    hdr.protocol = 1;
    hdr.src_addr = 0x0A000001;  // 10.0.0.1
    hdr.dst_addr = 0x0A000002;  // 10.0.0.2

    std::vector<uint8_t> packet(kIPHeaderLen);
    build_ip_header(hdr, packet.data());
    assert(verify_ip_checksum(packet.data(), packet.size()));

    // Corrupting any byte should invalidate the checksum.
    packet[0] ^= 0xFF;
    assert(!verify_ip_checksum(packet.data(), packet.size()));
}

void test_odd_length() {
    uint8_t data[] = {0xAB};
    uint16_t result = checksum16(data, sizeof(data));
    // Single byte 0xAB treated as high byte of word 0xAB00; complement.
    assert(result == static_cast<uint16_t>(~0xAB00 & 0xFFFF));
}

}  // namespace

int main() {
    test_known_vector();
    test_build_then_verify_round_trip();
    test_odd_length();
    std::printf("checksum_test: all tests passed\n");
    return 0;
}
