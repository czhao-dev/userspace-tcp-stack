#include "tcp.h"

#include <algorithm>
#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <map>
#include <random>
#include <set>
#include <tuple>
#include <utility>

namespace minitcp {

bool parse_tcp_header(const uint8_t* bytes, size_t len, TCPHeader& out) {
    if (len < kTcpHeaderLen) {
        return false;
    }

    uint16_t src_port_n, dst_port_n, window_n, checksum_n, urgent_n;
    uint32_t seq_n, ack_n;
    std::memcpy(&src_port_n, bytes + 0, 2);
    std::memcpy(&dst_port_n, bytes + 2, 2);
    std::memcpy(&seq_n, bytes + 4, 4);
    std::memcpy(&ack_n, bytes + 8, 4);
    out.data_offset_reserved = bytes[12];
    out.flags = bytes[13];
    std::memcpy(&window_n, bytes + 14, 2);
    std::memcpy(&checksum_n, bytes + 16, 2);
    std::memcpy(&urgent_n, bytes + 18, 2);

    out.src_port = ntohs(src_port_n);
    out.dst_port = ntohs(dst_port_n);
    out.seq_num = ntohl(seq_n);
    out.ack_num = ntohl(ack_n);
    out.window = ntohs(window_n);
    out.checksum = ntohs(checksum_n);
    out.urgent_ptr = ntohs(urgent_n);
    return true;
}

void build_tcp_header(const TCPHeader& hdr, uint8_t* out) {
    uint16_t src_port_n = htons(hdr.src_port);
    uint16_t dst_port_n = htons(hdr.dst_port);
    uint32_t seq_n = htonl(hdr.seq_num);
    uint32_t ack_n = htonl(hdr.ack_num);
    uint16_t window_n = htons(hdr.window);
    uint16_t checksum_n = htons(hdr.checksum);
    uint16_t urgent_n = htons(hdr.urgent_ptr);

    std::memcpy(out + 0, &src_port_n, 2);
    std::memcpy(out + 2, &dst_port_n, 2);
    std::memcpy(out + 4, &seq_n, 4);
    std::memcpy(out + 8, &ack_n, 4);
    out[12] = hdr.data_offset_reserved;
    out[13] = hdr.flags;
    std::memcpy(out + 14, &window_n, 2);
    std::memcpy(out + 16, &checksum_n, 2);
    std::memcpy(out + 18, &urgent_n, 2);
}

uint16_t tcp_checksum(uint32_t src_addr, uint32_t dst_addr,
                      const uint8_t* tcp_segment, size_t tcp_segment_len) {
    std::vector<uint8_t> buf(12 + tcp_segment_len);
    uint32_t src_n = htonl(src_addr);
    uint32_t dst_n = htonl(dst_addr);
    std::memcpy(buf.data(), &src_n, 4);
    std::memcpy(buf.data() + 4, &dst_n, 4);
    buf[8] = 0;
    buf[9] = 6;  // protocol = TCP
    uint16_t len_n = htons(static_cast<uint16_t>(tcp_segment_len));
    std::memcpy(buf.data() + 10, &len_n, 2);
    std::memcpy(buf.data() + 12, tcp_segment, tcp_segment_len);
    return checksum16(buf.data(), buf.size());
}

const char* tcp_state_name(TCPState state) {
    switch (state) {
        case TCPState::CLOSED: return "CLOSED";
        case TCPState::LISTEN: return "LISTEN";
        case TCPState::SYN_SENT: return "SYN_SENT";
        case TCPState::SYN_RCVD: return "SYN_RCVD";
        case TCPState::ESTABLISHED: return "ESTABLISHED";
        case TCPState::FIN_WAIT_1: return "FIN_WAIT_1";
        case TCPState::FIN_WAIT_2: return "FIN_WAIT_2";
        case TCPState::CLOSING: return "CLOSING";
        case TCPState::TIME_WAIT: return "TIME_WAIT";
        case TCPState::CLOSE_WAIT: return "CLOSE_WAIT";
        case TCPState::LAST_ACK: return "LAST_ACK";
    }
    return "?";
}

namespace {

struct ConnKey {
    uint32_t local_addr;
    uint16_t local_port;
    uint32_t remote_addr;
    uint16_t remote_port;

    bool operator<(const ConnKey& other) const {
        return std::tie(local_addr, local_port, remote_addr, remote_port) <
               std::tie(other.local_addr, other.local_port, other.remote_addr,
                        other.remote_port);
    }
};

constexpr size_t kMss = 1400;
constexpr std::chrono::milliseconds kInitialRto(500);
constexpr std::chrono::milliseconds kMaxRto(8000);
constexpr int kMaxRetries = 6;
constexpr std::chrono::seconds kTimeWaitDuration(4);  // shortened 2*MSL for demo purposes

std::map<ConnKey, TCPConnPtr> g_connections;
std::set<std::pair<uint32_t, uint16_t>> g_listeners;
std::map<std::pair<uint32_t, uint16_t>, std::deque<TCPConnPtr>> g_accept_queues;
uint16_t g_next_ephemeral_port = 49152;

std::string flags_to_string(uint8_t flags) {
    std::string s;
    if (flags & kTcpSyn) s += "SYN,";
    if (flags & kTcpAck) s += "ACK,";
    if (flags & kTcpFin) s += "FIN,";
    if (flags & kTcpRst) s += "RST,";
    if (flags & kTcpPsh) s += "PSH,";
    if (flags & kTcpUrg) s += "URG,";
    if (!s.empty()) s.pop_back();
    if (s.empty()) s = "-";
    return s;
}

uint32_t generate_iss() {
    static std::mt19937 rng(
        static_cast<unsigned>(std::chrono::steady_clock::now().time_since_epoch().count()));
    return rng();
}

uint16_t allocate_ephemeral_port() {
    return g_next_ephemeral_port++;
}

uint16_t advertise_window(const TCPConnPtr& conn) {
    size_t used = conn->recv_buffer.size();
    size_t cap = TCPConnection::kRecvBufferCap;
    if (used >= cap) return 0;
    size_t avail = cap - used;
    return static_cast<uint16_t>(std::min<size_t>(avail, 65535));
}

void send_segment(const TCPConnPtr& conn, int tun_fd, uint8_t flags,
                   uint32_t seq, const uint8_t* data, size_t len, bool trace) {
    TCPHeader hdr{};
    hdr.src_port = conn->local_port;
    hdr.dst_port = conn->remote_port;
    hdr.seq_num = seq;
    hdr.ack_num = (flags & kTcpAck) ? conn->rcv_nxt : 0;
    hdr.data_offset_reserved = static_cast<uint8_t>(5 << 4);
    hdr.flags = flags;
    hdr.window = advertise_window(conn);
    hdr.checksum = 0;
    hdr.urgent_ptr = 0;

    std::vector<uint8_t> segment(kTcpHeaderLen + len);
    build_tcp_header(hdr, segment.data());
    if (len > 0) {
        std::memcpy(segment.data() + kTcpHeaderLen, data, len);
    }

    uint16_t csum = tcp_checksum(conn->local_addr, conn->remote_addr, segment.data(),
                                  segment.size());
    uint16_t csum_n = htons(csum);
    std::memcpy(segment.data() + 16, &csum_n, 2);

    IPHeader iphdr{};
    iphdr.version = 4;
    iphdr.ihl = 5;
    iphdr.tos = 0;
    iphdr.total_length = static_cast<uint16_t>(kIPHeaderLen + segment.size());
    iphdr.identification = 0;
    iphdr.flags = 0;
    iphdr.fragment_offset = 0;
    iphdr.ttl = 64;
    iphdr.protocol = 6;
    iphdr.src_addr = conn->local_addr;
    iphdr.dst_addr = conn->remote_addr;

    std::vector<uint8_t> packet(kIPHeaderLen + segment.size());
    build_ip_header(iphdr, packet.data());
    std::memcpy(packet.data() + kIPHeaderLen, segment.data(), segment.size());
    send_ip_packet(tun_fd, packet.data(), packet.size());

    if (trace) {
        std::printf("[TCP ] send  %-11s seq=%u ack=%u win=%u len=%zu\n",
                    flags_to_string(flags).c_str(), seq, hdr.ack_num, hdr.window, len);
    }
}

void queue_and_send(const TCPConnPtr& conn, int tun_fd, uint8_t flags,
                     const uint8_t* data, size_t len, bool trace) {
    uint32_t seq = conn->snd_nxt;
    send_segment(conn, tun_fd, flags, seq, data, len, trace);

    UnackedSegment u;
    u.seq = seq;
    u.flags = flags;
    u.data.assign(data, data + len);
    u.sent_at = std::chrono::steady_clock::now();
    u.rto = kInitialRto;
    u.retry_count = 0;
    conn->retransmit_queue.push_back(std::move(u));

    uint32_t consumed = static_cast<uint32_t>(len) + ((flags & kTcpSyn) ? 1 : 0) +
                        ((flags & kTcpFin) ? 1 : 0);
    conn->snd_nxt += consumed;
}

void send_ack_only(const TCPConnPtr& conn, int tun_fd, bool trace) {
    send_segment(conn, tun_fd, kTcpAck, conn->snd_nxt, nullptr, 0, trace);
}

void remove_acked(const TCPConnPtr& conn, uint32_t new_una) {
    while (!conn->retransmit_queue.empty()) {
        const UnackedSegment& front = conn->retransmit_queue.front();
        uint32_t end = front.seq + static_cast<uint32_t>(front.data.size()) +
                      ((front.flags & kTcpSyn) ? 1 : 0) + ((front.flags & kTcpFin) ? 1 : 0);
        if (end <= new_una) {
            conn->retransmit_queue.pop_front();
        } else {
            break;
        }
    }
}

void process_ack(const TCPConnPtr& conn, const TCPHeader& seg) {
    if (!(seg.flags & kTcpAck)) return;
    if (seg.ack_num > conn->snd_una) {
        conn->snd_una = seg.ack_num;
        remove_acked(conn, conn->snd_una);
    }
    conn->snd_wnd = seg.window;
}

void flush_send(const TCPConnPtr& conn, int tun_fd, bool trace) {
    if (conn->state != TCPState::ESTABLISHED && conn->state != TCPState::CLOSE_WAIT) {
        return;
    }
    while (!conn->send_pending.empty()) {
        uint32_t bytes_in_flight = conn->snd_nxt - conn->snd_una;
        if (bytes_in_flight >= conn->snd_wnd) break;
        size_t available = conn->snd_wnd - bytes_in_flight;
        size_t chunk_len = std::min({kMss, available, conn->send_pending.size()});
        if (chunk_len == 0) break;
        queue_and_send(conn, tun_fd, kTcpAck | kTcpPsh, conn->send_pending.data(), chunk_len,
                      trace);
        conn->send_pending.erase(conn->send_pending.begin(),
                                 conn->send_pending.begin() + chunk_len);
    }
}

void enqueue_accept(const TCPConnPtr& conn) {
    g_accept_queues[{conn->local_addr, conn->local_port}].push_back(conn);
}

// Handles in-order/out-of-order data delivery and FIN consumption for
// any state where the remote may still be sending data (ESTABLISHED,
// FIN_WAIT_1, FIN_WAIT_2). Sends an ACK if anything was new. Sets
// `fin_consumed` if the remote's FIN was just consumed in sequence.
void receive_data_and_maybe_fin(const TCPConnPtr& conn, int tun_fd, const TCPHeader& seg,
                                 const uint8_t* payload, size_t payload_len, bool trace,
                                 bool& fin_consumed) {
    fin_consumed = false;
    bool has_fin = seg.flags & kTcpFin;
    bool should_ack = false;

    if (seg.seq_num == conn->rcv_nxt) {
        if (payload_len > 0) {
            conn->recv_buffer.insert(conn->recv_buffer.end(), payload, payload + payload_len);
            conn->rcv_nxt += static_cast<uint32_t>(payload_len);
            should_ack = true;
        }
        // Splice in any out-of-order segments that are now contiguous.
        while (true) {
            auto it = conn->ooo_buffer.find(conn->rcv_nxt);
            if (it == conn->ooo_buffer.end()) break;
            conn->recv_buffer.insert(conn->recv_buffer.end(), it->second.begin(),
                                     it->second.end());
            conn->rcv_nxt += static_cast<uint32_t>(it->second.size());
            conn->ooo_buffer.erase(it);
            should_ack = true;
        }
        if (has_fin) {
            conn->rcv_nxt += 1;
            fin_consumed = true;
            should_ack = true;
        }
    } else if (seg.seq_num > conn->rcv_nxt) {
        // Out of order: buffer any data and send a duplicate ACK
        // advertising the byte we're actually still waiting for.
        if (payload_len > 0) {
            conn->ooo_buffer[seg.seq_num] = std::vector<uint8_t>(payload, payload + payload_len);
        }
        should_ack = true;
    } else {
        // seg.seq_num < rcv_nxt: old retransmitted data we already have.
        should_ack = payload_len > 0 || has_fin;
    }

    if (should_ack) {
        send_ack_only(conn, tun_fd, trace);
    }
}

void print_state_change(const TCPConnPtr& conn, TCPState old_state) {
    std::printf("[TCP ] state %s -> %s\n", tcp_state_name(old_state),
               tcp_state_name(conn->state));
}

void process_segment(const TCPConnPtr& conn, int tun_fd, const TCPHeader& seg,
                     const uint8_t* payload, size_t payload_len, bool trace) {
    if (trace) {
        std::printf("[TCP ] recv  %-11s seq=%u ack=%u win=%u len=%zu  state=%s\n",
                    flags_to_string(seg.flags).c_str(), seg.seq_num, seg.ack_num, seg.window,
                    payload_len, tcp_state_name(conn->state));
    }

    TCPState old_state = conn->state;

    switch (conn->state) {
        case TCPState::SYN_SENT: {
            if (seg.flags & kTcpRst) {
                conn->state = TCPState::CLOSED;
                break;
            }
            if ((seg.flags & kTcpSyn) && (seg.flags & kTcpAck) &&
                seg.ack_num == conn->snd_nxt) {
                conn->irs = seg.seq_num;
                conn->rcv_nxt = seg.seq_num + 1;
                conn->snd_una = seg.ack_num;
                conn->snd_wnd = seg.window;
                remove_acked(conn, conn->snd_una);
                conn->state = TCPState::ESTABLISHED;
                send_ack_only(conn, tun_fd, trace);
            }
            break;
        }
        case TCPState::SYN_RCVD: {
            if (seg.flags & kTcpRst) {
                conn->state = TCPState::CLOSED;
                break;
            }
            if ((seg.flags & kTcpAck) && seg.ack_num == conn->snd_nxt) {
                conn->snd_una = seg.ack_num;
                remove_acked(conn, conn->snd_una);
                conn->snd_wnd = seg.window;
                conn->state = TCPState::ESTABLISHED;
                enqueue_accept(conn);
                if (payload_len > 0 || (seg.flags & kTcpFin)) {
                    bool fin = false;
                    receive_data_and_maybe_fin(conn, tun_fd, seg, payload, payload_len, trace,
                                               fin);
                    if (fin) conn->state = TCPState::CLOSE_WAIT;
                }
            }
            break;
        }
        case TCPState::ESTABLISHED: {
            process_ack(conn, seg);
            bool fin = false;
            receive_data_and_maybe_fin(conn, tun_fd, seg, payload, payload_len, trace, fin);
            if (fin) conn->state = TCPState::CLOSE_WAIT;
            flush_send(conn, tun_fd, trace);
            break;
        }
        case TCPState::FIN_WAIT_1: {
            process_ack(conn, seg);
            bool our_fin_acked = (seg.flags & kTcpAck) && seg.ack_num == conn->snd_nxt;
            bool fin = false;
            receive_data_and_maybe_fin(conn, tun_fd, seg, payload, payload_len, trace, fin);
            if (our_fin_acked && fin) {
                conn->state = TCPState::TIME_WAIT;
                conn->time_wait_deadline = std::chrono::steady_clock::now() + kTimeWaitDuration;
            } else if (our_fin_acked) {
                conn->state = TCPState::FIN_WAIT_2;
            } else if (fin) {
                conn->state = TCPState::CLOSING;
            }
            break;
        }
        case TCPState::FIN_WAIT_2: {
            process_ack(conn, seg);
            bool fin = false;
            receive_data_and_maybe_fin(conn, tun_fd, seg, payload, payload_len, trace, fin);
            if (fin) {
                conn->state = TCPState::TIME_WAIT;
                conn->time_wait_deadline = std::chrono::steady_clock::now() + kTimeWaitDuration;
            }
            break;
        }
        case TCPState::CLOSING: {
            process_ack(conn, seg);
            if ((seg.flags & kTcpAck) && seg.ack_num == conn->snd_nxt) {
                conn->state = TCPState::TIME_WAIT;
                conn->time_wait_deadline = std::chrono::steady_clock::now() + kTimeWaitDuration;
            }
            break;
        }
        case TCPState::CLOSE_WAIT: {
            process_ack(conn, seg);
            flush_send(conn, tun_fd, trace);
            break;
        }
        case TCPState::LAST_ACK: {
            process_ack(conn, seg);
            if ((seg.flags & kTcpAck) && seg.ack_num == conn->snd_nxt) {
                conn->state = TCPState::CLOSED;
            }
            break;
        }
        case TCPState::TIME_WAIT: {
            // The whole point of TIME_WAIT: if our final ACK was lost,
            // the remote retransmits its FIN. Re-ACK it (and restart
            // the timer) instead of silently ignoring it, or the
            // remote will retransmit until it gives up entirely.
            if (seg.flags & kTcpFin) {
                send_ack_only(conn, tun_fd, trace);
                conn->time_wait_deadline = std::chrono::steady_clock::now() + kTimeWaitDuration;
            }
            break;
        }
        case TCPState::CLOSED:
        case TCPState::LISTEN:
        default:
            break;
    }

    if (trace && conn->state != old_state) {
        print_state_change(conn, old_state);
    }
}

void send_rst_for_unknown(int tun_fd, const IPHeader& ip_hdr, const TCPHeader& seg,
                          size_t data_len, bool trace) {
    TCPHeader rst{};
    rst.src_port = seg.dst_port;
    rst.dst_port = seg.src_port;
    bool incoming_ack = seg.flags & kTcpAck;
    if (incoming_ack) {
        rst.seq_num = seg.ack_num;
        rst.flags = kTcpRst;
        rst.ack_num = 0;
    } else {
        rst.seq_num = 0;
        rst.flags = kTcpRst | kTcpAck;
        uint32_t consumed = static_cast<uint32_t>(data_len) +
                            ((seg.flags & kTcpSyn) ? 1 : 0) + ((seg.flags & kTcpFin) ? 1 : 0);
        rst.ack_num = seg.seq_num + consumed;
    }
    rst.data_offset_reserved = static_cast<uint8_t>(5 << 4);
    rst.window = 0;
    rst.checksum = 0;
    rst.urgent_ptr = 0;

    std::vector<uint8_t> segment(kTcpHeaderLen);
    build_tcp_header(rst, segment.data());
    uint16_t csum = tcp_checksum(ip_hdr.dst_addr, ip_hdr.src_addr, segment.data(),
                                  segment.size());
    uint16_t csum_n = htons(csum);
    std::memcpy(segment.data() + 16, &csum_n, 2);

    IPHeader iphdr{};
    iphdr.version = 4;
    iphdr.ihl = 5;
    iphdr.total_length = static_cast<uint16_t>(kIPHeaderLen + segment.size());
    iphdr.ttl = 64;
    iphdr.protocol = 6;
    iphdr.src_addr = ip_hdr.dst_addr;
    iphdr.dst_addr = ip_hdr.src_addr;

    std::vector<uint8_t> packet(kIPHeaderLen + segment.size());
    build_ip_header(iphdr, packet.data());
    std::memcpy(packet.data() + kIPHeaderLen, segment.data(), segment.size());
    send_ip_packet(tun_fd, packet.data(), packet.size());

    if (trace) {
        std::printf("[TCP ] send  RST,ACK    -> port %u unreachable\n", seg.dst_port);
    }
}

void cleanup_closed_connections() {
    for (auto it = g_connections.begin(); it != g_connections.end();) {
        if (it->second->state == TCPState::CLOSED) {
            it = g_connections.erase(it);
        } else {
            ++it;
        }
    }
}

}  // namespace

void handle_tcp(int tun_fd, const IPHeader& ip_hdr, const uint8_t* payload, size_t payload_len,
                bool trace) {
    if (payload_len < kTcpHeaderLen) return;

    TCPHeader seg;
    if (!parse_tcp_header(payload, payload_len, seg)) return;

    uint16_t csum = tcp_checksum(ip_hdr.src_addr, ip_hdr.dst_addr, payload, payload_len);
    if (csum != 0) {
        if (trace) std::printf("[TCP ] recv  bad checksum, dropping segment\n");
        return;
    }

    const uint8_t* data = payload + kTcpHeaderLen;
    size_t data_len = payload_len - kTcpHeaderLen;

    ConnKey key{ip_hdr.dst_addr, seg.dst_port, ip_hdr.src_addr, seg.src_port};
    auto it = g_connections.find(key);
    if (it != g_connections.end()) {
        process_segment(it->second, tun_fd, seg, data, data_len, trace);
        cleanup_closed_connections();
        return;
    }

    auto listen_key = std::make_pair(ip_hdr.dst_addr, seg.dst_port);
    if ((seg.flags & kTcpSyn) && !(seg.flags & kTcpAck) && g_listeners.count(listen_key)) {
        TCPConnPtr conn = tcp_create();
        conn->local_addr = ip_hdr.dst_addr;
        conn->local_port = seg.dst_port;
        conn->remote_addr = ip_hdr.src_addr;
        conn->remote_port = seg.src_port;
        conn->irs = seg.seq_num;
        conn->rcv_nxt = seg.seq_num + 1;
        conn->iss = generate_iss();
        conn->snd_una = conn->iss;
        conn->snd_nxt = conn->iss;
        conn->snd_wnd = seg.window;
        conn->state = TCPState::SYN_RCVD;
        g_connections[key] = conn;

        if (trace) {
            std::printf("[TCP ] recv  %-11s seq=%u ack=%u win=%u len=%zu  state=LISTEN\n",
                        flags_to_string(seg.flags).c_str(), seg.seq_num, seg.ack_num, seg.window,
                        data_len);
            std::printf("[TCP ] state LISTEN -> SYN_RCVD\n");
        }
        queue_and_send(conn, tun_fd, kTcpSyn | kTcpAck, nullptr, 0, trace);
        return;
    }

    if (!(seg.flags & kTcpRst)) {
        send_rst_for_unknown(tun_fd, ip_hdr, seg, data_len, trace);
    }
}

void tcp_tick(int tun_fd, bool trace) {
    auto now = std::chrono::steady_clock::now();

    for (auto& entry : g_connections) {
        TCPConnPtr& conn = entry.second;

        if (conn->state == TCPState::TIME_WAIT) {
            if (now >= conn->time_wait_deadline) {
                conn->state = TCPState::CLOSED;
                if (trace) std::printf("[TCP ] state TIME_WAIT -> CLOSED\n");
            }
            continue;
        }

        if (!conn->retransmit_queue.empty()) {
            UnackedSegment& front = conn->retransmit_queue.front();
            if (now - front.sent_at >= front.rto) {
                if (front.retry_count >= kMaxRetries) {
                    if (trace) {
                        std::printf("[TCP ] giving up after %d retries, dropping connection\n",
                                    front.retry_count);
                    }
                    conn->state = TCPState::CLOSED;
                    continue;
                }
                if (trace) {
                    std::printf("[TCP ] retransmit seq=%u (attempt %d, rto=%lldms)\n", front.seq,
                                front.retry_count + 1,
                                static_cast<long long>(front.rto.count()));
                }
                send_segment(conn, tun_fd, front.flags, front.seq, front.data.data(),
                            front.data.size(), trace);
                front.sent_at = now;
                front.rto = std::min(front.rto * 2, kMaxRto);
                front.retry_count++;
            }
        }

        flush_send(conn, tun_fd, trace);
    }

    cleanup_closed_connections();
}

TCPConnPtr tcp_create() {
    return std::make_shared<TCPConnection>();
}

void tcp_listen(uint32_t local_addr, uint16_t local_port) {
    g_listeners.insert({local_addr, local_port});
}

TCPConnPtr tcp_accept(uint32_t local_addr, uint16_t local_port) {
    auto it = g_accept_queues.find({local_addr, local_port});
    if (it == g_accept_queues.end() || it->second.empty()) {
        return nullptr;
    }
    TCPConnPtr conn = it->second.front();
    it->second.pop_front();
    return conn;
}

bool tcp_connect(TCPConnPtr conn, int tun_fd, uint32_t local_addr, uint32_t remote_addr,
                 uint16_t remote_port, bool trace) {
    uint16_t local_port = allocate_ephemeral_port();
    conn->local_addr = local_addr;
    conn->local_port = local_port;
    conn->remote_addr = remote_addr;
    conn->remote_port = remote_port;
    conn->iss = generate_iss();
    conn->snd_una = conn->iss;
    conn->snd_nxt = conn->iss;
    conn->state = TCPState::SYN_SENT;

    g_connections[ConnKey{local_addr, local_port, remote_addr, remote_port}] = conn;

    if (trace) {
        std::printf("[TCP ] state CLOSED -> SYN_SENT (connecting to port %u)\n", remote_port);
    }
    queue_and_send(conn, tun_fd, kTcpSyn, nullptr, 0, trace);
    return true;
}

size_t tcp_send(TCPConnPtr conn, int tun_fd, const uint8_t* data, size_t len, bool trace) {
    conn->send_pending.insert(conn->send_pending.end(), data, data + len);
    flush_send(conn, tun_fd, trace);
    return len;
}

size_t tcp_recv(TCPConnPtr conn, uint8_t* buf, size_t maxlen) {
    size_t n = std::min(maxlen, conn->recv_buffer.size());
    if (n > 0) {
        std::memcpy(buf, conn->recv_buffer.data(), n);
        conn->recv_buffer.erase(conn->recv_buffer.begin(), conn->recv_buffer.begin() + n);
    }
    return n;
}

void tcp_close(TCPConnPtr conn, int tun_fd, bool trace) {
    TCPState old_state = conn->state;
    switch (conn->state) {
        case TCPState::ESTABLISHED:
            queue_and_send(conn, tun_fd, kTcpFin | kTcpAck, nullptr, 0, trace);
            conn->state = TCPState::FIN_WAIT_1;
            break;
        case TCPState::CLOSE_WAIT:
            queue_and_send(conn, tun_fd, kTcpFin | kTcpAck, nullptr, 0, trace);
            conn->state = TCPState::LAST_ACK;
            break;
        case TCPState::SYN_SENT:
        case TCPState::LISTEN:
            conn->state = TCPState::CLOSED;
            break;
        default:
            break;
    }
    if (trace && conn->state != old_state) {
        print_state_change(conn, old_state);
    }
}

bool tcp_is_established(const TCPConnPtr& conn) {
    return conn && conn->state == TCPState::ESTABLISHED;
}

bool tcp_is_closed(const TCPConnPtr& conn) {
    return !conn || conn->state == TCPState::CLOSED;
}

TCPConnPtr tcp_lookup(uint32_t local_addr, uint16_t local_port, uint32_t remote_addr,
                      uint16_t remote_port) {
    auto it = g_connections.find(ConnKey{local_addr, local_port, remote_addr, remote_port});
    if (it == g_connections.end()) return nullptr;
    return it->second;
}

}  // namespace minitcp
