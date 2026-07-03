//! Simulates packet loss on the "wire" between two in-process TCP
//! endpoints (no TUN device needed) and verifies that a full
//! handshake -> data transfer -> teardown cycle still completes
//! correctly at 0%, 10%, and 30% simulated loss, exercising the real
//! retransmission-timer / exponential-backoff code path in `tcp.rs`.
use std::os::unix::io::RawFd;
use std::thread;
use std::time::{Duration, Instant};

use minitcp::ip;
use minitcp::tcp::{self, TcpTable};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

const SERVER_ADDR: u32 = 0x0A09_0001; // 10.9.0.1
const CLIENT_ADDR: u32 = 0x0A09_0002; // 10.9.0.2
const SERVER_PORT: u16 = 9191;

struct Pipe {
    read_fd: RawFd,
    write_fd: RawFd,
}

/// A datagram (not stream) socketpair, so each write on one end shows
/// up as exactly one read on the other — matching a real TUN device's
/// one-packet-per-read semantics. A plain pipe does NOT have this
/// property: it's a byte stream, so two small segments written
/// back-to-back can coalesce into a single read, which would get
/// misparsed as one (corrupt) packet. That bug bit the very first
/// version of this test (in its original C++ form).
fn make_nonblocking_pipe() -> Pipe {
    let mut fds = [0 as RawFd; 2];
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
    assert_eq!(rc, 0, "socketpair failed: {}", std::io::Error::last_os_error());
    unsafe {
        libc::fcntl(fds[0], libc::F_SETFL, libc::O_NONBLOCK);
    }
    Pipe {
        read_fd: fds[0],
        write_fd: fds[1],
    }
}

/// Drains any packets waiting on `from_read_fd` and, with probability
/// `drop_rate`, discards each one instead of feeding it into the other
/// side's `handle_segment()` — the actual packet-loss simulation.
fn forward_packets(
    table: &mut TcpTable,
    from_read_fd: RawFd,
    to_tun_fd: RawFd,
    drop_rate: f64,
    rng: &mut StdRng,
    dropped_count: &mut u32,
) {
    let mut buf = [0u8; 2048];
    loop {
        let n = unsafe { libc::read(from_read_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= 0 {
            break;
        }
        let n = n as usize;
        if rng.gen::<f64>() < drop_rate {
            *dropped_count += 1;
            continue;
        }
        let Some(ip_hdr) = ip::parse_ip_header(&buf[..n]) else {
            continue;
        };
        let header_bytes = (ip_hdr.ihl as usize) * 4;
        if header_bytes > n {
            continue;
        }
        table.handle_segment(to_tun_fd, &ip_hdr, &buf[header_bytes..n], false);
    }
}

fn run_one_trial(drop_rate: f64) {
    let mut rng = StdRng::seed_from_u64(12345 + (drop_rate * 1000.0) as u64);

    let client_wire = make_nonblocking_pipe();
    let server_wire = make_nonblocking_pipe();

    let mut client_table = TcpTable::new();
    let mut server_table = TcpTable::new();

    assert!(server_table.listen(SERVER_ADDR, SERVER_PORT, false));

    let client_key = client_table.connect(client_wire.write_fd, CLIENT_ADDR, SERVER_ADDR, SERVER_PORT, false);

    let message = b"hello from minitcp client";
    let message_len = message.len();

    let mut server_key: Option<tcp::ConnectionKey> = None;
    let mut received: Vec<u8> = Vec::new();
    let mut sent_data = false;
    let mut client_closed = false;
    let mut server_closed = false;
    let mut dropped_count = 0u32;

    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        forward_packets(
            &mut server_table,
            client_wire.read_fd,
            server_wire.write_fd,
            drop_rate,
            &mut rng,
            &mut dropped_count,
        );
        forward_packets(
            &mut client_table,
            server_wire.read_fd,
            client_wire.write_fd,
            drop_rate,
            &mut rng,
            &mut dropped_count,
        );
        client_table.tick(client_wire.write_fd, false);
        server_table.tick(server_wire.write_fd, false);

        if server_key.is_none() {
            server_key = server_table.accept(SERVER_ADDR, SERVER_PORT);
        }

        if server_key.is_some() && client_table.is_established(client_key) && !sent_data {
            client_table.send(client_key, client_wire.write_fd, message, false);
            sent_data = true;
        }

        if let Some(skey) = server_key {
            if sent_data && received.len() < message_len {
                let mut chunk = [0u8; 256];
                let n = server_table.recv(skey, &mut chunk);
                if n > 0 {
                    received.extend_from_slice(&chunk[..n]);
                }
            }
        }

        // Both sides close once the message has been fully delivered —
        // the server's close (replying to the client's eventual FIN
        // with its own) is what lets the client ever leave FIN_WAIT_2.
        if sent_data && received.len() == message_len && !client_closed {
            client_table.close(client_key, client_wire.write_fd, false);
            client_closed = true;
        }
        if let Some(skey) = server_key {
            if received.len() == message_len && !server_closed {
                server_table.close(skey, server_wire.write_fd, false);
                server_closed = true;
            }
        }

        if client_closed
            && server_closed
            && client_table.is_closed(client_key)
            && server_key.is_some_and(|k| server_table.is_closed(k))
        {
            break;
        }

        thread::sleep(Duration::from_millis(5));
    }

    assert!(server_key.is_some(), "server connection never completed accept");
    assert_eq!(received.len(), message_len, "data never fully delivered");
    assert_eq!(&received[..], &message[..], "delivered data corrupted");
    assert!(client_table.is_closed(client_key), "client connection never reached CLOSED");
    assert!(
        server_key.is_some_and(|k| server_table.is_closed(k)),
        "server connection never reached CLOSED"
    );

    println!(
        "retransmission_test: drop_rate={:3.0}%  completed OK  (simulated drops: {}, data: \"{}\")",
        drop_rate * 100.0,
        dropped_count,
        String::from_utf8_lossy(&received)
    );

    unsafe {
        libc::close(client_wire.read_fd);
        libc::close(client_wire.write_fd);
        libc::close(server_wire.read_fd);
        libc::close(server_wire.write_fd);
    }
}

#[test]
fn retransmission_under_packet_loss() {
    run_one_trial(0.0);
    run_one_trial(0.10);
    run_one_trial(0.30);
}
