//! Exercises `Stack::setsockopt`/get_* end to end, including
//! SO_RCVTIMEO actually causing a blocking call to return instead of
//! hanging forever. Uses `Stack::init_with_fd()` with a socketpair
//! standing in for the TUN fd (the same technique
//! `tests/retransmission.rs` uses for TCP), since `Stack::init()` opens
//! a real TUN device and needs root/CAP_NET_ADMIN, which a test
//! sandbox doesn't have.
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::unix::io::RawFd;
use std::time::{Duration, Instant};

use minitcp::{SockOpt, Stack, TIMEOUT};

const SELF_ADDR: u32 = 0x0A0C_0001; // 10.12.0.1

fn make_socketpair() -> (RawFd, RawFd) {
    let mut fds = [0 as RawFd; 2];
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
    assert_eq!(rc, 0, "socketpair failed: {}", std::io::Error::last_os_error());
    (fds[0], fds[1])
}

#[test]
fn so_rcvtimeo_actually_times_out() {
    let (fd0, fd1) = make_socketpair();
    let mut stack = Stack::init_with_fd(fd0, SELF_ADDR, false);

    let sock = stack.udp_socket();
    let addr = SocketAddrV4::new(Ipv4Addr::from(SELF_ADDR), 9000);
    assert!(stack.bind(sock, addr));

    assert!(stack.setsockopt(sock, SockOpt::RcvTimeo(Duration::from_millis(200))));

    let mut buf = [0u8; 64];
    let start = Instant::now();
    let (n, _src) = stack.recvfrom(sock, &mut buf);
    let elapsed = start.elapsed();

    assert_eq!(n, TIMEOUT);
    assert!(elapsed < Duration::from_secs(2));

    stack.close(sock);
    unsafe {
        libc::close(fd0);
        libc::close(fd1);
    }
}

#[test]
fn getsockopt_round_trip() {
    let (fd0, fd1) = make_socketpair();
    let mut stack = Stack::init_with_fd(fd0, SELF_ADDR, false);

    let sock = stack.udp_socket();

    assert!(stack.setsockopt(sock, SockOpt::ReuseAddr(true)));
    assert!(stack.get_reuse_addr(sock));

    assert!(stack.setsockopt(sock, SockOpt::RcvBuf(32768)));
    assert_eq!(stack.get_rcvbuf(sock), 32768);

    assert!(stack.setsockopt(sock, SockOpt::SndBuf(16384)));
    assert_eq!(stack.get_sndbuf(sock), 16384);

    // Unlike the original's raw (level, optname, void*) signature,
    // SockOpt is a closed enum: an "unsupported option" can't even be
    // constructed, so the type system enforces what the original
    // checked at runtime. A zero RcvBuf/SndBuf is the one remaining
    // runtime-rejectable case (an invalid value for a supported option).
    assert!(!stack.setsockopt(sock, SockOpt::RcvBuf(0)));

    stack.close(sock);
    unsafe {
        libc::close(fd0);
        libc::close(fd1);
    }
}
