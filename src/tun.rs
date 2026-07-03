//! Linux-only TUN device access: opens `/dev/net/tun` and configures it
//! via `ioctl(TUNSETIFF)`. This will not work on macOS at runtime (no
//! `/dev/net/tun`, no `TUNSETIFF` — macOS uses the entirely different
//! `utun` control-socket mechanism), matching the original C++'s
//! Linux-only design; development happens inside the project's Docker
//! container (see docker/Dockerfile), which runs a real Linux kernel.
//!
//! `libc` doesn't cover `linux/if_tun.h`, so `IFF_TUN`/`IFF_NO_PI`/
//! `TUNSETIFF` and the `ifreq` layout are hand-defined here, mirroring
//! what the C++ version got from `<linux/if.h>`/`<linux/if_tun.h>`.

use std::ffi::CString;
use std::os::unix::io::RawFd;

const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;
// _IOW('T', 202, int) — see linux/if_tun.h. The kernel encodes this
// ioctl's size as sizeof(int) even though the real argument is a
// larger `struct ifreq*`; that's a long-standing quirk of the kernel
// header, not something we need to correct here.
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;

/// Mirrors Linux's `struct ifreq`. Only `ifr_name` and the
/// (`ifr_flags`-aliased) first two bytes of the trailing union are
/// ever read or written by this module, but the struct must still
/// match the kernel's full 40-byte size (16-byte name + 24-byte union
/// on x86_64/aarch64 Linux): `ioctl(TUNSETIFF)` copies a full
/// `struct ifreq` out of our buffer, so an undersized struct here
/// would let the kernel read past the end of it.
#[repr(C)]
struct Ifreq {
    ifr_name: [libc::c_char; libc::IFNAMSIZ],
    ifr_flags: libc::c_short,
    _pad: [u8; 22],
}

/// Opens (or attaches to) the named TUN device and configures it via
/// `ioctl(TUNSETIFF)` with `IFF_TUN | IFF_NO_PI` (raw IP packets, no
/// 4-byte packet-info prefix). `dev_name`: desired interface name
/// (e.g. "tun0"); pass an empty string to let the kernel auto-assign a
/// name, in which case `dev_name` is updated with the assigned name on
/// return. Returns the open file descriptor, or -1 on failure (check
/// `std::io::Error::last_os_error()`).
pub fn tun_alloc(dev_name: &mut String) -> RawFd {
    let path = CString::new("/dev/net/tun").unwrap();
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR) };
    if fd < 0 {
        return -1;
    }

    let mut ifr: Ifreq = unsafe { std::mem::zeroed() };
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if !dev_name.is_empty() {
        let bytes = dev_name.as_bytes();
        let n = bytes.len().min(libc::IFNAMSIZ - 1);
        for (i, &b) in bytes[..n].iter().enumerate() {
            ifr.ifr_name[i] = b as libc::c_char;
        }
    }

    let res = unsafe { libc::ioctl(fd, TUNSETIFF as _, &mut ifr) };
    if res < 0 {
        unsafe { libc::close(fd) };
        return -1;
    }

    let name_bytes: Vec<u8> = ifr
        .ifr_name
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    *dev_name = String::from_utf8_lossy(&name_bytes).into_owned();

    fd
}

/// Reads one raw IP packet from the TUN fd into `buf`. Returns number
/// of bytes read, 0 on EOF, or -1 on error.
pub fn tun_read(fd: RawFd, buf: &mut [u8]) -> isize {
    unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) }
}

/// Writes one raw IP packet (header + payload, already serialized) to
/// the TUN fd. Returns number of bytes written, or -1 on error.
pub fn tun_write(fd: RawFd, buf: &[u8]) -> isize {
    unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) }
}
