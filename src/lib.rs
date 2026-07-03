//! MiniTCP: a user-space TCP/IP stack over a TUN device.
//!
//! Layering mirrors the original C++ implementation:
//! application -> [`stack::Stack`] socket API -> [`tcp`] / [`udp`] ->
//! [`icmp`] -> [`ip`] -> [`tun`] -> kernel routing -> the real network.

pub mod icmp;
pub mod ip;
pub mod stack;
pub mod tcp;
pub mod tun;
pub mod udp;

pub use stack::{SockOpt, SocketId, Stack, TIMEOUT};
