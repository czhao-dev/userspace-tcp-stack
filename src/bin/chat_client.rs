//! Minimal chat client built entirely on the `Stack` socket API. Reads
//! lines from stdin, sends each to chat_server, prints the echoed
//! reply. Runs on its own TUN device (default tun1) so it can
//! genuinely connect to chat_server (on tun0) through the kernel's own
//! IP forwarding between the two — a real two-party conversation over
//! our own TCP implementation, not just against external tools.
use std::io::{self, BufRead, Write};
use std::net::Ipv4Addr;

fn parse_addr(s: &str) -> u32 {
    match s.parse::<Ipv4Addr>() {
        Ok(a) => u32::from(a),
        Err(_) => {
            eprintln!("invalid address: {s}");
            std::process::exit(1);
        }
    }
}

fn main() {
    let mut port: u16 = 8080;
    let mut tun_dev = "tun1".to_string();
    let mut self_addr_str = "10.0.1.2".to_string();
    let mut server_addr_str = "10.0.0.2".to_string();
    let mut trace = false;

    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--port" if i + 1 < args.len() => {
                i += 1;
                port = args[i].parse().unwrap_or(8080);
            }
            "--tun" if i + 1 < args.len() => {
                i += 1;
                tun_dev = args[i].clone();
            }
            "--addr" if i + 1 < args.len() => {
                i += 1;
                self_addr_str = args[i].clone();
            }
            "--server" if i + 1 < args.len() => {
                i += 1;
                server_addr_str = args[i].clone();
            }
            "--trace" => trace = true,
            _ => {}
        }
        i += 1;
    }

    let self_addr = parse_addr(&self_addr_str);
    let server_addr = parse_addr(&server_addr_str);

    let mut stack = match minitcp::Stack::init(&tun_dev, self_addr, trace) {
        Some(s) => s,
        None => {
            eprintln!("minitcp_init: {}", io::Error::last_os_error());
            std::process::exit(1);
        }
    };

    let sock = stack.socket();
    if !stack.connect(sock, server_addr, port) {
        eprintln!("chat_client: failed to connect to {server_addr_str}:{port}");
        std::process::exit(1);
    }
    println!("chat_client: connected to {server_addr_str}:{port} -- type messages, Ctrl+D to quit");

    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let Ok(mut line) = line else { break };
        line.push('\n');
        stack.send(sock, line.as_bytes());

        let mut buf = [0u8; 2048];
        let n = stack.recv(sock, &mut buf);
        if n <= 0 {
            println!("chat_client: server closed the connection");
            break;
        }
        io::stdout().write_all(&buf[..n as usize]).ok();
        io::stdout().flush().ok();
    }

    stack.close(sock);
}
