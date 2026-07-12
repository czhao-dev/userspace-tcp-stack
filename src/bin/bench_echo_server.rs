//! Benchmark-only TCP echo peer.
//!
//! Unlike `chat_server`, this binary neither logs application payloads nor
//! implements HTTP. It exists so throughput measurements cover MiniTCP and
//! the TUN path rather than terminal I/O.
use std::net::Ipv4Addr;

fn parse_addr(s: &str) -> u32 {
    match s.parse::<Ipv4Addr>() {
        Ok(addr) => u32::from(addr),
        Err(_) => {
            eprintln!("invalid address: {s}");
            std::process::exit(2);
        }
    }
}

fn main() {
    let mut port: u16 = 8080;
    let mut tun_dev = "tun0".to_string();
    let mut self_addr_str = "10.0.0.2".to_string();
    let mut connections: usize = 1;

    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--port" if i + 1 < args.len() => {
                i += 1;
                port = args[i].parse().unwrap_or(port);
            }
            "--tun" if i + 1 < args.len() => {
                i += 1;
                tun_dev = args[i].clone();
            }
            "--addr" if i + 1 < args.len() => {
                i += 1;
                self_addr_str = args[i].clone();
            }
            "--connections" if i + 1 < args.len() => {
                i += 1;
                connections = args[i].parse().unwrap_or(connections);
            }
            _ => {}
        }
        i += 1;
    }

    let self_addr = parse_addr(&self_addr_str);
    let mut stack = match minitcp::Stack::init(&tun_dev, self_addr, false) {
        Some(stack) => stack,
        None => {
            eprintln!("minitcp_init: {}", std::io::Error::last_os_error());
            std::process::exit(1);
        }
    };

    let listener = stack.socket();
    if !stack.listen(listener, port) {
        eprintln!("failed to listen on {self_addr_str}:{port}");
        std::process::exit(1);
    }

    for _ in 0..connections {
        let (Some(conn), _) = stack.accept(listener) else {
            continue;
        };
        let mut buf = [0u8; 16 * 1024];
        loop {
            let received = stack.recv(conn, &mut buf);
            if received <= 0 {
                break;
            }

            let mut sent = 0;
            while sent < received as usize {
                let n = stack.send(conn, &buf[sent..received as usize]);
                if n <= 0 {
                    break;
                }
                sent += n as usize;
            }
            if sent != received as usize {
                break;
            }
        }
        stack.close(conn);
    }

    stack.close(listener);
}
