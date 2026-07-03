//! Minimal chat server built entirely on the `Stack` socket API — no
//! direct access to TCP internals. Doubles as the curl
//! cross-validation target: any request that looks like an HTTP verb
//! gets a canned 200 OK instead of being echoed as chat.
use std::io::Write;
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

fn looks_like_http(buf: &[u8]) -> bool {
    buf.len() >= 4 && matches!(&buf[..4], b"GET " | b"POST" | b"HEAD" | b"PUT ")
}

fn main() {
    let mut port: u16 = 8080;
    let mut tun_dev = "tun0".to_string();
    let mut self_addr_str = "10.0.0.2".to_string();
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
            "--trace" => trace = true,
            _ => {}
        }
        i += 1;
    }

    let self_addr = parse_addr(&self_addr_str);
    let mut stack = match minitcp::Stack::init(&tun_dev, self_addr, trace) {
        Some(s) => s,
        None => {
            eprintln!("minitcp_init: {}", std::io::Error::last_os_error());
            std::process::exit(1);
        }
    };

    let listener = stack.socket();
    stack.listen(listener, port);
    println!("chat_server: listening on port {port} (self={self_addr_str}, tun={tun_dev})");

    loop {
        let (conn, _timed_out) = stack.accept(listener);
        let Some(conn) = conn else { continue };
        println!("chat_server: client connected");

        let mut buf = [0u8; 4096];
        loop {
            let n = stack.recv(conn, &mut buf);
            if n <= 0 {
                break;
            }
            let n = n as usize;
            if looks_like_http(&buf[..n]) {
                const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nhello\n";
                stack.send(conn, RESPONSE);
                break;
            }
            std::io::stdout().write_all(&buf[..n]).ok();
            std::io::stdout().flush().ok();
            stack.send(conn, &buf[..n]); // echo back as the "chat"
        }

        println!("chat_server: client disconnected");
        stack.close(conn);
    }
}
