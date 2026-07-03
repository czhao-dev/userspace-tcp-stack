//! Bare protocol demo: responds to ICMP echo requests and auto-echoes
//! UDP datagrams sent to any unbound port. Registers no TCP listener
//! or UDP bind of its own (that's what chat_server/chat_client are
//! for) — this binary just runs the raw dispatch loop.

fn main() {
    let mut trace = false;
    let dev_name = "tun0".to_string();

    for arg in std::env::args().skip(1) {
        if arg == "--trace" {
            trace = true;
        }
    }

    let mut stack = match minitcp::Stack::init(&dev_name, 0, trace) {
        Some(s) => s,
        None => {
            eprintln!("tun_alloc: {}", std::io::Error::last_os_error());
            std::process::exit(1);
        }
    };
    println!(
        "MiniTCP listening on {dev_name}{}",
        if trace { " (trace enabled)" } else { "" }
    );

    // Poll with a timeout (rather than blocking forever on a raw read)
    // so TCP's retransmission timers and TIME_WAIT expiry keep running
    // even when no packets are arriving. pump_once() does exactly this.
    loop {
        stack.pump_once(200);
    }
}
