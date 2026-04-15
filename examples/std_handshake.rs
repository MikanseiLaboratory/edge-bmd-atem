//! Host example: UDP handshake with an ATEM switcher (same flow as [`edge_bmd_atem::AtemSession::connect`]).
//!
//! ```text
//! cargo run --example std_handshake --features std -- 192.168.1.240
//! cargo run --example std_handshake --features std -- --verbose 192.168.1.240
//! cargo run --example std_handshake --features std -- --listen-ms=2000 192.168.1.240
//! ```
//!
//! Address: first positional argument or `ATEM_ADDR` (e.g. `192.168.1.240:9910`).
//!
//! Optional environment:
//! - `ATEM_INIT_SID` — initial session id (`0x2970` or decimal), default `0x2970`
//! - `ATEM_TIMEOUT_MS` — handshake timeout, default `3000`
//! - `ATEM_LISTEN_MS` — after connect, print incoming packets until this many ms elapse (default `0`)

use core::net::SocketAddr;
use std::env;
use std::io;
use std::str::FromStr as _;
use std::time::Duration;

use edge_bmd_atem::io::{ErrorType, UdpReceive, UdpSend};
use edge_bmd_atem::{
    AtemControl, AtemPacket, AtemPacketPayload, AtemSession, SessionConfig, ATEM_UDP_PORT,
};
use tokio::net::UdpSocket;

struct TokioUdp {
    sock: UdpSocket,
}

impl TokioUdp {
    async fn bind_any() -> io::Result<Self> {
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        Ok(Self { sock })
    }

    fn socket(&self) -> &UdpSocket {
        &self.sock
    }
}

impl ErrorType for TokioUdp {
    type Error = io::Error;
}

impl UdpSend for TokioUdp {
    async fn send(&mut self, remote: SocketAddr, data: &[u8]) -> Result<(), Self::Error> {
        self.sock.send_to(data, remote).await?;
        Ok(())
    }
}

impl UdpReceive for TokioUdp {
    async fn receive(&mut self, buffer: &mut [u8]) -> Result<(usize, SocketAddr), Self::Error> {
        self.sock.recv_from(buffer).await
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let Cli { verbose, listen_ms } = parse_cli()?;

    let atem = parse_atem_addr()?;
    let init_sid = parse_init_sid()?;
    let timeout_ms = parse_timeout_ms()?;
    let listen_ms = listen_ms.or(parse_listen_ms_env()?).unwrap_or(0);

    if verbose {
        eprintln!(
            "config: remote={atem}, init_sid=0x{init_sid:04x}, handshake_timeout_ms={timeout_ms}, listen_ms={listen_ms}"
        );
    }

    println!("Connecting to ATEM at {atem}…");

    let mut udp = TokioUdp::bind_any().await?;
    if verbose {
        eprintln!("bound local {}", udp.socket().local_addr()?);
    }

    let session = AtemSession::connect(
        &mut udp,
        atem,
        init_sid,
        SessionConfig {
            init_timeout_ms: timeout_ms,
            ..SessionConfig::default()
        },
    )
    .await?;

    println!(
        "OK: session_id=0x{:04x}, initial_session_id=0x{:04x}, switcher_pid={}",
        session.state.session_id,
        session.state.initial_session_id,
        session.state.switcher_packet_id_at_connect
    );

    if listen_ms > 0 {
        println!("Listening for post-handshake datagrams ({listen_ms} ms)…");
        drain_incoming(udp.socket(), atem, listen_ms, verbose).await?;
    }

    Ok(())
}

struct Cli {
    verbose: bool,
    listen_ms: Option<u64>,
}

fn parse_cli() -> Result<Cli, Box<dyn std::error::Error>> {
    let mut verbose = env_flag_truthy("ATEM_VERBOSE");
    let mut listen_ms: Option<u64> = None;
    let mut positional: Vec<String> = Vec::new();

    for a in env::args().skip(1) {
        match a.as_str() {
            "-h" | "--help" | "help" => {
                print_help();
                std::process::exit(0);
            }
            "-v" | "--verbose" => verbose = true,
            s if s.starts_with("--listen-ms=") => {
                listen_ms = Some(
                    s["--listen-ms=".len()..]
                        .parse()
                        .map_err(|_| "invalid --listen-ms value")?,
                );
            }
            s if s == "--listen-ms" => {
                return Err("expected --listen-ms=<u64>".into());
            }
            _ if a.starts_with('-') => {
                return Err(format!("unknown flag: {a}").into());
            }
            _ => positional.push(a),
        }
    }

    if let Some(first) = positional.first() {
        env::set_var("ATEM_ADDR", first);
    }

    Ok(Cli { verbose, listen_ms })
}

fn print_help() {
    eprintln!(
        "\
std_handshake — ATEM UDP connect handshake (uses AtemSession::connect)

USAGE:
    cargo run --example std_handshake --features std -- [OPTIONS] <ADDR>
    cargo run --example std_handshake --features std -- [OPTIONS]   (uses ATEM_ADDR)

OPTIONS:
    -v, --verbose       Log local bind, config, unexpected UDP sources
    --listen-ms=<N>     After OK, recv/print packets for N milliseconds
    -h, --help          This help

ENVIRONMENT:
    ATEM_ADDR          host:port or IP (port defaults to {ATEM_UDP_PORT})
    ATEM_INIT_SID      initial session id, hex (0x2970) or decimal [default: 0x2970]
    ATEM_TIMEOUT_MS    handshake timeout [default: 3000]
    ATEM_LISTEN_MS     same as --listen-ms when flag omitted
    ATEM_VERBOSE       set to 1/true/yes to enable verbose
"
    );
}

fn env_flag_truthy(name: &str) -> bool {
    env::var(name)
        .ok()
        .map(|v| {
            matches!(
                v.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn parse_atem_addr() -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let arg = env::var("ATEM_ADDR").map_err(|_| {
        "missing address: pass <IP|host:port> or set ATEM_ADDR (see --help)"
    })?;

    if let Ok(a) = SocketAddr::from_str(&arg) {
        return Ok(a);
    }
    let ip = core::net::IpAddr::from_str(&arg)?;
    Ok(SocketAddr::new(ip, ATEM_UDP_PORT))
}

fn parse_init_sid() -> Result<u16, Box<dyn std::error::Error>> {
    let raw = env::var("ATEM_INIT_SID").unwrap_or_else(|_| "0x2970".into());
    let v = if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        u16::from_str_radix(hex, 16).map_err(|_| "ATEM_INIT_SID: invalid hex u16")?
    } else {
        raw.parse::<u16>()
            .map_err(|_| "ATEM_INIT_SID: expected u16 or 0x-prefixed hex")?
    };
    if !(1..=0x7fff).contains(&v) {
        return Err("ATEM_INIT_SID must be in 1..=0x7fff".into());
    }
    Ok(v)
}

fn parse_timeout_ms() -> Result<u32, Box<dyn std::error::Error>> {
    let raw = env::var("ATEM_TIMEOUT_MS").unwrap_or_else(|_| "3000".into());
    let v: u32 = raw
        .parse()
        .map_err(|_| "ATEM_TIMEOUT_MS: expected positive u32")?;
    if v == 0 {
        return Err("ATEM_TIMEOUT_MS must be >= 1".into());
    }
    Ok(v)
}

fn parse_listen_ms_env() -> Result<Option<u64>, Box<dyn std::error::Error>> {
    let Ok(raw) = env::var("ATEM_LISTEN_MS") else {
        return Ok(None);
    };
    let v: u64 = raw
        .parse()
        .map_err(|_| "ATEM_LISTEN_MS: expected u64 milliseconds")?;
    Ok(Some(v))
}

async fn drain_incoming(
    sock: &UdpSocket,
    expected: SocketAddr,
    total_ms: u64,
    verbose: bool,
) -> io::Result<()> {
    let mut buf = [0u8; 2048];
    let deadline = tokio::time::Instant::now() + Duration::from_millis(total_ms.max(1));
    let mut n_pkt = 0usize;

    while tokio::time::Instant::now() < deadline {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            break;
        }
        let recv = sock.recv_from(&mut buf);
        let r = tokio::time::timeout(left, recv).await;
        let Ok(Ok((n, src))) = r else {
            break;
        };
        if src != expected {
            if verbose {
                eprintln!("recv: unexpected source {src} (expected {expected}), len={n}");
            }
            continue;
        }
        n_pkt += 1;
        match AtemPacket::decode(&buf[..n]) {
            Ok(pkt) => println!("recv[{n_pkt}]: {}", summarize_packet(&pkt)),
            Err(e) => {
                if verbose {
                    println!("recv[{n_pkt}]: {n} bytes from {src}, decode error: {e}");
                } else {
                    println!("recv[{n_pkt}]: {n} bytes (non-ATEM or truncated)");
                }
            }
        }
    }

    if n_pkt == 0 {
        println!("(no datagrams received in window)");
    }
    Ok(())
}

fn summarize_packet(pkt: &AtemPacket) -> String {
    let flags = &pkt.flags;
    let fl = format!(
        "ack={} ctl={} rsp={} retr={} hello={}",
        flags.ack, flags.control, flags.response, flags.retransmission, flags.hello
    );
    let payload = match &pkt.payload {
        AtemPacketPayload::None => "none".into(),
        AtemPacketPayload::Control(c) => match c {
            AtemControl::Connect => "ctl:Connect".into(),
            AtemControl::ConnectAck { session_id } => {
                format!("ctl:ConnectAck(session_id={session_id})")
            }
            AtemControl::ConnectNack => "ctl:ConnectNack".into(),
            AtemControl::Disconnect => "ctl:Disconnect".into(),
            AtemControl::DisconnectAck => "ctl:DisconnectAck".into(),
        },
        AtemPacketPayload::Atoms(b) => format!("atoms:{}B", b.len()),
    };
    format!(
        "session_id=0x{:04x} acked_pid={} client_pid={} sender_pid={} flags({fl}) {payload}",
        pkt.session_id, pkt.acked_packet_id, pkt.client_packet_id, pkt.sender_packet_id,
    )
}
