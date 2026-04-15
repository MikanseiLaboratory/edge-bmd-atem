//! Host example: UDP handshake with an ATEM switcher (same flow as [`edge_bmd_atem::AtemSession::connect`]).
//!
//! ```text
//! cargo run --example std_handshake --features std -- 192.168.1.240
//! cargo run --example std_handshake --features std -- --verbose 192.168.1.240
//! cargo run --example std_handshake --features std -- --listen-ms 2000 192.168.1.240
//! cargo run --example std_handshake --features std -- --help
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

use clap::Parser;
use edge_bmd_atem::io::{ErrorType, UdpReceive, UdpReceiveBounded, UdpSend};
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

impl UdpReceiveBounded for TokioUdp {
    async fn receive_for(
        &mut self,
        buffer: &mut [u8],
        timeout_ms: u32,
    ) -> Result<Option<(usize, SocketAddr)>, Self::Error> {
        let dur = std::time::Duration::from_millis(u64::from(timeout_ms.max(1)));
        match tokio::time::timeout(dur, self.sock.recv_from(buffer)).await {
            Ok(Ok(v)) => Ok(Some(v)),
            Ok(Err(e)) => Err(e),
            Err(_) => Ok(None),
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "std_handshake",
    version,
    about = "ATEM UDP connect handshake (uses AtemSession::connect)",
    after_long_help = "Environment (when not overridden by CLI):\n  ATEM_ADDR       if ADDR is omitted\n  ATEM_INIT_SID   initial session id, hex or decimal [default: 0x2970]\n  ATEM_TIMEOUT_MS handshake wait [default: 3000]\n  ATEM_LISTEN_MS  post-handshake recv window if --listen-ms omitted\n  ATEM_VERBOSE    1/true/yes/on enables verbose with or without -v"
)]
struct Cli {
    /// host:port or IP (port defaults to 9910). Omit if `ATEM_ADDR` is set.
    #[arg(value_name = "ADDR")]
    addr: Option<String>,

    /// Log local bind, config, and unexpected UDP sources.
    #[arg(short, long)]
    verbose: bool,

    /// After handshake OK, recv and print packets for this many milliseconds.
    #[arg(long, value_name = "MS")]
    listen_ms: Option<u64>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let verbose = cli.verbose || env_flag_truthy("ATEM_VERBOSE");
    let listen_ms = cli.listen_ms.or(parse_listen_ms_env()?).unwrap_or(0);

    let atem = parse_atem_addr(cli.addr.as_deref())?;
    let init_sid = parse_init_sid()?;
    let timeout_ms = parse_timeout_ms()?;

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

    let t0 = std::time::Instant::now();
    let session = AtemSession::connect(
        &mut udp,
        atem,
        init_sid,
        SessionConfig {
            init_timeout_ms: timeout_ms,
            ..SessionConfig::default()
        },
        || t0.elapsed().as_millis() as u32,
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

fn parse_atem_addr(addr_arg: Option<&str>) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let arg = addr_arg
        .map(str::to_owned)
        .or_else(|| env::var("ATEM_ADDR").ok())
        .ok_or("missing address: pass ADDR or set ATEM_ADDR (see --help)")?;

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
