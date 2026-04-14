//! Host example: UDP handshake with an ATEM switcher (same flow as [`edge_bmd_atem::AtemSession::connect`]).
//!
//! ```text
//! cargo run --example std_handshake --features std -- 192.168.1.240
//! ```
//!
//! Or set `ATEM_ADDR` (e.g. `192.168.1.240:9910`).

use core::net::SocketAddr;
use std::env;
use std::io;
use std::str::FromStr as _;

use edge_bmd_atem::io::{ErrorType, UdpReceive, UdpSend};
use edge_bmd_atem::{AtemSession, SessionConfig, ATEM_UDP_PORT};
use tokio::net::UdpSocket;

struct TokioUdp {
    sock: UdpSocket,
}

impl TokioUdp {
    async fn bind_any() -> io::Result<Self> {
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        Ok(Self { sock })
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
    let atem = parse_atem_addr()?;
    println!("Connecting to ATEM at {atem}…");

    let mut udp = TokioUdp::bind_any().await?;
    let init_sid: u16 = 0x2970;

    let session = AtemSession::connect(
        &mut udp,
        atem,
        init_sid,
        SessionConfig {
            init_timeout_ms: 3_000,
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
    Ok(())
}

fn parse_atem_addr() -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let arg = env::args()
        .nth(1)
        .or_else(|| env::var("ATEM_ADDR").ok())
        .ok_or("usage: std_handshake <IP>   or   ATEM_ADDR=host:port")?;

    if let Ok(a) = SocketAddr::from_str(&arg) {
        return Ok(a);
    }
    let ip = core::net::IpAddr::from_str(&arg)?;
    Ok(SocketAddr::new(ip, ATEM_UDP_PORT))
}
