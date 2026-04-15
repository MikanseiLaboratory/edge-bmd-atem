//! RP2040 + W5500 (Embassy): DHCP, ATEM connect, then after `InCm`:
//! - One packet with **`CTTp`** (next Auto transition style) and, if enabled, **`CPvI` / `CPgI`**
//!   (preview/program — **off by default** so routing is not changed unexpectedly).
//! - Periodic **`DAut`** (Auto transition).
//! - Optional one-shot **`FtbA`** after a delay (`FTB_AUTO_DEMO_AFTER_SECS`), optional one **`DCut`**
//!   (`SEND_DEMO_CUT_AFTER_INCM`).
//!
//! Edit `ATEM_IPV4` before flashing. See `README.md` in this directory.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use core::mem::MaybeUninit;
use core::net::Ipv4Addr;

use defmt::*;
use edge_bmd_atem::{
    encode_atom_change_preview_input, encode_atom_change_program_input,
    encode_atom_change_transition_next, encode_atom_do_ftb_auto, encode_atom_do_transition_auto,
    encode_atom_do_transition_cut, AtomIter, AtemControl, AtemPacket, AtemPacketFlags,
    AtemPacketPayload, NextTransitionStyle, ATEM_UDP_PORT,
    Error as PError,
};
use embedded_alloc::LlffHeap;
use embassy_executor::Spawner;
use embassy_futures::select::{select, Either};
use embassy_futures::yield_now;
use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::{Ipv4Address, Stack, StackResources};
use embassy_net_wiznet::chip::W5500;
use embassy_net_wiznet::*;
use embassy_rp::clocks::RoscRng;
use embassy_rp::gpio::{Input, Level, Output, Pull};
use embassy_rp::peripherals::{DMA_CH0, DMA_CH1, SPI0};
use embassy_rp::spi::{Async, Config as SpiConfig, Spi};
use embassy_rp::{bind_interrupts, dma};
use embassy_time::{Delay, Duration, Instant, Timer};
use embedded_hal_bus::spi::ExclusiveDevice;
use static_cell::StaticCell;
use {defmt_rtt as _, panic_probe as _};

/// Heap for `alloc` (required because `edge_bmd_atem` uses the Rust `alloc` crate).
const HEAP_SIZE: usize = 32 * 1024;
static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];

#[global_allocator]
static HEAP: LlffHeap = LlffHeap::empty();

/// ATEM IPv4 (same subnet as DHCP). Change for your network.
const ATEM_IPV4: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 101);

/// Initial BURP session id (client-chosen; necromancer default `0x2970`).
const ATEM_INIT_SID: u16 = 0x2970;

/// Mix effect index for `DoTransitionAuto` (`0` = ME1).
const ATEM_ME_INDEX: u8 = 0;

/// Style for the next **Auto** (`CTTp` / `ChangeTransitionNext`).
const NEXT_AUTO_TRANSITION: NextTransitionStyle = NextTransitionStyle::Mix;

/// If true, sends `CPvI` / `CPgI` once after `InCm` (changes preview/program — use with care).
const SEND_INPUT_CHANGES_AFTER_INCM: bool = false;

/// BMD video source ids when [`SEND_INPUT_CHANGES_AFTER_INCM`] is true (see necromancer `VideoSource`).
const PREVIEW_INPUT: u16 = 2;
const PROGRAM_INPUT: u16 = 1;

/// After `InCm`, send one **`FtbA`** when this many seconds elapse (`0` = never).
const FTB_AUTO_DEMO_AFTER_SECS: u64 = 0;

/// If true, sends one **`DCut`** immediately after the post-InCm atom packet (off by default).
const SEND_DEMO_CUT_AFTER_INCM: bool = false;

/// Seconds between **Auto** (transition) commands while connected.
const AUTO_TRANSITION_INTERVAL_SECS: u64 = 10;

/// After the dump request, wait for switcher `InCm` (necromancer `InitialisationComplete`).
const WAIT_INCM_TIMEOUT_SECS: u64 = 20;

/// How long we `recv` at a time while waiting for `InCm` / between autos (keeps ACKs flowing).
const RX_PUMP_SLICE_MS: u64 = 300;

/// Retransmit **Auto** if no UDP activity shortly after send (best-effort).
const DAUT_RETRANSMIT_ATTEMPTS: u8 = 2;
const DAUT_RETRANSMIT_GAP_MS: u64 = 120;

static RX_META: StaticCell<[PacketMetadata; 4]> = StaticCell::new();
static TX_META: StaticCell<[PacketMetadata; 4]> = StaticCell::new();
static RX_BUF: StaticCell<[u8; 2048]> = StaticCell::new();
static TX_BUF: StaticCell<[u8; 2048]> = StaticCell::new();

bind_interrupts!(struct Irqs {
    DMA_IRQ_0 => dma::InterruptHandler<DMA_CH0>, dma::InterruptHandler<DMA_CH1>;
});

async fn recv_timeout<'s>(
    sock: &'s UdpSocket<'s>,
    buf: &'s mut [u8],
    ms: u64,
) -> Result<(usize, embassy_net::udp::UdpMetadata), embassy_net::udp::RecvError> {
    match select(sock.recv_from(buf), Timer::after_millis(ms)).await {
        Either::First(r) => r,
        Either::Second(()) => Err(embassy_net::udp::RecvError::Truncated),
    }
}

/// Connect + dump; `socket` must already be `bind(0)`.
///
/// Returns `(assigned_session_id, init_sid, switcher_sender_pid_from_ack)`.
///
/// `assigned_session_id` is `ConnectAck`’s session id with `0x8000` set (necromancer
/// `AtemReceiver::initialise`); use it for all post-handshake packets including atoms.
async fn atem_handshake(
    socket: &mut UdpSocket<'static>,
    atem: Ipv4Addr,
    init_sid: u16,
) -> Result<(u16, u16, u16), PError> {
    if !(1..=0x7fff).contains(&init_sid) {
        return Err(PError::UnexpectedState);
    }
    let o = atem.octets();
    let atem_ip = Ipv4Address::new(o[0], o[1], o[2], o[3]);

    let connect = AtemPacket::new_control(
        AtemPacketFlags {
            control: true,
            ..AtemPacketFlags::default()
        },
        init_sid,
        0,
        0xb1,
        0,
        AtemControl::Connect,
    );
    let mut tx = [0u8; 256];
    let n = connect.wire_len();
    connect.write_into(&mut tx[..n])?;
    socket
        .send_to(&tx[..n], (atem_ip, ATEM_UDP_PORT))
        .await
        .map_err(|_| PError::Other("connect send"))?;

    let mut rx = [0u8; 2048];
    let deadline_ms: u64 = 3000;
    let mut waited: u64 = 0;
    const SLICE_MS: u64 = 400;

    let (switcher_pid, session_id) = loop {
        if waited >= deadline_ms {
            return Err(PError::Timeout);
        }
        let remain = (deadline_ms - waited).min(SLICE_MS);
        let (m, _) = recv_timeout(socket, &mut rx, remain)
            .await
            .map_err(|_| PError::Timeout)?;
        waited += remain;
        if m < AtemPacket::HEADER_LEN {
            continue;
        }
        let Ok(pkt) = AtemPacket::decode(&rx[..m]) else {
            continue;
        };
        if pkt.session_id != init_sid {
            continue;
        }
        let Some(AtemControl::ConnectAck { session_id: sid }) = pkt.control() else {
            if matches!(pkt.control(), Some(AtemControl::ConnectNack)) {
                return Err(PError::ConnectRejected);
            }
            continue;
        };
        break (pkt.sender_packet_id, sid | 0x8000);
    };

    let dump_req = AtemPacket::new(
        AtemPacketFlags {
            response: true,
            ..AtemPacketFlags::default()
        },
        init_sid,
        switcher_pid,
        0xd4,
        0,
    );
    let n2 = dump_req.wire_len();
    dump_req.write_into(&mut tx[..n2])?;
    socket
        .send_to(&tx[..n2], (atem_ip, ATEM_UDP_PORT))
        .await
        .map_err(|_| PError::Other("dump send"))?;

    Ok((session_id, init_sid, switcher_pid))
}

#[inline]
fn session_ok(pkt: &AtemPacket, session_id: u16, init_sid: u16, allow_init_sid: bool) -> bool {
    pkt.session_id == session_id || (allow_init_sid && pkt.session_id == init_sid)
}

/// Returns true if payload contains `InCm` (initialisation complete).
fn payload_has_incm(payload: &AtemPacketPayload) -> bool {
    let AtemPacketPayload::Atoms(blob) = payload else {
        return false;
    };
    for a in AtomIter::new(blob) {
        if let Ok(slice) = a {
            if slice.name.0 == *b"InCm" {
                return true;
            }
        }
    }
    false
}

/// Receive / ACK until `deadline`. If `wait_incm`, stop early once `InCm` is seen (returns true).
async fn pump_switcher(
    socket: &mut UdpSocket<'static>,
    atem_ip: Ipv4Address,
    rx: &mut [u8],
    tx: &mut [u8],
    session_id: u16,
    init_sid: u16,
    allow_init_sid: bool,
    deadline: Instant,
    wait_incm: bool,
) -> bool {
    while Instant::now() < deadline {
        let remain = deadline.saturating_duration_since(Instant::now());
        let slice = core::cmp::min(remain.as_millis() as u64, RX_PUMP_SLICE_MS);
        if slice == 0 {
            break;
        }
        let got = recv_timeout(socket, rx, slice).await;
        let Ok((m, _)) = got else {
            continue;
        };
        if m < AtemPacket::HEADER_LEN {
            continue;
        }
        let Ok(pkt) = AtemPacket::decode(&rx[..m]) else {
            continue;
        };
        if !session_ok(&pkt, session_id, init_sid, allow_init_sid) {
            continue;
        }
        if let Some(ack) = pkt.make_ack() {
            let n = ack.wire_len();
            if n <= tx.len() && ack.write_into(&mut tx[..n]).is_ok() {
                let _ = socket.send_to(&tx[..n], (atem_ip, ATEM_UDP_PORT)).await;
            }
        }
        if wait_incm && payload_has_incm(&pkt.payload) {
            return true;
        }
    }
    false
}

#[inline]
fn bump_sender_packet_id(pid: u16) -> u16 {
    if pid >= AtemPacket::MAX_PACKET_ID {
        1
    } else {
        pid + 1
    }
}

/// Build post-`InCm` atom blob: `CTTp` plus optional `CPvI` / `CPgI`.
fn post_incm_config_atoms(out: &mut [u8; 36]) -> usize {
    let mut off = 0;
    let cttp = encode_atom_change_transition_next(ATEM_ME_INDEX, NEXT_AUTO_TRANSITION);
    out[off..off + 12].copy_from_slice(&cttp);
    off += 12;
    if SEND_INPUT_CHANGES_AFTER_INCM {
        let cpvi = encode_atom_change_preview_input(ATEM_ME_INDEX, PREVIEW_INPUT);
        out[off..off + 12].copy_from_slice(&cpvi);
        off += 12;
        let cpgi = encode_atom_change_program_input(ATEM_ME_INDEX, PROGRAM_INPUT);
        out[off..off + 12].copy_from_slice(&cpgi);
        off += 12;
    }
    off
}

fn write_atoms_cmd(
    session_id: u16,
    sender_pid: u16,
    atom_blob: &[u8],
    tx_cmd: &mut [u8],
) -> Result<usize, PError> {
    let pkt = AtemPacket::with_atoms(
        AtemPacketFlags {
            ack: true,
            ..AtemPacketFlags::default()
        },
        session_id,
        0,
        0,
        sender_pid,
        Vec::from(atom_blob),
    );
    let n = pkt.wire_len();
    if n > tx_cmd.len() {
        return Err(PError::InvalidLength);
    }
    pkt.write_into(&mut tx_cmd[..n])?;
    Ok(n)
}

#[embassy_executor::task]
async fn ethernet_task(
    runner: Runner<
        'static,
        W5500,
        ExclusiveDevice<Spi<'static, SPI0, Async>, Output<'static>, Delay>,
        Input<'static>,
        Output<'static>,
    >,
) -> ! {
    runner.run().await
}

#[embassy_executor::task]
async fn net_task(mut runner: embassy_net::Runner<'static, Device<'static>>) -> ! {
    runner.run().await
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    unsafe {
        let base = core::ptr::addr_of_mut!(HEAP_MEM) as usize;
        HEAP.init(base, HEAP_SIZE);
    }

    let p = embassy_rp::init(Default::default());
    let mut spi_cfg = SpiConfig::default();
    spi_cfg.frequency = 50_000_000;
    let (miso, mosi, clk) = (p.PIN_16, p.PIN_19, p.PIN_18);
    let spi = Spi::new(p.SPI0, clk, mosi, miso, p.DMA_CH0, p.DMA_CH1, Irqs, spi_cfg);
    let cs = Output::new(p.PIN_17, Level::High);
    let w5500_int = Input::new(p.PIN_21, Pull::Up);
    let w5500_reset = Output::new(p.PIN_20, Level::High);

    let mac_addr = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00];
    static STATE: StaticCell<State<8, 8>> = StaticCell::new();
    let state = STATE.init(State::new());
    let (device, runner) = embassy_net_wiznet::new(
        mac_addr,
        state,
        ExclusiveDevice::new(spi, cs, Delay).unwrap(),
        w5500_int,
        w5500_reset,
    )
    .await
    .unwrap();

    spawner.spawn(defmt::unwrap!(ethernet_task(runner)));

    let mut rng = RoscRng;
    let seed = rng.next_u64();
    static RESOURCES: StaticCell<StackResources<3>> = StaticCell::new();
    let (stack, runner) = embassy_net::new(
        device,
        embassy_net::Config::dhcpv4(Default::default()),
        RESOURCES.init(StackResources::new()),
        seed,
    );

    spawner.spawn(defmt::unwrap!(net_task(runner)));

    info!("Waiting for DHCP…");
    let cfg = wait_for_config(stack).await;
    info!("IP: {:?}", cfg.address.address());

    let atem = ATEM_IPV4;
    let o = atem.octets();
    let atem_ip = Ipv4Address::new(o[0], o[1], o[2], o[3]);
    info!(
        "ATEM {}:{} — ME{}: CTTp (+ optional CPvI/CPgI) after InCm; DAut every {} s; FtbA demo after {} s (0=off)",
        atem,
        ATEM_UDP_PORT,
        ATEM_ME_INDEX,
        AUTO_TRANSITION_INTERVAL_SECS,
        FTB_AUTO_DEMO_AFTER_SECS
    );

    let mut socket = UdpSocket::new(
        stack,
        RX_META.init([PacketMetadata::EMPTY; 4]),
        RX_BUF.init([0u8; 2048]),
        TX_META.init([PacketMetadata::EMPTY; 4]),
        TX_BUF.init([0u8; 2048]),
    );
    socket.bind(0).unwrap();

    let (session_id, init_sid, _switcher_pid_at_connect) = loop {
        match atem_handshake(&mut socket, atem, ATEM_INIT_SID).await {
            Ok(v) => break v,
            Err(e) => {
                match e {
                    PError::TooShort => warn!("Handshake: too short"),
                    PError::InvalidLength => warn!("Handshake: invalid length"),
                    PError::BadControl => warn!("Handshake: bad control"),
                    PError::Other(msg) => warn!("Handshake: {}", msg),
                    PError::Timeout => warn!("Handshake: timeout"),
                    PError::ConnectRejected => warn!("Handshake: connect rejected"),
                    PError::UnexpectedState => warn!("Handshake: unexpected state"),
                }
                Timer::after_secs(5).await;
            }
        }
    };

    let mut tx_cmd = [0u8; 128];
    let mut rx = [0u8; 2048];

    info!(
        "Connected (session_id=0x{:04x}, init_sid=0x{:04x}); waiting for InCm (up to {} s)…",
        session_id,
        init_sid,
        WAIT_INCM_TIMEOUT_SECS
    );
    let incm_deadline = Instant::now() + Duration::from_secs(WAIT_INCM_TIMEOUT_SECS);
    let got_incm = pump_switcher(
        &mut socket,
        atem_ip,
        &mut rx,
        &mut tx_cmd,
        session_id,
        init_sid,
        true,
        incm_deadline,
        true,
    )
    .await;
    if got_incm {
        info!("Switcher reported InCm (ready for commands).");
    } else {
        warn!("InCm not seen before timeout; continuing anyway.");
    }

    let mut next_sender: u16 = 1;
    let mut atoms_staging = [0u8; 36];
    let post_len = post_incm_config_atoms(&mut atoms_staging);
    match write_atoms_cmd(
        session_id,
        next_sender,
        &atoms_staging[..post_len],
        &mut tx_cmd,
    ) {
        Ok(n) => match socket.send_to(&tx_cmd[..n], (atem_ip, ATEM_UDP_PORT)).await {
            Ok(()) => {
                info!(
                    "Sent post-InCm atoms ({} B) sender_pid={}",
                    post_len, next_sender
                );
                next_sender = bump_sender_packet_id(next_sender);
            }
            Err(_) => warn!("post-InCm atoms: UDP send failed"),
        },
        Err(_) => warn!("post-InCm atoms: encode failed"),
    }

    if SEND_DEMO_CUT_AFTER_INCM {
        let cut = encode_atom_do_transition_cut(ATEM_ME_INDEX);
        match write_atoms_cmd(session_id, next_sender, &cut, &mut tx_cmd) {
            Ok(n) => match socket.send_to(&tx_cmd[..n], (atem_ip, ATEM_UDP_PORT)).await {
                Ok(()) => {
                    info!("Sent demo DCut sender_pid={}", next_sender);
                    next_sender = bump_sender_packet_id(next_sender);
                }
                Err(_) => warn!("demo DCut: UDP send failed"),
            },
            Err(_) => warn!("demo DCut: encode failed"),
        }
    }

    let ready_at = Instant::now();
    let mut ftb_demo_sent = false;
    let mut next_auto = Instant::now() + Duration::from_secs(AUTO_TRANSITION_INTERVAL_SECS);

    loop {
        if FTB_AUTO_DEMO_AFTER_SECS > 0 && !ftb_demo_sent {
            let elapsed = Instant::now().saturating_duration_since(ready_at);
            if elapsed >= Duration::from_secs(FTB_AUTO_DEMO_AFTER_SECS) {
                let ftb = encode_atom_do_ftb_auto(ATEM_ME_INDEX);
                match write_atoms_cmd(session_id, next_sender, &ftb, &mut tx_cmd) {
                    Ok(n) => match socket.send_to(&tx_cmd[..n], (atem_ip, ATEM_UDP_PORT)).await {
                        Ok(()) => {
                            info!("Sent FtbA demo sender_pid={}", next_sender);
                            next_sender = bump_sender_packet_id(next_sender);
                            ftb_demo_sent = true;
                        }
                        Err(_) => warn!("FtbA demo: UDP send failed"),
                    },
                    Err(_) => warn!("FtbA demo: encode failed"),
                }
            }
        }

        pump_switcher(
            &mut socket,
            atem_ip,
            &mut rx,
            &mut tx_cmd,
            session_id,
            init_sid,
            false,
            next_auto,
            false,
        )
        .await;

        let atom = encode_atom_do_transition_auto(ATEM_ME_INDEX);
        // Matches necromancer `handle_queued_command`: `new_atoms` uses assigned
        // `session_id`, `acked_packet_id` / `client_packet_id` = 0, monotonic `sender_packet_id`.
        let send_res = write_atoms_cmd(session_id, next_sender, &atom, &mut tx_cmd);

        match send_res {
            Ok(n) => {
                let mut sent = false;
                for attempt in 0..=DAUT_RETRANSMIT_ATTEMPTS {
                    if attempt > 0 {
                        Timer::after_millis(DAUT_RETRANSMIT_GAP_MS).await;
                    }
                    match socket.send_to(&tx_cmd[..n], (atem_ip, ATEM_UDP_PORT)).await {
                        Ok(()) => {
                            sent = true;
                            if attempt == 0 {
                                info!("Sent Auto (DAut) sender_pid={}", next_sender);
                            } else {
                                info!("Re-sent Auto (DAut) sender_pid={}", next_sender);
                            }
                        }
                        Err(_) => warn!("Auto send failed (UDP) attempt {}", attempt),
                    }
                }
                if sent {
                    next_sender = bump_sender_packet_id(next_sender);
                }
            }
            Err(_) => warn!("Auto encode failed"),
        }

        let post = Instant::now() + Duration::from_millis(400);
        pump_switcher(
            &mut socket,
            atem_ip,
            &mut rx,
            &mut tx_cmd,
            session_id,
            init_sid,
            false,
            post,
            false,
        )
        .await;

        next_auto = Instant::now() + Duration::from_secs(AUTO_TRANSITION_INTERVAL_SECS);
    }
}

async fn wait_for_config(stack: Stack<'static>) -> embassy_net::StaticConfigV4 {
    loop {
        if let Some(config) = stack.config_v4() {
            return config.clone();
        }
        yield_now().await;
    }
}
