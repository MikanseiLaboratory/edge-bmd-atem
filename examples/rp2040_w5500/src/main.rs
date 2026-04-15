//! RP2040 + W5500 (Embassy): DHCP then ATEM UDP handshake (W5500-EVB-Pico pinout).
//!
//! Edit `ATEM_IPV4` before flashing. See `README.md` in this directory.

#![no_std]
#![no_main]

use core::mem::MaybeUninit;
use core::net::Ipv4Addr;

use defmt::*;
use edge_bmd_atem::{
    AtemControl, AtemPacket, AtemPacketFlags, ATEM_UDP_PORT, Error as PError,
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
use embassy_time::{Delay, Timer};
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

/// Seconds between automatic handshake attempts (Connect + dump, same as one-shot demo).
const AUTO_HANDSHAKE_INTERVAL_SECS: u64 = 30;

fn random_init_sid(rng: &mut RoscRng) -> u16 {
    let v = (rng.next_u32() & 0x7fff) as u16;
    if v == 0 { 0x2970 } else { v }
}

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

async fn atem_handshake(stack: Stack<'static>, atem: Ipv4Addr, init_sid: u16) -> Result<(u16, u16), PError> {
    if !(1..=0x7fff).contains(&init_sid) {
        return Err(PError::UnexpectedState);
    }
    let o = atem.octets();
    let atem_ip = Ipv4Address::new(o[0], o[1], o[2], o[3]);

    static RX_META: StaticCell<[PacketMetadata; 4]> = StaticCell::new();
    static TX_META: StaticCell<[PacketMetadata; 4]> = StaticCell::new();
    static RX_BUF: StaticCell<[u8; 2048]> = StaticCell::new();
    static TX_BUF: StaticCell<[u8; 2048]> = StaticCell::new();

    let mut socket = UdpSocket::new(
        stack,
        RX_META.init([PacketMetadata::EMPTY; 4]),
        RX_BUF.init([0u8; 2048]),
        TX_META.init([PacketMetadata::EMPTY; 4]),
        TX_BUF.init([0u8; 2048]),
    );
    socket.bind(0).map_err(|_| PError::UnexpectedState)?;

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
        let (m, _) = recv_timeout(&socket, &mut rx, remain)
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

    Ok((session_id, init_sid))
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
    let mut rng = RoscRng;

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
    info!("ATEM target: {}:{}", atem, ATEM_UDP_PORT);

    match atem_handshake(stack, atem, 0x2970).await {
        Ok((sid, init)) => {
            info!("Handshake OK: session_id=0x{:04x}, init=0x{:04x}", sid, init);
        }
        Err(e) => match e {
            PError::TooShort => warn!("Handshake failed: too short"),
            PError::InvalidLength => warn!("Handshake failed: invalid length"),
            PError::BadControl => warn!("Handshake failed: bad control"),
            PError::Other(msg) => warn!("Handshake failed: {}", msg),
            PError::Timeout => warn!("Handshake failed: timeout"),
            PError::ConnectRejected => warn!("Handshake failed: connect rejected"),
            PError::UnexpectedState => warn!("Handshake failed: unexpected state"),
        },
    }

    loop {
        Timer::after_secs(60).await;
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
