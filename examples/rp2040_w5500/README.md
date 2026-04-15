# RP2040 + W5500 (Embassy) ATEM handshake

Firmware sample for [WIZnet W5500-EVB-Pico](https://docs.wiznet.io/Product/iEthernet/W5500/w5500-evb-pico) (same pinout as Embassy’s `ethernet_w5500_udp` example).

## What it does

- Brings up W5500 via SPI, runs DHCP, then performs the same UDP handshake as [`std_handshake`](../../examples/std_handshake.rs) using [`edge_bmd_atem`](../../) packet types and `io::UdpSend` / `UdpReceive` implemented on `embassy_net::udp::UdpSocket`.

## Build / flash

Install the `thumbv6m-none-eabi` target and a probe (`probe-rs` or `cargo-embed`).

```sh
cd examples/rp2040_w5500
cargo build --release
```

Flash/run (when `.cargo/config.toml` `runner` is set):

```sh
cargo run --release
```

## Configure ATEM address

Edit `ATEM_IPV4` in `src/main.rs` to your switcher’s IPv4 (same subnet as DHCP).

## Pins (W5500-EVB-Pico)

| Signal   | GPIO |
|----------|------|
| SPI CLK  | 18   |
| SPI MOSI | 19   |
| SPI MISO | 16   |
| CS       | 17   |
| INT      | 21   |
| RST      | 20   |
| SPI      | SPI0 |

Adjust in `main.rs` if your board differs.
