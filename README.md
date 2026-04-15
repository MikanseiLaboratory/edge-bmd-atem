# edge-bmd-atem

Blackmagic Design ATEM control protocol (UDP / BURP) for embedded Rust, aligned with [edge-net](https://github.com/sysgrok/edge-net) / Embassy style stacks.

## Layout

- `#![no_std]` + `alloc` library: UDP traits in [`io`](src/io.rs), packet codec, session helpers.
- Enable **`std`** for Tokio-based unit tests and [`AtemSession::connect`](src/session.rs).

## Build

```sh
cargo check
cargo test --features std
```

## ATEM on a microcontroller

1. Implement [`edge_bmd_atem::io::UdpSend`](src/io.rs) and [`UdpReceive`](src/io.rs) for your stack (for example wrap `edge-nal-embassy` types in a newtype and delegate; API matches `edge-nal` 0.6).
2. Call [`AtemPacket::decode`](src/packet.rs) / [`write_into`](src/packet.rs) for framing, or use [`AtemSession`](src/session.rs) on **host** (`std` feature) while iterating on-device wiring.

Default UDP port: [`ATEM_UDP_PORT`](src/lib.rs) (9910).

## License

Apache-2.0. See `NOTICE` for necromancer-derived protocol notes.
