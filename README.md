# edge-bmd-atem

Blackmagic Design ATEM control protocol (UDP / BURP) for embedded Rust, aligned with [edge-net](https://github.com/sysgrok/edge-net) / Embassy style stacks.

## Layout

- `#![no_std]` + `alloc` library: UDP traits in [`io`](src/io.rs), packet codec, session helpers.
- Enable **`std`** for Tokio-based unit tests and the `std_handshake` example.

## Build

```sh
cargo check
cargo test --features std
```

## ATEM on a microcontroller

1. Implement [`UdpSend`](src/io.rs), [`UdpReceive`](src/io.rs), and [`UdpReceiveBounded`](src/io.rs) for your stack (for example wrap `edge-nal-embassy` types in a newtype and delegate; API matches `edge-nal` 0.6). `UdpReceiveBounded` is typically `select(recv, timer)` on the wait slice.
2. Call [`AtemPacket::decode`](src/packet.rs) / [`write_into`](src/packet.rs) for framing, or [`AtemSession::connect`](src/session.rs) with a monotonic `now_ms` closure.

Default UDP port: [`ATEM_UDP_PORT`](src/lib.rs) (9910).

## License

Apache-2.0. See `NOTICE` for necromancer-derived protocol notes.
