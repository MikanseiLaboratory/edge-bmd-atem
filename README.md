# edge-bmd-atem — **ARCHIVED**

> **This crate is archived. Development continues in
> [`MikanseiLaboratory/embassy-bmd-atem`](https://github.com/MikanseiLaboratory/embassy-bmd-atem).**
>
> The UDP/BURP implementation that lived here is now `embassy_bmd_atem::udp`, and the
> same crate also implements the ATEM **USB-C 8.6+** control link
> (`embassy_bmd_atem::usb`, host side, verified against real hardware).
> The repository is read-only; git dependencies pinned to this URL keep working,
> but new code should depend on the published crates below.

## Where to go

| Published crate | Contents |
|---|---|
| [`embassy-bmd-atem`](https://crates.io/crates/embassy-bmd-atem) | UDP/BURP **and** USB 8.6+ protocol core, `no_std` |
| [`bmd-atem-atom`](https://crates.io/crates/bmd-atem-atom) | transport-independent atom (command record) codec |
| [`embassy-bmd-atem-std`](https://crates.io/crates/embassy-bmd-atem-std) | Tokio + nusb desktop backend and the `atem-usb-control` CLI |

## Migration

The wire format, the atom codec and the UDP session logic were carried over
unchanged; only the crate and module paths moved.

```toml
# before
edge_bmd_atem = { git = "https://github.com/MikanseiLaboratory/edge-bmd-atem", default-features = false }

# after (published)
embassy-bmd-atem = { version = "0.1", default-features = false }

# or, pinned to the repository
embassy-bmd-atem = { git = "https://github.com/MikanseiLaboratory/embassy-bmd-atem", default-features = false }
```

```rust
// before
use edge_bmd_atem::io::{ErrorType, UdpReceive, UdpReceiveBounded, UdpSend};
use edge_bmd_atem::{AtemPacket, AtemSession, Error, ATEM_UDP_PORT};

// after — the same items are re-exported at the crate root
use embassy_bmd_atem::{ErrorType, UdpReceive, UdpReceiveBounded, UdpSend};
use embassy_bmd_atem::{AtemPacket, AtemSession, Error, ATEM_UDP_PORT};
```

Module paths that used to be flat are available both ways:

| old | new |
|---|---|
| `edge_bmd_atem::io` | `embassy_bmd_atem::udp::io` (also re-exported at the root) |
| `edge_bmd_atem::packet` | `embassy_bmd_atem::udp::packet` |
| `edge_bmd_atem::session` | `embassy_bmd_atem::udp::session` |
| `edge_bmd_atem::udp` | `embassy_bmd_atem::udp::mock` |
| `edge_bmd_atem::{parse_atoms, FourCc, …}` | `embassy_bmd_atem::{parse_atoms, FourCc, …}` (unchanged) |

New capabilities in the successor crate:

- `embassy_bmd_atem::usb` — ATEM USB-C 8.6+ host implementation (framing, credit
  windows, idle-stall recovery, ZLP keepalive matching pyatem's cadence).
- `bmd_atem_atom::AtomWriter` — no-alloc command builder shared by both transports.
- `embassy_bmd_atem::link::{frame_command, TransportKind, FrameContext, FramePlan}`
  — one command blob, framed for either transport.

## License

Apache-2.0. See `NOTICE` for third-party attribution.
