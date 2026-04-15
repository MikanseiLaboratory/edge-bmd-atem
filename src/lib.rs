//! Blackmagic ATEM switcher control over UDP (BURP), for [`edge-nal`] stacks.
//!
//! This crate is `#![no_std]` with [`alloc`]. Enable the `std` feature for host-only
//! helpers and Tokio-based tests.
//!
//! Protocol layout and handshake behaviour are aligned with the
//! [necromancer](https://github.com/micolous/necromancer) project (Apache-2.0); see
//! the repository `NOTICE` file.
//!
//! ## References (issue #1)
//!
//! - **Primary wire format / atoms**: necromancer `necromancer_protocol` (FourCC names).
//! - **SKAARHOJ-Open-Engineering**: older Arduino-oriented material; treat as secondary
//!   when names or lengths disagree with necromancer.
//!
//! [`edge-nal`]: https://docs.rs/edge-nal

#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

mod atoms;
mod error;
pub mod io;
mod packet;
mod session;
mod udp;

pub use atoms::{encode_atom_do_transition_auto, parse_atoms, AtomIter, FourCc, RawAtom};
pub use error::Error;
pub use packet::{AtemControl, AtemPacket, AtemPacketFlags, AtemPacketPayload};
#[cfg(feature = "std")]
pub use session::SessionError;
pub use session::{AtemSession, PendingPacket, SessionConfig, SessionState};
pub use udp::{EdgeNalUdp, MockUdp, MockUdpExhausted};

pub const ATEM_UDP_PORT: u16 = 9910;
