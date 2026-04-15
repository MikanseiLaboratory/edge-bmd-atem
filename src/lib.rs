//! Blackmagic ATEM switcher control over UDP (BURP), for [`edge-nal`] stacks.
//!
//! This crate is `#![no_std]` with [`alloc`]. Enable the `std` feature for Tokio-based
//! unit tests and the `std_handshake` example.
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

pub use atoms::{
    encode_atom_change_program_input, encode_atom_change_preview_input,
    encode_atom_change_transition_next, encode_atom_do_ftb_auto, encode_atom_do_ftb_cut,
    encode_atom_do_transition_auto, encode_atom_do_transition_cut, parse_atoms, AtomIter, FourCc,
    NextTransitionStyle, RawAtom,
};
pub use error::Error;
pub use io::UdpReceiveBounded;
pub use packet::{AtemControl, AtemPacket, AtemPacketFlags, AtemPacketPayload};
pub use session::{AtemSession, PendingPacket, SessionConfig, SessionError, SessionState};
pub use udp::{EdgeNalUdp, MockUdp, MockUdpExhausted};

pub const ATEM_UDP_PORT: u16 = 9910;
