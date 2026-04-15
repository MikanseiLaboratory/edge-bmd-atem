//! UDP traits aligned with [`edge_nal`](https://docs.rs/edge-nal) so stacks like
//! `edge-nal-embassy` can be bridged with a small newtype in your firmware crate.
//!
//! This crate does **not** depend on `edge-nal` to keep host `cargo test` free of
//! the `embassy-time` driver symbols pulled by `edge-nal` 0.6.

#![allow(async_fn_in_trait)]

use core::net::SocketAddr;

pub use embedded_io_async::ErrorType;

/// Async UDP receive (same contract as `edge_nal::UdpReceive`).
pub trait UdpReceive: ErrorType {
    /// Returns `(bytes copied into buffer, remote address)`.
    async fn receive(&mut self, buffer: &mut [u8]) -> Result<(usize, SocketAddr), Self::Error>;
}

/// Async UDP send (same contract as `edge_nal::UdpSend`).
pub trait UdpSend: ErrorType {
    async fn send(&mut self, remote: SocketAddr, data: &[u8]) -> Result<(), Self::Error>;
}

/// Bounded wait for a datagram (Embassy `select(recv, Timer)` / host `timeout` pattern).
///
/// Implementations should block for **up to** `timeout_ms` when no datagram is ready, then
/// return [`Ok(None)`]. When a datagram arrives sooner, return it immediately. The value
/// `timeout_ms` is always `>= 1` when called from [`crate::AtemSession::connect`].
pub trait UdpReceiveBounded: UdpReceive {
    async fn receive_for(
        &mut self,
        buffer: &mut [u8],
        timeout_ms: u32,
    ) -> Result<Option<(usize, SocketAddr)>, Self::Error>;
}
