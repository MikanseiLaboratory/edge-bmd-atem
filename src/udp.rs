//! UDP helpers: [`MockUdp`] for tests, [`EdgeNalUdp`] for fixed-peer forwarding.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::fmt;
use core::net::SocketAddr;

use crate::io::{ErrorType, UdpReceive, UdpReceiveBounded, UdpSend};
use embedded_io_async::{Error as EioError, ErrorKind};

/// [`MockUdp`] ran out of preloaded datagrams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MockUdpExhausted;

impl fmt::Display for MockUdpExhausted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MockUdp inbound queue is empty")
    }
}

impl EioError for MockUdpExhausted {
    fn kind(&self) -> ErrorKind {
        ErrorKind::NotFound
    }
}

impl core::error::Error for MockUdpExhausted {}

/// In-memory UDP peer for unit tests (`std` + Tokio tests).
#[derive(Default)]
pub struct MockUdp {
    /// Packets `receive` will hand out (FIFO).
    pub inbound: VecDeque<(SocketAddr, Vec<u8>)>,
    /// Every `send` appends here.
    pub outbound: Vec<(SocketAddr, Vec<u8>)>,
}

impl ErrorType for MockUdp {
    type Error = MockUdpExhausted;
}

impl UdpReceive for MockUdp {
    async fn receive(&mut self, buffer: &mut [u8]) -> Result<(usize, SocketAddr), Self::Error> {
        let (addr, data) = self.inbound.pop_front().ok_or(MockUdpExhausted)?;
        let n = data.len().min(buffer.len());
        buffer[..n].copy_from_slice(&data[..n]);
        Ok((n, addr))
    }
}

impl UdpSend for MockUdp {
    async fn send(&mut self, remote: SocketAddr, data: &[u8]) -> Result<(), Self::Error> {
        self.outbound.push((remote, data.to_vec()));
        Ok(())
    }
}

impl UdpReceiveBounded for MockUdp {
    async fn receive_for(
        &mut self,
        buffer: &mut [u8],
        _timeout_ms: u32,
    ) -> Result<Option<(usize, SocketAddr)>, Self::Error> {
        self.receive(buffer).await.map(Some)
    }
}

/// Forwards [`UdpSend::send`] to a fixed `peer` (connected-style ergonomics).
pub struct EdgeNalUdp<S> {
    inner: S,
    peer: SocketAddr,
}

impl<S> EdgeNalUdp<S> {
    #[must_use]
    pub const fn new(inner: S, peer: SocketAddr) -> Self {
        Self { inner, peer }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }

    pub fn peer(&self) -> SocketAddr {
        self.peer
    }
}

impl<S: ErrorType> ErrorType for EdgeNalUdp<S> {
    type Error = S::Error;
}

impl<S: UdpReceive> UdpReceive for EdgeNalUdp<S> {
    async fn receive(&mut self, buffer: &mut [u8]) -> Result<(usize, SocketAddr), Self::Error> {
        self.inner.receive(buffer).await
    }
}

impl<S: UdpSend> UdpSend for EdgeNalUdp<S> {
    async fn send(&mut self, _remote: SocketAddr, data: &[u8]) -> Result<(), Self::Error> {
        self.inner.send(self.peer, data).await
    }
}

impl<S: UdpReceiveBounded> UdpReceiveBounded for EdgeNalUdp<S> {
    async fn receive_for(
        &mut self,
        buffer: &mut [u8],
        timeout_ms: u32,
    ) -> Result<Option<(usize, SocketAddr)>, Self::Error> {
        self.inner.receive_for(buffer, timeout_ms).await
    }
}
