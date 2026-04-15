//! Session lifecycle: connect handshake (host async) and ACK / retransmit helpers.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::net::SocketAddr;

use crate::io::{UdpReceiveBounded, UdpSend};
use crate::packet::AtemPacket;
use crate::packet::{AtemControl, AtemPacketFlags};
use crate::Error;

/// Tunables for queues and timing (MCU-friendly defaults).
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Handshake wait (host async path).
    pub init_timeout_ms: u32,
    pub max_ack_queue: usize,
    pub retransmit_limit: u8,
    pub retransmit_delay_ms: u32,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            init_timeout_ms: 1000,
            max_ack_queue: 64,
            retransmit_limit: 3,
            retransmit_delay_ms: 500,
        }
    }
}

/// Established session parameters after [`AtemSession::connect`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionState {
    /// Switcher-assigned session (`0x8000` bit set).
    pub session_id: u16,
    /// Client-chosen id used on the first control exchange.
    pub initial_session_id: u16,
    /// Switcher `sender_packet_id` from the `ConnectAck` datagram header.
    pub switcher_packet_id_at_connect: u16,
    pub remote: SocketAddr,
}

/// Outbound packet waiting for switcher cumulative ACK (`acked_packet_id`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingPacket {
    pub sender_packet_id: u16,
    pub wire: Vec<u8>,
    pub retries: u8,
    pub last_sent_ms: u32,
}

/// Maps UDP failures or protocol errors for [`AtemSession::connect`].
#[derive(Debug)]
pub enum SessionError<E> {
    Protocol(Error),
    Backend(E),
}

impl<E: core::fmt::Debug> core::fmt::Display for SessionError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Protocol(e) => write!(f, "{e}"),
            Self::Backend(e) => write!(f, "{e:?}"),
        }
    }
}

#[cfg(feature = "std")]
impl<E: core::fmt::Debug + 'static> std::error::Error for SessionError<E> {}

/// Live session with optional reliability queue.
#[derive(Debug)]
pub struct AtemSession {
    pub state: SessionState,
    pub config: SessionConfig,
    ack_queue: VecDeque<PendingPacket>,
    next_sender_packet_id: u16,
}

impl AtemSession {
    /// Full UDP handshake + initial state dump request (necromancer `initialise` subset).
    ///
    /// `now_ms` must read a **monotonic** millisecond counter (wrapping `u32` arithmetic is
    /// fine for handshake-length windows). Used with [`UdpReceiveBounded::receive_for`] to
    /// bound total wait to [`SessionConfig::init_timeout_ms`].
    pub async fn connect<S, F>(
        udp: &mut S,
        remote: SocketAddr,
        initial_session_id: u16,
        config: SessionConfig,
        mut now_ms: F,
    ) -> Result<Self, SessionError<S::Error>>
    where
        S: UdpSend + UdpReceiveBounded,
        F: FnMut() -> u32,
    {
        if !(1..=0x7fff).contains(&initial_session_id) {
            return Err(SessionError::Protocol(Error::UnexpectedState));
        }

        let connect = AtemPacket::new_control(
            AtemPacketFlags {
                control: true,
                ..AtemPacketFlags::default()
            },
            initial_session_id,
            0,
            0xb1,
            0,
            AtemControl::Connect,
        );
        let mut tx = [0u8; 256];
        let n = connect.wire_len();
        connect
            .write_into(&mut tx[..n])
            .map_err(SessionError::Protocol)?;
        udp
            .send(remote, &tx[..n])
            .await
            .map_err(SessionError::Backend)?;

        let mut rx = [0u8; 2048];
        let t0 = now_ms();
        let limit = config.init_timeout_ms.max(1);

        let (switcher_pid, session_id) = loop {
            let elapsed = now_ms().wrapping_sub(t0);
            if elapsed >= limit {
                return Err(SessionError::Protocol(Error::Timeout));
            }
            let left = limit - elapsed;
            let slice = left.min(1000).max(1);
            let got = udp
                .receive_for(&mut rx, slice)
                .await
                .map_err(SessionError::Backend)?;
            let Some((m, _src)) = got else {
                continue;
            };
            if m < crate::packet::AtemPacket::HEADER_LEN {
                continue;
            }
            let Ok(pkt) = AtemPacket::decode(&rx[..m]) else {
                continue;
            };
            if pkt.session_id != initial_session_id {
                continue;
            }
            let Some(AtemControl::ConnectAck { session_id: sid }) = pkt.control() else {
                if matches!(pkt.control(), Some(AtemControl::ConnectNack)) {
                    return Err(SessionError::Protocol(Error::ConnectRejected));
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
            initial_session_id,
            switcher_pid,
            0xd4,
            0,
        );
        let n2 = dump_req.wire_len();
        dump_req
            .write_into(&mut tx[..n2])
            .map_err(SessionError::Protocol)?;
        udp
            .send(remote, &tx[..n2])
            .await
            .map_err(SessionError::Backend)?;

        Ok(Self {
            state: SessionState {
                session_id,
                initial_session_id,
                switcher_packet_id_at_connect: switcher_pid,
                remote,
            },
            config,
            ack_queue: VecDeque::new(),
            next_sender_packet_id: 1,
        })
    }

    #[must_use]
    pub fn next_sender_packet_id(&self) -> u16 {
        self.next_sender_packet_id
    }

    /// Allocate the next local `sender_packet_id` (1..=0x7fff, wrapping).
    pub fn take_sender_packet_id(&mut self) -> u16 {
        let v = self.next_sender_packet_id;
        self.next_sender_packet_id = if v >= AtemPacket::MAX_PACKET_ID {
            1
        } else {
            v + 1
        };
        v
    }

    /// Remember an outbound packet that expects a switcher ACK.
    pub fn register_pending_ack(&mut self, sender_packet_id: u16, wire: Vec<u8>, now_ms: u32) {
        self.ack_queue.push_back(PendingPacket {
            sender_packet_id,
            wire,
            retries: 0,
            last_sent_ms: now_ms,
        });
        while self.ack_queue.len() > self.config.max_ack_queue {
            self.ack_queue.pop_front();
        }
    }

    /// Remove pending entries acknowledged cumulatively by the switcher.
    ///
    /// Mirrors necromancer `handle_ack` ordering assumptions (sorted by
    /// `sender_packet_id`, `u16` wrap guarded with a queue-length window).
    pub fn apply_cumulative_ack(&mut self, acked_packet_id: u16) {
        if self.ack_queue.is_empty() || acked_packet_id == 0 {
            return;
        }
        let max_q = self.config.max_ack_queue.min(usize::from(u16::MAX)) as u16;
        let min_pos = if acked_packet_id >= AtemPacket::MAX_PACKET_ID.saturating_sub(max_q) {
            let min_acked = acked_packet_id.saturating_sub(max_q);
            deque_partition_point(&self.ack_queue, |p| p.sender_packet_id < min_acked)
        } else {
            0
        };
        let pos = deque_partition_point(&self.ack_queue, |p| p.sender_packet_id <= acked_packet_id);
        if pos > min_pos {
            self.ack_queue.drain(min_pos..pos);
        }
    }

    /// Build ACK packets for a received switcher datagram and update the ACK queue.
    pub fn handle_incoming(&mut self, pkt: &AtemPacket) -> Vec<AtemPacket> {
        self.apply_cumulative_ack(pkt.acked_packet_id);
        let mut out = Vec::new();
        if let Some(ack) = pkt.make_ack() {
            out.push(ack);
        }
        out
    }

    /// Packets that should be re-sent (`wire` buffers), respecting limits.
    pub fn retransmits_due(&mut self, now_ms: u32) -> Vec<Vec<u8>> {
        let mut v = Vec::new();
        let delay = self.config.retransmit_delay_ms;
        let limit = self.config.retransmit_limit;
        for p in &mut self.ack_queue {
            if p.retries >= limit {
                continue;
            }
            if now_ms.saturating_sub(p.last_sent_ms) >= delay {
                p.retries = p.retries.saturating_add(1);
                p.last_sent_ms = now_ms;
                v.push(p.wire.clone());
            }
        }
        v
    }
}

fn deque_partition_point<T>(dq: &VecDeque<T>, mut pred: impl FnMut(&T) -> bool) -> usize {
    let mut left = 0usize;
    let mut right = dq.len();
    while left < right {
        let mid = left + (right - left) / 2;
        if pred(&dq[mid]) {
            left = mid + 1;
        } else {
            right = mid;
        }
    }
    left
}

#[cfg(all(test, feature = "std"))]
use core::net::Ipv4Addr;

#[cfg(all(test, feature = "std"))]
#[tokio::test]
async fn mock_handshake() {
    use crate::udp::MockUdp;

    let remote = SocketAddr::new(Ipv4Addr::new(192, 168, 1, 240).into(), 9910);
    let init = 0x2970u16;

    let switcher_ack = AtemPacket::new_control(
        AtemPacketFlags {
            control: true,
            ..AtemPacketFlags::default()
        },
        init,
        0,
        0,
        0,
        AtemControl::ConnectAck { session_id: 2 },
    );
    let mut inbound = VecDeque::new();
    inbound.push_back((remote, switcher_ack.to_bytes()));

    let mut udp = MockUdp {
        inbound,
        outbound: Vec::new(),
    };

    let t0 = std::time::Instant::now();
    let session = AtemSession::connect(
        &mut udp,
        remote,
        init,
        SessionConfig {
            init_timeout_ms: 500,
            ..SessionConfig::default()
        },
        || t0.elapsed().as_millis() as u32,
    )
    .await
    .expect("handshake");

    assert_eq!(session.state.session_id, 0x8002);
    assert_eq!(udp.outbound.len(), 2);
}

#[cfg(all(test, feature = "std"))]
#[test]
fn ack_queue_cumulative_pop() {
    let remote = SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), 9910);
    let mut s = AtemSession {
        state: SessionState {
            session_id: 0x8001,
            initial_session_id: 0x100,
            switcher_packet_id_at_connect: 1,
            remote,
        },
        config: SessionConfig::default(),
        ack_queue: VecDeque::new(),
        next_sender_packet_id: 5,
    };
    s.register_pending_ack(1, vec![1], 0);
    s.register_pending_ack(2, vec![2], 0);
    s.register_pending_ack(3, vec![3], 0);
    s.apply_cumulative_ack(2);
    assert_eq!(s.ack_queue.len(), 1);
    assert_eq!(s.ack_queue[0].sender_packet_id, 3);
}

#[cfg(all(test, feature = "std"))]
#[test]
fn retransmit_increments_retry() {
    let remote = SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), 9910);
    let mut s = AtemSession {
        state: SessionState {
            session_id: 0x8001,
            initial_session_id: 0x100,
            switcher_packet_id_at_connect: 1,
            remote,
        },
        config: SessionConfig {
            retransmit_delay_ms: 100,
            retransmit_limit: 2,
            ..SessionConfig::default()
        },
        ack_queue: VecDeque::from([PendingPacket {
            sender_packet_id: 1,
            wire: vec![0xaa],
            retries: 0,
            last_sent_ms: 0,
        }]),
        next_sender_packet_id: 2,
    };
    let r = s.retransmits_due(150);
    assert_eq!(r, vec![vec![0xaa]]);
    assert_eq!(s.ack_queue[0].retries, 1);
    let r2 = s.retransmits_due(300);
    assert_eq!(r2, vec![vec![0xaa]]);
    assert_eq!(s.ack_queue[0].retries, 2);
    let r3 = s.retransmits_due(500);
    assert!(r3.is_empty());
}
