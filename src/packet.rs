//! ATEM UDP framing (BURP packet layer).
//!
//! Field layout matches necromancer `AtemPacket` / `AtemPacketFlagsLength`.

use alloc::vec::Vec;

/// High-level flag bits (stored in bits 11..=15 of the first `u16` on the wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AtemPacketFlags {
    pub ack: bool,
    pub control: bool,
    pub retransmission: bool,
    pub hello: bool,
    pub response: bool,
}

impl AtemPacketFlags {
    const fn to_wire(self) -> u16 {
        let mut v = 0u16;
        if self.ack {
            v |= 1 << 11;
        }
        if self.control {
            v |= 1 << 12;
        }
        if self.retransmission {
            v |= 1 << 13;
        }
        if self.hello {
            v |= 1 << 14;
        }
        if self.response {
            v |= 1 << 15;
        }
        v
    }

    fn from_wire(w: u16) -> Self {
        Self {
            ack: (w & (1 << 11)) != 0,
            control: (w & (1 << 12)) != 0,
            retransmission: (w & (1 << 13)) != 0,
            hello: (w & (1 << 14)) != 0,
            response: (w & (1 << 15)) != 0,
        }
    }
}

/// Control-plane payload when `flags.control` is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtemControl {
    Connect,
    ConnectAck { session_id: u16 },
    ConnectNack,
    Disconnect,
    DisconnectAck,
}

impl AtemControl {
    pub const WIRE_LENGTH: usize = 8;

    fn decode(buf: &[u8]) -> Result<Self, crate::Error> {
        if buf.len() < Self::WIRE_LENGTH {
            return Err(crate::Error::BadControl);
        }
        match buf[0] {
            0x01 => Ok(Self::Connect),
            0x02 => {
                let session_id = u16::from_be_bytes([buf[2], buf[3]]);
                Ok(Self::ConnectAck { session_id })
            }
            0x03 => Ok(Self::ConnectNack),
            0x04 => Ok(Self::Disconnect),
            0x05 => Ok(Self::DisconnectAck),
            _ => Err(crate::Error::BadControl),
        }
    }

    fn encode(self, out: &mut [u8; Self::WIRE_LENGTH]) {
        out.fill(0);
        match self {
            Self::Connect => out[0] = 0x01,
            Self::ConnectAck { session_id } => {
                out[0] = 0x02;
                out[2..4].copy_from_slice(&session_id.to_be_bytes());
            }
            Self::ConnectNack => out[0] = 0x03,
            Self::Disconnect => out[0] = 0x04,
            Self::DisconnectAck => out[0] = 0x05,
        }
    }
}

/// Payload after the 12-byte header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AtemPacketPayload {
    None,
    Control(AtemControl),
    /// Raw atom blob (big-endian length-prefixed records); see [`crate::parse_atoms`].
    Atoms(alloc::vec::Vec<u8>),
}

/// One UDP datagram worth of ATEM protocol data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtemPacket {
    pub flags: AtemPacketFlags,
    pub session_id: u16,
    pub acked_packet_id: u16,
    pub unknown: u16,
    pub client_packet_id: u16,
    pub sender_packet_id: u16,
    pub payload: AtemPacketPayload,
}

impl AtemPacket {
    pub const HEADER_LEN: usize = 12;
    pub const MAX_PACKET_LEN: usize = 0x7ff;
    pub const MAX_PACKET_ID: u16 = 0x7fff;

    /// Build a non-control packet (empty payload).
    #[must_use]
    pub fn new(
        flags: AtemPacketFlags,
        session_id: u16,
        acked_packet_id: u16,
        client_packet_id: u16,
        sender_packet_id: u16,
    ) -> Self {
        Self {
            flags,
            session_id,
            acked_packet_id,
            unknown: 0,
            client_packet_id,
            sender_packet_id,
            payload: AtemPacketPayload::None,
        }
    }

    /// Build a control packet (`flags.control` must be true on the wire).
    #[must_use]
    pub fn new_control(
        mut flags: AtemPacketFlags,
        session_id: u16,
        acked_packet_id: u16,
        client_packet_id: u16,
        sender_packet_id: u16,
        control: AtemControl,
    ) -> Self {
        flags.control = true;
        Self {
            flags,
            session_id,
            acked_packet_id,
            unknown: 0,
            client_packet_id,
            sender_packet_id,
            payload: AtemPacketPayload::Control(control),
        }
    }

    /// Non-control packet whose payload is a raw atom blob (length-prefixed records).
    #[must_use]
    pub fn with_atoms(
        flags: AtemPacketFlags,
        session_id: u16,
        acked_packet_id: u16,
        client_packet_id: u16,
        sender_packet_id: u16,
        atoms: alloc::vec::Vec<u8>,
    ) -> Self {
        Self {
            flags,
            session_id,
            acked_packet_id,
            unknown: 0,
            client_packet_id,
            sender_packet_id,
            payload: AtemPacketPayload::Atoms(atoms),
        }
    }

    /// Total serialized length including header.
    #[must_use]
    pub fn wire_len(&self) -> usize {
        Self::HEADER_LEN
            + match &self.payload {
                AtemPacketPayload::None => 0,
                AtemPacketPayload::Control(_) => AtemControl::WIRE_LENGTH,
                AtemPacketPayload::Atoms(b) => b.len(),
            }
    }

    fn flags_length_word(&self) -> Result<u16, crate::Error> {
        let len = self.wire_len();
        let len_u16: u16 = len.try_into().map_err(|_| crate::Error::InvalidLength)?;
        if usize::from(len_u16) != len {
            return Err(crate::Error::InvalidLength);
        }
        let low = len_u16 & 0x7ff;
        let high = self.flags.to_wire();
        Ok(low | high)
    }

    /// Serialize into `out`, which must be at least `self.wire_len()` bytes.
    pub fn write_into(&self, out: &mut [u8]) -> Result<(), crate::Error> {
        let n = self.wire_len();
        if n > Self::MAX_PACKET_LEN {
            return Err(crate::Error::InvalidLength);
        }
        if out.len() < n {
            return Err(crate::Error::InvalidLength);
        }
        let o = &mut out[..n];
        o[0..2].copy_from_slice(&self.flags_length_word()?.to_be_bytes());
        o[2..4].copy_from_slice(&self.session_id.to_be_bytes());
        o[4..6].copy_from_slice(&self.acked_packet_id.to_be_bytes());
        o[6..8].copy_from_slice(&self.unknown.to_be_bytes());
        o[8..10].copy_from_slice(&self.client_packet_id.to_be_bytes());
        o[10..12].copy_from_slice(&self.sender_packet_id.to_be_bytes());
        match &self.payload {
            AtemPacketPayload::None => {}
            AtemPacketPayload::Control(c) => {
                let mut tmp = [0u8; AtemControl::WIRE_LENGTH];
                c.encode(&mut tmp);
                o[12..20].copy_from_slice(&tmp);
            }
            AtemPacketPayload::Atoms(b) => {
                o[12..n].copy_from_slice(b);
            }
        }
        Ok(())
    }

    /// Encode to a freshly allocated buffer.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = alloc::vec![0u8; self.wire_len()];
        self.write_into(&mut v)
            .expect("buffer sized to wire_len() must succeed");
        v
    }

    /// Parse one datagram.
    pub fn decode(buf: &[u8]) -> Result<Self, crate::Error> {
        if buf.len() < Self::HEADER_LEN {
            return Err(crate::Error::TooShort);
        }
        let flags_length = u16::from_be_bytes([buf[0], buf[1]]);
        let total_len = usize::from(flags_length & 0x7ff);
        if !(Self::HEADER_LEN..=Self::MAX_PACKET_LEN).contains(&total_len) {
            return Err(crate::Error::InvalidLength);
        }
        if buf.len() < total_len {
            return Err(crate::Error::InvalidLength);
        }
        let flags = AtemPacketFlags::from_wire(flags_length & !0x7ff);
        let session_id = u16::from_be_bytes([buf[2], buf[3]]);
        let acked_packet_id = u16::from_be_bytes([buf[4], buf[5]]);
        let unknown = u16::from_be_bytes([buf[6], buf[7]]);
        let client_packet_id = u16::from_be_bytes([buf[8], buf[9]]);
        let sender_packet_id = u16::from_be_bytes([buf[10], buf[11]]);
        let rest = &buf[Self::HEADER_LEN..total_len];
        let payload = if flags.control {
            if rest.len() != AtemControl::WIRE_LENGTH {
                return Err(crate::Error::InvalidLength);
            }
            AtemPacketPayload::Control(AtemControl::decode(rest)?)
        } else if rest.is_empty() {
            AtemPacketPayload::None
        } else {
            AtemPacketPayload::Atoms(rest.to_vec())
        };
        Ok(Self {
            flags,
            session_id,
            acked_packet_id,
            unknown,
            client_packet_id,
            sender_packet_id,
            payload,
        })
    }

    pub fn control(&self) -> Option<&AtemControl> {
        match &self.payload {
            AtemPacketPayload::Control(c) => Some(c),
            _ => None,
        }
    }

    /// If the peer asked for ACK, build a response ACK packet (necromancer `make_ack` subset).
    #[must_use]
    pub fn make_ack(&self) -> Option<Self> {
        if !self.flags.ack {
            return None;
        }
        Some(Self::new(
            AtemPacketFlags {
                response: true,
                ..AtemPacketFlags::default()
            },
            self.session_id,
            self.sender_packet_id,
            0,
            0,
        ))
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::String;
    use alloc::vec::Vec;

    use super::*;

    fn from_hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn control_connect_roundtrip() {
        let expected = AtemPacket::new_control(
            AtemPacketFlags {
                control: true,
                ..AtemPacketFlags::default()
            },
            0x2970,
            0,
            0xb1,
            0,
            AtemControl::Connect,
        );
        let cmd = from_hex("101429700000000000b100000100000000000000");
        let pkt = AtemPacket::decode(&cmd).unwrap();
        assert_eq!(expected, pkt);
        assert_eq!(pkt.to_bytes(), cmd);
    }

    #[test]
    fn control_connect_ack_roundtrip() {
        let expected = AtemPacket::new_control(
            AtemPacketFlags {
                control: true,
                ..AtemPacketFlags::default()
            },
            0x2970,
            0,
            0,
            0,
            AtemControl::ConnectAck { session_id: 0x0002 },
        );
        let cmd = from_hex("1014297000000000000000000200000200000000");
        let pkt = AtemPacket::decode(&cmd).unwrap();
        assert_eq!(expected, pkt);
        assert_eq!(pkt.to_bytes(), cmd);
    }
}
