//! Minimal atom iteration (necromancer `Atom` wire shape).
//!
//! # Reference (issue #1, P4)
//!
//! - **necromancer** names and lengths are the primary guide for current BURP
//!   atoms (`necromancer_protocol::atom`).
//! - **SKAARHOJ-Open-Engineering** targets older switcher firmware; treat its
//!   message tables as historical hints only when they disagree with necromancer.

use alloc::vec::Vec;

use crate::Error;

/// Four-byte atom type (ASCII FourCC on the wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FourCc(pub [u8; 4]);

impl FourCc {
    #[must_use]
    pub const fn from_bytes(b: [u8; 4]) -> Self {
        Self(b)
    }

    /// Returns ASCII if all bytes are printable; otherwise hex.
    #[must_use]
    pub fn display_lossy(self) -> FourCcDisplay {
        FourCcDisplay(self)
    }
}

pub struct FourCcDisplay(FourCc);

impl core::fmt::Display for FourCcDisplay {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let b = (self.0).0;
        if b.iter().all(|x| x.is_ascii_graphic()) {
            let s = core::str::from_utf8(&b).map_err(|_| core::fmt::Error)?;
            f.write_str(s)
        } else {
            for x in b {
                core::write!(f, "{x:02x}")?;
            }
            Ok(())
        }
    }
}

/// One atom inside an ATEM packet payload (`length` includes the full record).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawAtom {
    pub name: FourCc,
    /// Bytes after the 8-byte atom header (FourCC + this data = `length - 8`).
    pub data: Vec<u8>,
}

/// Parse a contiguous atom blob (as in [`crate::AtemPacketPayload::Atoms`]).
pub fn parse_atoms(mut buf: &[u8]) -> Result<Vec<RawAtom>, Error> {
    let mut out = Vec::new();
    while !buf.is_empty() {
        if buf.len() < 8 {
            return Err(Error::InvalidLength);
        }
        let alen = usize::from(u16::from_be_bytes([buf[0], buf[1]]));
        if alen < 8 {
            return Err(Error::InvalidLength);
        }
        if buf.len() < alen {
            return Err(Error::InvalidLength);
        }
        let chunk = &buf[..alen];
        let name = FourCc(chunk[4..8].try_into().map_err(|_| Error::InvalidLength)?);
        let data = chunk[8..alen].to_vec();
        out.push(RawAtom { name, data });
        buf = &buf[alen..];
    }
    Ok(out)
}

/// Borrowing iterator over atoms in a payload slice.
pub struct AtomIter<'a> {
    buf: &'a [u8],
}

impl<'a> AtomIter<'a> {
    #[must_use]
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }
}

impl<'a> Iterator for AtomIter<'a> {
    type Item = Result<RawAtomSlice<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.is_empty() {
            return None;
        }
        if self.buf.len() < 8 {
            self.buf = &[];
            return Some(Err(Error::InvalidLength));
        }
        let alen = usize::from(u16::from_be_bytes([self.buf[0], self.buf[1]]));
        if alen < 8 || self.buf.len() < alen {
            self.buf = &[];
            return Some(Err(Error::InvalidLength));
        }
        let chunk = &self.buf[..alen];
        let name = match chunk[4..8].try_into() {
            Ok(n) => FourCc(n),
            Err(_) => {
                self.buf = &[];
                return Some(Err(Error::InvalidLength));
            }
        };
        let data = &chunk[8..alen];
        self.buf = &self.buf[alen..];
        Some(Ok(RawAtomSlice { name, data }))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawAtomSlice<'a> {
    pub name: FourCc,
    pub data: &'a [u8],
}

/// One `DAut` atom on the wire (`DoTransitionAuto` in necromancer `atom::transitions::Auto`).
///
/// `me` is the mix-effect index (`0` = first ME). Padding matches necromancer `pad_size_to = 4`.
#[must_use]
pub const fn encode_atom_do_transition_auto(me: u8) -> [u8; 12] {
    [
        0x00,
        0x0c,
        0x00,
        0x00,
        b'D',
        b'A',
        b'u',
        b't',
        me,
        0,
        0,
        0,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfip_first_atom_from_necromancer_dump() {
        let hex = "001c0000524649500001420901000000ffffffffffff01000004cb01";
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let atoms = parse_atoms(&bytes).unwrap();
        assert_eq!(atoms.len(), 1);
        assert_eq!(atoms[0].name.0, *b"RFIP");
        assert_eq!(atoms[0].data.len(), 0x1c - 8);
    }

    #[test]
    fn daut_atom_roundtrip() {
        let w = encode_atom_do_transition_auto(0);
        let atoms = parse_atoms(&w).unwrap();
        assert_eq!(atoms.len(), 1);
        assert_eq!(atoms[0].name.0, *b"DAut");
        assert_eq!(atoms[0].data, [0, 0, 0, 0]);
        let w2 = encode_atom_do_transition_auto(1);
        assert_eq!(parse_atoms(&w2).unwrap()[0].data, [1, 0, 0, 0]);
    }
}
