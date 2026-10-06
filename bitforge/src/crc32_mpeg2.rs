//! CRC-32 MPEG-2 — Annex C of ETSI EN 300 468, Annex A of ETSI TS 102 773.

/// MPEG-2 CRC-32 generator polynomial.
pub const POLY: u32 = 0x04C1_1DB7;

pub(crate) const TABLE: [u32; 256] = {
    let mut t = [0u32; 256];
    let mut i = 0u32;
    while i < 256 {
        let mut c = i << 24;
        let mut j = 0;
        while j < 8 {
            c = if c & 0x8000_0000 != 0 {
                (c << 1) ^ POLY
            } else {
                c << 1
            };
            j += 1;
        }
        t[i as usize] = c;
        i += 1;
    }
    t
};

#[inline]
/// Computes the CRC-32/MPEG-2 of `bytes`.
pub fn compute(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in bytes {
        crc = (crc << 8) ^ TABLE[((crc >> 24) as u8 ^ b) as usize];
    }
    crc
}
