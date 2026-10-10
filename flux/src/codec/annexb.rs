//! Annex B ↔ length-prefixed NAL conversion

use alloc::vec::Vec;

pub fn iter_annexb_nals(annexb: &[u8]) -> AnnexBNalIter<'_> {
    AnnexBNalIter {
        data: annexb,
        code_positions: start_code_positions(annexb),
        idx: 0,
    }
}

fn start_code_positions(data: &[u8]) -> Vec<usize> {
    let mut positions = Vec::new();
    let n = data.len();
    let mut p = 0usize;
    while p + 3 <= n {
        if data[p] == 0 && data[p + 1] == 0 && data[p + 2] == 1 {
            positions.push(p);
            p += 3;
        } else {
            p += 1;
        }
    }
    positions
}

pub struct AnnexBNalIter<'a> {
    data: &'a [u8],
    code_positions: Vec<usize>,
    idx: usize,
}

impl<'a> Iterator for AnnexBNalIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        // Iterative (not recursive): a stream of many empty NALs must not grow the stack.
        while self.idx < self.code_positions.len() {
            let start = self.code_positions[self.idx] + 3;
            let end = self
                .code_positions
                .get(self.idx + 1)
                .copied()
                .unwrap_or(self.data.len());
            self.idx += 1;
            let mut slice = self.data.get(start..end).unwrap_or(&[]);

            while let Some((&0, rest)) = slice.split_last() {
                slice = rest;
            }

            if !slice.is_empty() {
                return Some(slice);
            }
        }
        None
    }
}

pub fn annexb_to_length_prefixed(annexb: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(annexb.len());
    for nal in iter_annexb_nals(annexb) {
        out.extend_from_slice(&u32::try_from(nal.len()).unwrap_or(u32::MAX).to_be_bytes());
        out.extend_from_slice(nal);
    }
    out
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn many_empty_nals_do_not_overflow_the_stack() {
        let mut data = Vec::new();
        for _ in 0..200_000 {
            data.extend_from_slice(&[0, 0, 1]);
        }
        data.extend_from_slice(&[0, 0, 1, 0x65, 0xAA]);
        let nals: Vec<&[u8]> = iter_annexb_nals(&data).collect();
        assert_eq!(nals, alloc::vec![&[0x65u8, 0xAA][..]]);
    }
}
