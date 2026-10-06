//! Big-endian, MSB-first bit reader/writer for dense sub-byte wire fields.

use core::fmt;

/// Errors produced by [`BitReader`] and [`BitWriter`] operations.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BitError {
    /// Not enough bits remain in the buffer.
    OutOfBounds {
        /// Bits the operation needed.
        needed_bits: usize,
        /// Bits left in the buffer.
        remaining_bits: usize,
    },
    /// More than 64 bits were requested at once.
    TooManyBits {
        /// Bits requested.
        requested: u32,
    },
    /// The value does not fit in the requested bit width.
    ValueTooWide {
        /// The value that was too wide.
        value: u64,
        /// The bit width it had to fit in.
        bits: u32,
    },
}

impl fmt::Display for BitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BitError::OutOfBounds {
                needed_bits,
                remaining_bits,
            } => write!(
                f,
                "bit buffer out of bounds: need {needed_bits} bit(s), {remaining_bits} remaining"
            ),
            BitError::TooManyBits { requested } => {
                write!(f, "requested {requested} bits exceeds the 64-bit carrier")
            }
            BitError::ValueTooWide { value, bits } => {
                write!(f, "value {value:#x} does not fit in {bits} bit(s)")
            }
        }
    }
}

impl core::error::Error for BitError {}

#[derive(Debug, Clone)]
/// Reads big-endian, MSB-first bit fields from a byte slice.
pub struct BitReader<'a> {
    data: &'a [u8],

    bit_pos: usize,
}

impl<'a> BitReader<'a> {

    #[must_use]
    /// Creates a reader at the start of `data`.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, bit_pos: 0 }
    }

    #[must_use]
    /// Total number of bits in the buffer.
    pub fn total_bits(&self) -> usize {
        self.data.len() * 8
    }

    #[must_use]
    /// Number of bits consumed so far.
    pub fn bits_read(&self) -> usize {
        self.bit_pos
    }

    #[must_use]
    /// Number of bits left to read.
    pub fn bits_remaining(&self) -> usize {
        self.total_bits() - self.bit_pos
    }

    #[must_use]
    /// Whether the position is on a byte boundary.
    pub fn is_byte_aligned(&self) -> bool {
        self.bit_pos.is_multiple_of(8)
    }

    /// Reads `n` bits (up to 64) as an unsigned integer.
    pub fn read_bits(&mut self, n: u32) -> Result<u64, BitError> {
        if n > 64 {
            return Err(BitError::TooManyBits { requested: n });
        }
        if n == 0 {
            return Ok(0);
        }
        let need = n as usize;
        let remaining = self.bits_remaining();
        if need > remaining {
            return Err(BitError::OutOfBounds {
                needed_bits: need,
                remaining_bits: remaining,
            });
        }
        let mut value: u64 = 0;
        for _ in 0..n {
            let byte = self.data[self.bit_pos / 8];
            let bit_index = 7 - (self.bit_pos % 8);
            let bit = (byte >> bit_index) & 1;
            value = (value << 1) | u64::from(bit);
            self.bit_pos += 1;
        }
        Ok(value)
    }

    /// Reads one bit as a boolean.
    pub fn read_bool(&mut self) -> Result<bool, BitError> {
        Ok(self.read_bits(1)? != 0)
    }

    /// Advances the position by `n` bits.
    pub fn skip_bits(&mut self, n: usize) -> Result<(), BitError> {
        let remaining = self.bits_remaining();
        if n > remaining {
            return Err(BitError::OutOfBounds {
                needed_bits: n,
                remaining_bits: remaining,
            });
        }
        self.bit_pos += n;
        Ok(())
    }

    /// Advances to the next byte boundary.
    pub fn align_to_byte(&mut self) {
        let rem = self.bit_pos % 8;
        if rem != 0 {
            self.bit_pos += 8 - rem;
        }
    }
}

#[derive(Debug)]
/// Writes big-endian, MSB-first bit fields into a mutable byte slice.
pub struct BitWriter<'a> {
    data: &'a mut [u8],
    bit_pos: usize,
}

impl<'a> BitWriter<'a> {

    #[must_use]
    /// Creates a writer at the start of `data`.
    pub fn new(data: &'a mut [u8]) -> Self {
        Self { data, bit_pos: 0 }
    }

    #[must_use]
    /// Total number of bits in the buffer.
    pub fn capacity_bits(&self) -> usize {
        self.data.len() * 8
    }

    #[must_use]
    /// Number of bits written so far.
    pub fn bits_written(&self) -> usize {
        self.bit_pos
    }

    #[must_use]
    /// Whether the position is on a byte boundary.
    pub fn is_byte_aligned(&self) -> bool {
        self.bit_pos.is_multiple_of(8)
    }

    /// Writes the low `n` bits (up to 64) of `value`.
    pub fn write_bits(&mut self, value: u64, n: u32) -> Result<(), BitError> {
        if n > 64 {
            return Err(BitError::TooManyBits { requested: n });
        }
        if n == 0 {
            return Ok(());
        }

        if n < 64 && value >= (1u64 << n) {
            return Err(BitError::ValueTooWide { value, bits: n });
        }
        let need = n as usize;
        let remaining = self.capacity_bits() - self.bit_pos;
        if need > remaining {
            return Err(BitError::OutOfBounds {
                needed_bits: need,
                remaining_bits: remaining,
            });
        }
        for i in (0..n).rev() {
            let bit = ((value >> i) & 1) as u8;
            let byte_idx = self.bit_pos / 8;
            let bit_index = 7 - (self.bit_pos % 8);
            if bit == 1 {
                self.data[byte_idx] |= 1 << bit_index;
            } else {
                self.data[byte_idx] &= !(1u8 << bit_index);
            }
            self.bit_pos += 1;
        }
        Ok(())
    }

    /// Writes one bit from a boolean.
    pub fn write_bool(&mut self, value: bool) -> Result<(), BitError> {
        self.write_bits(u64::from(value), 1)
    }

    /// Pads with zero bits up to the next byte boundary.
    pub fn align_to_byte(&mut self) -> Result<(), BitError> {
        let rem = self.bit_pos % 8;
        if rem != 0 {
            self.write_bits(0, (8 - rem) as u32)?;
        }
        Ok(())
    }
}