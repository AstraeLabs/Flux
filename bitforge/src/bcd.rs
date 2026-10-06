//! Binary-coded decimal (BCD) codec for DVB wire fields.

/// Maximum number of nibbles a `u64` carrier can hold.
pub const MAX_NIBBLES: u8 = 16;

#[must_use]
/// Decodes one packed BCD byte, or `None` if a nibble is above 9.
pub fn from_bcd_byte(byte: u8) -> Option<u8> {
    bcd_to_decimal(u64::from(byte), 2).map(|v| v as u8)
}

#[must_use]
/// Encodes a value `0..=99` as one packed BCD byte.
pub fn to_bcd_byte(value: u8) -> Option<u8> {
    decimal_to_bcd(u64::from(value), 2).map(|v| v as u8)
}

#[must_use]
/// Converts a packed BCD value with `nibbles` digits to decimal.
pub fn bcd_to_decimal(raw: u64, nibbles: u8) -> Option<u64> {
    if nibbles > MAX_NIBBLES {
        return None;
    }
    let mut acc = 0u64;
    for i in (0..nibbles).rev() {
        let digit = (raw >> (i * 4)) & 0x0F;
        if digit > 9 {
            return None;
        }
        acc = acc * 10 + digit;
    }
    Some(acc)
}

#[must_use]
/// Converts a decimal value to packed BCD with `nibbles` digits.
pub fn decimal_to_bcd(value: u64, nibbles: u8) -> Option<u64> {
    if nibbles > MAX_NIBBLES {
        return None;
    }
    let mut packed = 0u64;
    let mut remaining = value;
    for i in 0..nibbles {
        let digit = remaining % 10;
        packed |= digit << (i * 4);
        remaining /= 10;
    }
    if remaining != 0 {

        return None;
    }
    Some(packed)
}