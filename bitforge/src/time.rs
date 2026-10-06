//! UTC time and duration codecs for DVB wire fields.
use crate::bcd::{from_bcd_byte, to_bcd_byte};
use core::time::Duration;

/// A UTC date/time decoded from a DVB Modified Julian Date + BCD field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MjdBcdDateTime {
    /// Calendar year.
    pub year: u16,
    /// Month, 1..=12.
    pub month: u8,
    /// Day of month, 1..=31.
    pub day: u8,
    /// Hour, 0..=23.
    pub hour: u8,
    /// Minute, 0..=59.
    pub minute: u8,
    /// Second, 0..=59.
    pub second: u8,
}

#[must_use]
/// Decodes a DVB 5-byte MJD + BCD date and time field.
pub fn decode_mjd_bcd(raw: [u8; 5]) -> Option<MjdBcdDateTime> {
    let (mjd_bytes, _) = raw.split_first_chunk::<2>().unwrap();
    let mjd = u16::from_be_bytes(*mjd_bytes);
    let h = from_bcd_byte(raw[2])?;
    let mi = from_bcd_byte(raw[3])?;
    let s = from_bcd_byte(raw[4])?;
    if mi > 59 || s > 59 || h > 23 {
        return None;
    }
    let (year, month, day) = mjd_to_ymd_nogate(mjd)?;
    Some(MjdBcdDateTime {
        year,
        month,
        day,
        hour: h,
        minute: mi,
        second: s,
    })
}

#[must_use]
/// Encodes a date and time as a DVB 5-byte MJD + BCD field.
pub fn encode_mjd_bcd(dt: MjdBcdDateTime) -> Option<[u8; 5]> {
    let mjd = ymd_to_mjd_nogate(i32::from(dt.year), u32::from(dt.month), u32::from(dt.day))?;
    let [m0, m1] = mjd.to_be_bytes();
    Some([
        m0,
        m1,
        to_bcd_byte(dt.hour)?,
        to_bcd_byte(dt.minute)?,
        to_bcd_byte(dt.second)?,
    ])
}

fn mjd_to_ymd_nogate(mjd: u16) -> Option<(u16, u8, u8)> {
    let mjd = i64::from(mjd);
    let y_prime = ((mjd as f64 - 15_078.2) / 365.25) as i64;
    let m_prime = ((mjd as f64 - 14_956.1 - libm::floor(y_prime as f64 * 365.25)) / 30.6001) as i64;
    let d = mjd
        - 14_956
        - libm::floor(y_prime as f64 * 365.25) as i64
        - libm::floor(m_prime as f64 * 30.6001) as i64;
    let k = i64::from(m_prime == 14 || m_prime == 15);
    let y = y_prime + k + 1900;
    let m = m_prime - 1 - k * 12;
    let y_u16 = u16::try_from(y).ok()?;
    let m_u8 = u8::try_from(m).ok()?;
    let d_u8 = u8::try_from(d).ok()?;
    if !(1..=12).contains(&m_u8) || !(1..=31).contains(&d_u8) {
        return None;
    }
    Some((y_u16, m_u8, d_u8))
}

fn ymd_to_mjd_nogate(year: i32, month: u32, day: u32) -> Option<u16> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let l = if month <= 2 { 1.0 } else { 0.0 };
    let y = f64::from(year - 1900);
    let m = f64::from(month);
    let mjd = 14_956.0
        + f64::from(day)
        + libm::floor((y - l) * 365.25)
        + libm::floor((m + 1.0 + l * 12.0) * 30.6001);
    if (0.0..=f64::from(u16::MAX)).contains(&mjd) {
        Some(mjd as u16)
    } else {
        None
    }
}

#[must_use]
/// Decodes a DVB 3-byte BCD `HH:MM:SS` duration.
pub fn decode_bcd_duration(raw: [u8; 3]) -> Option<Duration> {
    let h = u64::from(from_bcd_byte(raw[0])?);
    let m = u64::from(from_bcd_byte(raw[1])?);
    let s = u64::from(from_bcd_byte(raw[2])?);
    if m > 59 || s > 59 {
        return None;
    }
    Some(Duration::from_secs(h * 3600 + m * 60 + s))
}

#[must_use]
/// Encodes a duration as a DVB 3-byte BCD `HH:MM:SS` field.
pub fn encode_bcd_duration(duration: Duration) -> Option<[u8; 3]> {
    let secs = duration.as_secs();
    let h = secs / 3600;
    if h > 99 {
        return None;
    }
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    Some([
        to_bcd_byte(h as u8)?,
        to_bcd_byte(m as u8)?,
        to_bcd_byte(s as u8)?,
    ])
}

#[cfg(feature = "chrono")]
#[cfg_attr(docsrs, doc(cfg(feature = "chrono")))]
#[must_use]
/// Converts a Modified Julian Date to a `(year, month, day)` triple.
pub fn mjd_to_ymd(mjd: u16) -> (i32, u32, u32) {
    let mjd = i64::from(mjd);
    let y_prime = ((mjd as f64 - 15_078.2) / 365.25) as i64;
    let m_prime = ((mjd as f64 - 14_956.1 - libm::floor(y_prime as f64 * 365.25)) / 30.6001) as i64;
    let d = mjd
        - 14_956
        - libm::floor(y_prime as f64 * 365.25) as i64
        - libm::floor(m_prime as f64 * 30.6001) as i64;
    let k = i64::from(m_prime == 14 || m_prime == 15);
    let y = y_prime + k + 1900;
    let m = m_prime - 1 - k * 12;
    (y as i32, m as u32, d as u32)
}

#[cfg(feature = "chrono")]
#[cfg_attr(docsrs, doc(cfg(feature = "chrono")))]
#[must_use]
/// Converts a `(year, month, day)` calendar date to a Modified Julian Date.
pub fn ymd_to_mjd(year: i32, month: u32, day: u32) -> Option<u16> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let l = if month <= 2 { 1.0 } else { 0.0 };
    let y = f64::from(year - 1900);
    let m = f64::from(month);
    let mjd = 14_956.0
        + f64::from(day)
        + libm::floor((y - l) * 365.25)
        + libm::floor((m + 1.0 + l * 12.0) * 30.6001);
    if (0.0..=f64::from(u16::MAX)).contains(&mjd) {
        Some(mjd as u16)
    } else {
        None
    }
}

#[cfg(feature = "chrono")]
#[cfg_attr(docsrs, doc(cfg(feature = "chrono")))]
#[must_use]
/// Decodes a DVB 5-byte MJD + BCD field into a UTC datetime.
pub fn decode_mjd_bcd_utc(raw: [u8; 5]) -> Option<chrono::DateTime<chrono::Utc>> {
    use chrono::{NaiveDate, NaiveDateTime, NaiveTime, TimeZone};
    let (mjd_bytes, _) = raw.split_first_chunk::<2>().unwrap();
    let mjd = u16::from_be_bytes(*mjd_bytes);
    let (y, m, d) = mjd_to_ymd(mjd);
    let h = from_bcd_byte(raw[2])?;
    let mi = from_bcd_byte(raw[3])?;
    let s = from_bcd_byte(raw[4])?;
    let date = NaiveDate::from_ymd_opt(y, m, d)?;
    let time = NaiveTime::from_hms_opt(u32::from(h), u32::from(mi), u32::from(s))?;
    chrono::Utc
        .from_local_datetime(&NaiveDateTime::new(date, time))
        .single()
}

#[cfg(feature = "chrono")]
#[cfg_attr(docsrs, doc(cfg(feature = "chrono")))]
#[must_use]
/// Encodes a UTC datetime as a DVB 5-byte MJD + BCD field.
pub fn encode_mjd_bcd_utc(dt: chrono::DateTime<chrono::Utc>) -> Option<[u8; 5]> {
    use chrono::{Datelike, Timelike};
    let naive = dt.naive_utc();
    let mjd = ymd_to_mjd(naive.year(), naive.month(), naive.day())?;
    let [m0, m1] = mjd.to_be_bytes();
    Some([
        m0,
        m1,
        to_bcd_byte(naive.hour() as u8)?,
        to_bcd_byte(naive.minute() as u8)?,
        to_bcd_byte(naive.second() as u8)?,
    ])
}

/// Unix timestamp of 2000-01-01T00:00:00Z.
pub const SECS_2000_EPOCH: i64 = 946_684_800;

#[cfg(feature = "chrono")]
#[cfg_attr(docsrs, doc(cfg(feature = "chrono")))]
#[must_use]
/// Decodes a DVB "seconds since 2000" field into a UTC datetime.
pub fn decode_seconds_since_2000_utc(
    seconds_since_2000: u64,
    subsec_nanos: u32,
    utco: u16,
) -> Option<chrono::DateTime<chrono::Utc>> {
    use chrono::TimeZone;

    let unix_secs = SECS_2000_EPOCH
        .checked_add(i64::try_from(seconds_since_2000).ok()?)?
        .checked_sub(i64::from(utco))?;
    chrono::Utc.timestamp_opt(unix_secs, subsec_nanos).single()
}

#[cfg(feature = "chrono")]
#[cfg_attr(docsrs, doc(cfg(feature = "chrono")))]
#[must_use]
/// Encodes a UTC datetime as a DVB "seconds since 2000" field.
pub fn encode_seconds_since_2000_utc(
    dt: chrono::DateTime<chrono::Utc>,
    utco: u16,
) -> Option<(u64, u32)> {
    use chrono::Timelike;
    let unix_secs = dt.timestamp();

    let raw = unix_secs
        .checked_sub(SECS_2000_EPOCH)?
        .checked_add(i64::from(utco))?;
    let secs = u64::try_from(raw).ok()?;

    if secs > 0xFF_FFFF_FFFF {
        return None;
    }
    Some((secs, dt.nanosecond()))
}