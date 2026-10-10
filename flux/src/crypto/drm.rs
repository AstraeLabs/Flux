//! Multi-DRM `pssh` init-data payload generation

use alloc::string::String;
use alloc::vec::Vec;

use crate::cenc::ProtectionSystemSpecificHeaderBox;
use crate::error::{Error, Result};

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64_ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(B64_ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64_ALPHABET[((n >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(B64_ALPHABET[(n & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn base64_decode(s: &str) -> Result<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes: Vec<u8> = s.bytes().filter(|&b| b != b'=').collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut acc = 0u32;
    let mut nbits = 0u32;
    for &b in &bytes {
        let v = val(b).ok_or(Error::InvalidValue {
            field: "base64",
            value: b as u64,
            reason: "not a base64 character",
        })?;
        acc = (acc << 6) | v;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    Ok(out)
}

pub const WIDEVINE_SYSTEM_ID: [u8; 16] = [
    0xED, 0xEF, 0x8B, 0xA9, 0x79, 0xD6, 0x4A, 0xCE, 0xA3, 0xC8, 0x27, 0xDC, 0xD5, 0x1D, 0x21, 0xED,
];

pub const PLAYREADY_SYSTEM_ID: [u8; 16] = [
    0x9A, 0x04, 0xF0, 0x79, 0x98, 0x40, 0x42, 0x86, 0xAB, 0x92, 0xE6, 0x5B, 0xE0, 0x88, 0x5F, 0x95,
];

pub const FAIRPLAY_SYSTEM_ID: [u8; 16] = [
    0x94, 0xCE, 0x86, 0xFB, 0x07, 0xFF, 0x4F, 0x43, 0xAD, 0xB8, 0x93, 0xD2, 0xFA, 0x96, 0x8C, 0xA2,
];

pub const fn cenc_kid_to_playready(uuid: [u8; 16]) -> [u8; 16] {
    [
        uuid[3], uuid[2], uuid[1], uuid[0],
        uuid[5], uuid[4],
        uuid[7], uuid[6],
        uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15],
    ]
}

pub const fn playready_kid_to_cenc(guid: [u8; 16]) -> [u8; 16] {
    [
        guid[3], guid[2], guid[1], guid[0], guid[5], guid[4], guid[7], guid[6], guid[8], guid[9],
        guid[10], guid[11], guid[12], guid[13], guid[14], guid[15],
    ]
}

const WRMHEADER_NAMESPACE: &str = "http://schemas.microsoft.com/DRM/2007/03/PlayReadyHeader";

const PLAYREADY_ALGID_AESCTR: &str = "AESCTR";

const PRO_RECORD_TYPE_HEADER: u16 = 0x0001;

pub fn playready_wrmheader(kids: &[[u8; 16]], la_url: Option<&str>) -> String {
    let version = "4.2.0.0";
    let mut xml = String::new();
    xml.push_str("<WRMHEADER xmlns=\"");
    xml.push_str(WRMHEADER_NAMESPACE);
    xml.push_str("\" version=\"");
    xml.push_str(version);
    xml.push_str("\"><DATA><PROTECTINFO><KIDS>");
    for kid in kids {
        let guid = cenc_kid_to_playready(*kid);
        let value = base64_encode(&guid);
        xml.push_str("<KID ALGID=\"");
        xml.push_str(PLAYREADY_ALGID_AESCTR);
        xml.push_str("\" VALUE=\"");
        xml.push_str(&value);
        xml.push_str("\"></KID>");
    }
    xml.push_str("</KIDS></PROTECTINFO>");
    if let Some(url) = la_url {
        xml.push_str("<LA_URL>");
        xml.push_str(&xml_escape(url));
        xml.push_str("</LA_URL>");
    }
    xml.push_str("</DATA></WRMHEADER>");
    xml
}

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(c),
        }
    }
    out
}

fn utf16le_bytes(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 2);
    for unit in s.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

pub fn playready_pro(kids: &[[u8; 16]], la_url: Option<&str>) -> Vec<u8> {
    let wrm = playready_wrmheader(kids, la_url);
    let value = utf16le_bytes(&wrm);
    let record_count: u16 = 1;
    let total_len = 4 + 2 + 2 + 2 + value.len();
    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(&(total_len as u32).to_le_bytes());
    out.extend_from_slice(&record_count.to_le_bytes());
    out.extend_from_slice(&PRO_RECORD_TYPE_HEADER.to_le_bytes());
    out.extend_from_slice(&(value.len() as u16).to_le_bytes());
    out.extend_from_slice(&value);
    out
}

pub fn playready_pssh(
    kids: &[[u8; 16]],
    la_url: Option<&str>,
) -> ProtectionSystemSpecificHeaderBox {
    ProtectionSystemSpecificHeaderBox {
        version: 0,
        system_id: PLAYREADY_SYSTEM_ID,
        kids: Vec::new(),
        data: playready_pro(kids, la_url),
    }
}

const PROTOBUF_WIRETYPE_LEN: u8 = 2;
const PROTOBUF_WIRETYPE_VARINT: u8 = 0;

const WV_FIELD_KEY_ID: u8 = 2;
const WV_FIELD_PROVIDER: u8 = 3;
const WV_FIELD_CONTENT_ID: u8 = 4;
const WV_FIELD_PROTECTION_SCHEME: u8 = 9;

const fn pb_tag(field: u8, wire_type: u8) -> u8 {
    (field << 3) | wire_type
}

fn pb_put_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn pb_put_len_delimited(out: &mut Vec<u8>, field: u8, bytes: &[u8]) {
    out.push(pb_tag(field, PROTOBUF_WIRETYPE_LEN));
    pb_put_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

pub fn widevine_pssh_data(
    key_ids: &[[u8; 16]],
    provider: Option<&str>,
    protection_scheme: Option<[u8; 4]>,
) -> Vec<u8> {
    let mut out = Vec::new();
    for kid in key_ids {
        pb_put_len_delimited(&mut out, WV_FIELD_KEY_ID, kid);
    }
    if let Some(p) = provider {
        pb_put_len_delimited(&mut out, WV_FIELD_PROVIDER, p.as_bytes());
    }
    let _ = WV_FIELD_CONTENT_ID;
    if let Some(scheme) = protection_scheme {
        out.push(pb_tag(WV_FIELD_PROTECTION_SCHEME, PROTOBUF_WIRETYPE_VARINT));
        pb_put_varint(&mut out, u32::from_be_bytes(scheme) as u64);
    }
    out
}

pub fn widevine_pssh(
    kids: &[[u8; 16]],
    provider: Option<&str>,
) -> ProtectionSystemSpecificHeaderBox {
    ProtectionSystemSpecificHeaderBox {
        version: 0,
        system_id: WIDEVINE_SYSTEM_ID,
        kids: Vec::new(),
        data: widevine_pssh_data(kids, provider, None),
    }
}

pub fn widevine_pssh_key_ids(data: &[u8]) -> Vec<[u8; 16]> {
    let mut kids = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let Some((tag, tag_len)) = pb_read_varint(&data[pos..]) else {
            break;
        };
        pos += tag_len;
        let field = tag >> 3;
        let wire_type = (tag & 0x7) as u8;
        match wire_type {
            PROTOBUF_WIRETYPE_VARINT => {
                let Some((_, n)) = pb_read_varint(&data[pos..]) else {
                    break;
                };
                pos += n;
            }
            PROTOBUF_WIRETYPE_LEN => {
                let Some((len, n)) = pb_read_varint(&data[pos..]) else {
                    break;
                };
                pos += n;
                let Ok(len) = usize::try_from(len) else {
                    break;
                };
                if len > data.len() - pos {
                    break;
                }
                if field == u64::from(WV_FIELD_KEY_ID) && len == 16 {
                    let mut kid = [0u8; 16];
                    kid.copy_from_slice(&data[pos..pos + len]);
                    kids.push(kid);
                }
                pos += len;
            }
            5 | 1 => {
                let skip = if wire_type == 5 { 4 } else { 8 };
                if skip > data.len() - pos {
                    break;
                }
                pos += skip;
            }
            _ => break,
        }
    }
    kids
}

fn pb_read_varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for (i, &byte) in bytes.iter().enumerate().take(10) {
        value |= u64::from(byte & 0x7F) << (7 * i);
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
    }
    None
}

pub fn fairplay_pssh_data(skd_uri: &str) -> Vec<u8> {
    skd_uri.as_bytes().to_vec()
}

pub fn fairplay_pssh(skd_uri: &str) -> ProtectionSystemSpecificHeaderBox {
    ProtectionSystemSpecificHeaderBox {
        version: 0,
        system_id: FAIRPLAY_SYSTEM_ID,
        kids: Vec::new(),
        data: fairplay_pssh_data(skd_uri),
    }
}

pub fn playready_pssh_key_ids(pro_data: &[u8]) -> Vec<[u8; 16]> {
    let mut kids = Vec::new();
    if pro_data.len() < 6 {
        return kids;
    }
    let record_count = u16::from_le_bytes([pro_data[4], pro_data[5]]);
    let mut offset = 6usize;
    for _ in 0..record_count {
        if offset + 4 > pro_data.len() {
            break;
        }
        let record_type = u16::from_le_bytes([pro_data[offset], pro_data[offset + 1]]);
        let record_len = u16::from_le_bytes([pro_data[offset + 2], pro_data[offset + 3]]) as usize;
        offset += 4;
        if offset + record_len > pro_data.len() {
            break;
        }
        if record_type == PRO_RECORD_TYPE_HEADER {
            let utf16_bytes = &pro_data[offset..offset + record_len];
            if let Some(xml) = utf16le_decode(utf16_bytes) {
                extract_wrmheader_kids(&xml, &mut kids);
            }
        }
        offset += record_len;
    }
    kids
}

fn utf16le_decode(bytes: &[u8]) -> Option<String> {
    if bytes.len() % 2 != 0 {
        return None;
    }
    let units = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]]));
    char::decode_utf16(units).collect::<core::result::Result<String, _>>().ok()
}

fn extract_wrmheader_kids(xml: &str, out: &mut Vec<[u8; 16]>) {
    let mut rest = xml;
    while let Some(kid_start) = rest.find("<KID") {
        rest = &rest[kid_start..];
        let Some(tag_end) = rest.find('>') else {
            break;
        };
        let tag = &rest[..tag_end];
        if let Some(value) = xml_attr(tag, "VALUE")
            && let Ok(guid) = playready_kid_value_decode(value)
        {
            out.push(playready_kid_to_cenc(guid));
        }
        rest = &rest[tag_end + 1..];
    }
}

fn xml_attr<'a>(tag: &'a str, attr: &str) -> Option<&'a str> {
    let needle = alloc::format!("{attr}=\"");
    let start = tag.find(needle.as_str())? + needle.len();
    let rest = &tag[start..];
    let end = rest.find('"')?;
    Some(&rest[..end])
}

pub fn playready_kid_value_decode(value: &str) -> Result<[u8; 16]> {
    let bytes = base64_decode(value)?;
    if bytes.len() != 16 {
        return Err(Error::InvalidValue {
            field: "playready KID VALUE",
            value: bytes.len() as u64,
            reason: "expected 16 decoded bytes",
        });
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn playready_pssh_key_ids_round_trips_through_playready_pro() {
        let kid1 = [0x11u8; 16];
        let kid2 = [0x22u8; 16];
        let pro = playready_pro(&[kid1, kid2], Some("https://example.com/license"));

        let extracted = playready_pssh_key_ids(&pro);
        assert_eq!(extracted, alloc::vec![kid1, kid2]);
    }

    #[test]
    fn playready_pssh_key_ids_on_garbage_returns_empty_not_panicking() {
        assert!(playready_pssh_key_ids(&[]).is_empty());
        assert!(playready_pssh_key_ids(&[0u8; 3]).is_empty());
        assert!(playready_pssh_key_ids(&[0xFFu8; 40]).is_empty());
    }

    #[test]
    fn widevine_and_playready_kid_round_trip_agree_on_the_same_kid() {
        let kid = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];

        let wv_data = widevine_pssh_data(&[kid], None, None);
        assert_eq!(widevine_pssh_key_ids(&wv_data), alloc::vec![kid]);

        let pro = playready_pro(&[kid], None);
        assert_eq!(playready_pssh_key_ids(&pro), alloc::vec![kid]);
    }

    #[test]
    fn widevine_key_ids_huge_length_varint_terminates() {
        let mut data = vec![0x12u8];
        data.extend_from_slice(&[0xFF; 9]);
        data.push(0x01);
        assert!(widevine_pssh_key_ids(&data).is_empty());
        for d in [&[0x12u8][..], &[0x12, 0x10, 1, 2][..], &[0x0d, 1][..], &[0x09, 1, 2][..]] {
            assert!(widevine_pssh_key_ids(d).is_empty());
        }
    }
}
