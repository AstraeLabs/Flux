//! DRM system identification: `pssh` `system_id` UUID

use alloc::string::String;
use alloc::vec::Vec;

use crate::box_types::parse_box;
use crate::cenc::ProtectionSystemSpecificHeaderBox;
use crate::drm::{FAIRPLAY_SYSTEM_ID, PLAYREADY_SYSTEM_ID, WIDEVINE_SYSTEM_ID};

const COMMON_PSSH_SYSTEM_ID: [u8; 16] = [
    0x10, 0x77, 0xEF, 0xEC, 0xC0, 0xB2, 0x4D, 0x02, 0xAC, 0xE3, 0x3C, 0x1E, 0x52, 0xE2, 0xFB, 0x4B,
];
const CLEARKEY_SYSTEM_ID: [u8; 16] = [
    0xE2, 0x71, 0x9D, 0x58, 0xA9, 0x85, 0xB3, 0xC9, 0x78, 0x1A, 0xB0, 0x30, 0xAF, 0x78, 0xD3, 0x0E,
];
const FAIRPLAY_NETFLIX_SYSTEM_ID: [u8; 16] = [
    0x29, 0x70, 0x1F, 0xE4, 0x3C, 0xC7, 0x4A, 0x34, 0x8C, 0x5B, 0xAE, 0x90, 0xC7, 0x43, 0x9A, 0x47,
];
const CLEARKEY_AES128_SYSTEM_ID: [u8; 16] = [
    0x3E, 0xA8, 0x77, 0x8F, 0x77, 0x42, 0x4B, 0xF9, 0xB1, 0x8B, 0xE8, 0x34, 0xB2, 0xAC, 0xBD, 0x47,
];
const ADOBE_PRIMETIME_SYSTEM_ID: [u8; 16] = [
    0xF2, 0x39, 0xE7, 0x69, 0xEF, 0xA3, 0x48, 0x50, 0x9C, 0x16, 0xA9, 0x03, 0xC6, 0x93, 0x2E, 0xFB,
];
const IRDETO_SYSTEM_ID: [u8; 16] = [
    0x80, 0xA6, 0xBE, 0x7E, 0x14, 0x48, 0x4C, 0x37, 0x9E, 0x70, 0xD5, 0xAE, 0xBE, 0x04, 0xC8, 0xD2,
];
const MARLIN_SYSTEM_ID: [u8; 16] = [
    0x69, 0xF9, 0x08, 0xAF, 0x48, 0x16, 0x46, 0xEA, 0x91, 0x0C, 0xCD, 0x5D, 0xCC, 0xB0, 0xA3, 0x3A,
];
const NAGRA_SYSTEM_ID: [u8; 16] = [
    0xAD, 0xB4, 0x1C, 0x24, 0x2D, 0xBF, 0x4A, 0x6D, 0x95, 0x8B, 0x44, 0x57, 0xC0, 0xD2, 0x7B, 0x95,
];
const WISEPLAY_SYSTEM_ID: [u8; 16] = [
    0x3D, 0x5E, 0x6D, 0x35, 0x9B, 0x9A, 0x41, 0xE8, 0xB8, 0x43, 0xDD, 0x3C, 0x6E, 0x72, 0xC4, 0x2C,
];
const SECUREMEDIA_SYSTEM_ID: [u8; 16] = [
    0x1F, 0x83, 0xE1, 0xE8, 0x6E, 0xE9, 0x4F, 0x0D, 0xBA, 0x2F, 0x5E, 0xC4, 0xE3, 0xED, 0x1A, 0x66,
];

pub(crate) fn pssh_system_name(system_id: &[u8; 16]) -> Option<&'static str> {
    match *system_id {
        WIDEVINE_SYSTEM_ID => Some("widevine"),
        PLAYREADY_SYSTEM_ID => Some("playready"),
        FAIRPLAY_SYSTEM_ID => Some("fairplay"),
        FAIRPLAY_NETFLIX_SYSTEM_ID => Some("fairplay-netflix-variant"),
        COMMON_PSSH_SYSTEM_ID => Some("common"),
        CLEARKEY_SYSTEM_ID => Some("clearkey"),
        CLEARKEY_AES128_SYSTEM_ID => Some("clearkey-aes128"),
        ADOBE_PRIMETIME_SYSTEM_ID => Some("primetime"),
        IRDETO_SYSTEM_ID => Some("irdeto"),
        MARLIN_SYSTEM_ID => Some("marlin"),
        NAGRA_SYSTEM_ID => Some("nagra"),
        WISEPLAY_SYSTEM_ID => Some("wiseplay"),
        SECUREMEDIA_SYSTEM_ID => Some("securemedia"),
        _ => None,
    }
}

const BOX_HEADER_MIN_SIZE: usize = crate::box_types::BOX_HEADER_MIN_SIZE;

pub(crate) struct PsshInfo {
    pub system_id: [u8; 16],
    pub name: Option<String>,
    pub version: u8,
    pub data: Vec<u8>,
}

pub(crate) fn harvest_pssh_boxes(moov_bytes: &[u8]) -> Vec<PsshInfo> {
    let mut out: Vec<PsshInfo> = Vec::new();
    let body = moov_bytes[BOX_HEADER_MIN_SIZE.min(moov_bytes.len())..].as_ref();
    let mut offset = 0usize;
    while offset < body.len() {
        let Ok((child, consumed)) = parse_box(&body[offset..]) else {
            break;
        };
        if consumed == 0 {
            break;
        }
        if child.header.box_type.is(b"pssh")
            && let Ok(parsed) =
                ProtectionSystemSpecificHeaderBox::parse_box(&body[offset..offset + consumed])
        {
            if !out.iter().any(|p| p.system_id == parsed.system_id) {
                out.push(PsshInfo {
                    name: pssh_system_name(&parsed.system_id).map(String::from),
                    system_id: parsed.system_id,
                    version: parsed.version,
                    data: parsed.data,
                });
            }
        }
        offset += consumed;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    fn pssh_box(system_id: &[u8; 16]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&32u32.to_be_bytes());
        b.extend_from_slice(b"pssh");
        b.extend_from_slice(&[0, 0, 0, 0]);
        b.extend_from_slice(system_id);
        b.extend_from_slice(&0u32.to_be_bytes());
        b
    }

    fn fake_moov(children: &[u8]) -> Vec<u8> {
        let mut moov = Vec::new();
        moov.extend_from_slice(&((8 + children.len()) as u32).to_be_bytes());
        moov.extend_from_slice(b"moov");
        moov.extend_from_slice(children);
        moov
    }

    fn system_names(moov: &[u8]) -> Vec<String> {
        harvest_pssh_boxes(moov)
            .into_iter()
            .map(|p| p.name.unwrap_or_else(|| p.system_id.iter().map(|b| format!("{b:02x}")).collect()))
            .collect()
    }

    #[test]
    fn recognizes_widevine_and_playready_by_system_id() {
        let mut children = pssh_box(&WIDEVINE_SYSTEM_ID);
        children.extend_from_slice(&pssh_box(&PLAYREADY_SYSTEM_ID));
        let moov = fake_moov(&children);

        assert_eq!(system_names(&moov), vec!["widevine".to_string(), "playready".to_string()]);
    }

    #[test]
    fn recognizes_the_long_tail_systems() {
        let mut children = pssh_box(&IRDETO_SYSTEM_ID);
        children.extend_from_slice(&pssh_box(&MARLIN_SYSTEM_ID));
        children.extend_from_slice(&pssh_box(&NAGRA_SYSTEM_ID));
        children.extend_from_slice(&pssh_box(&ADOBE_PRIMETIME_SYSTEM_ID));
        children.extend_from_slice(&pssh_box(&WISEPLAY_SYSTEM_ID));
        let moov = fake_moov(&children);

        assert_eq!(
            system_names(&moov),
            vec!["irdeto", "marlin", "nagra", "primetime", "wiseplay"]
        );
    }

    #[test]
    fn unknown_system_id_falls_back_to_hex_and_duplicates_are_deduped() {
        let unknown = [0xAAu8; 16];
        let mut children = pssh_box(&unknown);
        children.extend_from_slice(&pssh_box(&unknown));
        children.extend_from_slice(&pssh_box(&WIDEVINE_SYSTEM_ID));
        let moov = fake_moov(&children);

        assert_eq!(system_names(&moov), vec!["aa".repeat(16), "widevine".to_string()]);
    }

    #[test]
    fn no_pssh_boxes_returns_empty() {
        let moov = fake_moov(&[]);
        assert!(harvest_pssh_boxes(&moov).is_empty());
    }
}
