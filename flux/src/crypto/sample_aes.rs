//! HLS Sample-AES + full-segment AES-128 content protection.

use alloc::string::String;
use alloc::vec::Vec;

use aes::cipher::{
    BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7, generic_array::GenericArray,
};

use crate::error::{Error, Result};

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

pub const KEY_LEN: usize = 16;
pub const BLOCK_LEN: usize = 16;

pub const NAL_TYPE_NON_IDR_SLICE: u8 = 1;
pub const NAL_TYPE_IDR_SLICE: u8 = 5;
pub const NAL_TYPE_MASK: u8 = 0x1F;
pub const H264_MIN_ENCRYPTED_NAL_LEN: usize = 48;
pub const H264_CLEAR_PREFIX_LEN: usize = 32;
pub const H264_SKIP_LEN: usize = 144;

pub const AUDIO_CLEAR_LEADER_LEN: usize = 16;
pub const ADTS_HEADER_LEN_NO_CRC: usize = 7;
pub const ADTS_HEADER_LEN_WITH_CRC: usize = 9;

fn cbc_encrypt_blocks_in_place(key: &[u8; KEY_LEN], iv: &[u8; BLOCK_LEN], data: &mut [u8]) {
    if data.is_empty() {
        return;
    }
    let mut enc = Aes128CbcEnc::new(key.into(), iv.into());
    for chunk in data.chunks_exact_mut(BLOCK_LEN) {
        let block = GenericArray::from_mut_slice(chunk);
        enc.encrypt_block_mut(block);
    }
}

fn cbc_decrypt_blocks_in_place(key: &[u8; KEY_LEN], iv: &[u8; BLOCK_LEN], data: &mut [u8]) {
    if data.is_empty() {
        return;
    }
    let mut dec = Aes128CbcDec::new(key.into(), iv.into());
    for chunk in data.chunks_exact_mut(BLOCK_LEN) {
        let block = GenericArray::from_mut_slice(chunk);
        dec.decrypt_block_mut(block);
    }
}

pub fn aes128_encrypt_segment(
    key: &[u8; KEY_LEN],
    iv: &[u8; BLOCK_LEN],
    plaintext: &[u8],
) -> Vec<u8> {
    let enc = Aes128CbcEnc::new(key.into(), iv.into());
    enc.encrypt_padded_vec_mut::<Pkcs7>(plaintext)
}

pub fn aes128_decrypt_segment(
    key: &[u8; KEY_LEN],
    iv: &[u8; BLOCK_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(BLOCK_LEN) {
        return Err(Error::InvalidInput(
            "AES-128 segment ciphertext length not a positive multiple of 16",
        ));
    }
    let dec = Aes128CbcDec::new(key.into(), iv.into());
    dec.decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|_| Error::InvalidInput("AES-128 segment PKCS#7 padding invalid"))
}

pub fn h264_nal_is_encrypted(nal: &[u8]) -> bool {
    if nal.len() <= H264_MIN_ENCRYPTED_NAL_LEN || nal.is_empty() {
        return false;
    }
    let nal_type = nal[0] & NAL_TYPE_MASK;
    nal_type == NAL_TYPE_NON_IDR_SLICE || nal_type == NAL_TYPE_IDR_SLICE
}

fn h264_unescape(escaped: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(escaped.len());
    let mut i = 0;
    while i < escaped.len() {
        if i + 3 < escaped.len()
            && escaped[i] == 0x00
            && escaped[i + 1] == 0x00
            && escaped[i + 2] == 0x03
            && escaped[i + 3] <= 0x03
        {
            out.push(0x00);
            out.push(0x00);
            i += 3;
        } else {
            out.push(escaped[i]);
            i += 1;
        }
    }
    out
}

fn h264_escape(unescaped: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(unescaped.len());
    let mut zero_run = 0usize;
    for &b in unescaped {
        if zero_run >= 2 && b <= 0x03 {
            out.push(0x03);
            zero_run = 0;
        }
        out.push(b);
        if b == 0x00 {
            zero_run += 1;
        } else {
            zero_run = 0;
        }
    }
    out
}

fn h264_transform_pattern(
    key: &[u8; KEY_LEN],
    iv: &[u8; BLOCK_LEN],
    nal: &mut [u8],
    encrypt: bool,
) {
    let mut offset = H264_CLEAR_PREFIX_LEN;
    while offset < nal.len() {
        let remaining = nal.len() - offset;
        if remaining >= BLOCK_LEN {
            let block = &mut nal[offset..offset + BLOCK_LEN];
            if encrypt {
                cbc_encrypt_blocks_in_place(key, iv, block);
            } else {
                cbc_decrypt_blocks_in_place(key, iv, block);
            }
            offset += BLOCK_LEN;
        } else {
            break;
        }
        offset += H264_SKIP_LEN.min(nal.len().saturating_sub(offset));
    }
}

pub fn h264_encrypt_nal(key: &[u8; KEY_LEN], iv: &[u8; BLOCK_LEN], nal: &[u8]) -> Vec<u8> {
    let mut raw = h264_unescape(nal);
    if !h264_nal_is_encrypted(&raw) {
        return nal.to_vec();
    }
    h264_transform_pattern(key, iv, &mut raw, true);
    h264_escape(&raw)
}

pub fn h264_decrypt_nal(key: &[u8; KEY_LEN], iv: &[u8; BLOCK_LEN], nal: &[u8]) -> Vec<u8> {
    let mut raw = h264_unescape(nal);
    if !h264_nal_is_encrypted(&raw) {
        return nal.to_vec();
    }
    h264_transform_pattern(key, iv, &mut raw, false);
    h264_escape(&raw)
}

fn audio_transform(
    key: &[u8; KEY_LEN],
    iv: &[u8; BLOCK_LEN],
    frame: &mut [u8],
    clear_prefix: usize,
    encrypt: bool,
) {
    if frame.len() <= clear_prefix {
        return;
    }
    let body = &mut frame[clear_prefix..];
    let whole = (body.len() / BLOCK_LEN) * BLOCK_LEN;
    if whole == 0 {
        return;
    }
    let blocks = &mut body[..whole];
    if encrypt {
        cbc_encrypt_blocks_in_place(key, iv, blocks);
    } else {
        cbc_decrypt_blocks_in_place(key, iv, blocks);
    }
}

pub fn adts_header_len(frame: &[u8]) -> Result<usize> {
    if frame.len() < ADTS_HEADER_LEN_NO_CRC {
        return Err(Error::InvalidInput("ADTS frame shorter than 7-byte header"));
    }
    let protection_absent = frame[1] & 0x01;
    Ok(if protection_absent == 1 {
        ADTS_HEADER_LEN_NO_CRC
    } else {
        ADTS_HEADER_LEN_WITH_CRC
    })
}

pub fn aac_encrypt_frame(
    key: &[u8; KEY_LEN],
    iv: &[u8; BLOCK_LEN],
    frame: &[u8],
) -> Result<Vec<u8>> {
    let hdr = adts_header_len(frame)?;
    let mut out = frame.to_vec();
    audio_transform(key, iv, &mut out, hdr + AUDIO_CLEAR_LEADER_LEN, true);
    Ok(out)
}

pub fn aac_decrypt_frame(
    key: &[u8; KEY_LEN],
    iv: &[u8; BLOCK_LEN],
    frame: &[u8],
) -> Result<Vec<u8>> {
    let hdr = adts_header_len(frame)?;
    let mut out = frame.to_vec();
    audio_transform(key, iv, &mut out, hdr + AUDIO_CLEAR_LEADER_LEN, false);
    Ok(out)
}

pub fn ac3_encrypt_frame(key: &[u8; KEY_LEN], iv: &[u8; BLOCK_LEN], frame: &[u8]) -> Vec<u8> {
    let mut out = frame.to_vec();
    audio_transform(key, iv, &mut out, AUDIO_CLEAR_LEADER_LEN, true);
    out
}

pub fn ac3_decrypt_frame(key: &[u8; KEY_LEN], iv: &[u8; BLOCK_LEN], frame: &[u8]) -> Vec<u8> {
    let mut out = frame.to_vec();
    audio_transform(key, iv, &mut out, AUDIO_CLEAR_LEADER_LEN, false);
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum HlsEncryptionMethod {
    Aes128,
    SampleAes,
}

impl HlsEncryptionMethod {
    pub fn name(&self) -> &'static str {
        match self {
            HlsEncryptionMethod::Aes128 => "AES-128",
            HlsEncryptionMethod::SampleAes => "SAMPLE-AES",
        }
    }
}

bitforge::impl_spec_display!(HlsEncryptionMethod);

pub fn format_iv(iv: &[u8; BLOCK_LEN]) -> String {
    let mut s = String::with_capacity(2 + 2 * BLOCK_LEN);
    s.push_str("0x");
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &b in iv {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0F) as usize] as char);
    }
    s
}

pub fn iv_from_sequence_number(media_sequence: u128) -> [u8; BLOCK_LEN] {
    media_sequence.to_be_bytes()
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ExtXKey {
    pub method: HlsEncryptionMethod,
    pub uri: String,
    pub iv: Option<[u8; BLOCK_LEN]>,
    pub keyformat: Option<String>,
    pub keyformatversions: Option<String>,
}

impl ExtXKey {
    pub fn fairplay_sample_aes(skd_uri: impl Into<String>) -> Self {
        Self {
            method: HlsEncryptionMethod::SampleAes,
            uri: skd_uri.into(),
            iv: None,
            keyformat: Some(String::from("com.apple.streamingkeydelivery")),
            keyformatversions: Some(String::from("1")),
        }
    }

    pub fn aes128(uri: impl Into<String>, iv: [u8; BLOCK_LEN]) -> Self {
        Self {
            method: HlsEncryptionMethod::Aes128,
            uri: uri.into(),
            iv: Some(iv),
            keyformat: None,
            keyformatversions: None,
        }
    }

    pub fn to_tag(&self) -> String {
        let mut s = String::from("#EXT-X-KEY:METHOD=");
        s.push_str(self.method.name());
        s.push_str(",URI=\"");
        s.push_str(&self.uri);
        s.push('"');
        if let Some(iv) = self.iv {
            s.push_str(",IV=");
            s.push_str(&format_iv(&iv));
        }
        if let Some(ref kf) = self.keyformat {
            s.push_str(",KEYFORMAT=\"");
            s.push_str(kf);
            s.push('"');
        }
        if let Some(ref kfv) = self.keyformatversions {
            s.push_str(",KEYFORMATVERSIONS=\"");
            s.push_str(kfv);
            s.push('"');
        }
        s
    }
}

impl core::fmt::Display for ExtXKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_tag())
    }
}