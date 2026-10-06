//! In-place WebM/Matroska (EBML) CENC decrypt.

use alloc::collections::BTreeMap;
use alloc::string::String;

use alloc::vec::Vec;

use crate::cenc::SubSampleEntry;
use crate::crypto::cenc_crypto::apply_ctr;
use crate::error::{Error, Result};

const SEGMENT: u32 = 0x1853_8067;
const TRACKS: u32 = 0x1654_AE6B;
const TRACK_ENTRY: u32 = 0xAE;
const TRACK_NUMBER: u32 = 0xD7;
const CONTENT_ENCODINGS: u32 = 0x6D80;
const CONTENT_ENCODING: u32 = 0x6240;
const CONTENT_ENCRYPTION: u32 = 0x5035;
const CONTENT_ENC_KEY_ID: u32 = 0x47E2;
const CLUSTER: u32 = 0x1F43_B675;
const SIMPLE_BLOCK: u32 = 0xA3;
const BLOCK_GROUP: u32 = 0xA0;
const BLOCK: u32 = 0xA1;
const SEEK_HEAD: u32 = 0x114D_9B74;
const CUES: u32 = 0x1C53_BB6B;

const BLOCK_FLAG_LACING_MASK: u8 = 0x06;

const WEBM_IV_SIZE: usize = 8;
const SIGNAL_ENCRYPTED: u8 = 0x01;
const SIGNAL_PARTITIONED: u8 = 0x02;

const KEY_LEN: usize = 16;

pub fn decrypt_webm(input: &[u8], keys: &[([u8; KEY_LEN], [u8; KEY_LEN])]) -> Result<Vec<u8>> {
    let scanned = scan_track_kids(input)?;

    let mut track_keys: BTreeMap<u64, [u8; KEY_LEN]> = BTreeMap::new();
    for (track_number, kid) in scanned {
        let Some(kid) = kid else { continue };
        if let Some((_, key)) = keys.iter().find(|(k, _)| *k == kid) {
            track_keys.insert(track_number, *key);
        }
    }

    if track_keys.is_empty() {
        return Err(Error::InvalidInput(
            "webm: no track's ContentEncKeyID matches any supplied --key pair",
        ));
    }

    rewrite_children(input, |id, body| {
        if id != SEGMENT {
            return Ok(ElemAction::Keep);
        }
        let new_segment = rewrite_children(body, |id2, body2| match id2 {
            TRACKS => Ok(ElemAction::Replace(rewrite_tracks(body2, &track_keys)?)),
            CLUSTER => Ok(ElemAction::Replace(rewrite_cluster(body2, &track_keys)?)),
            SEEK_HEAD | CUES => Ok(ElemAction::Drop),
            _ => Ok(ElemAction::Keep),
        })?;
        Ok(ElemAction::Replace(new_segment))
    })
}


fn scan_track_kids(input: &[u8]) -> Result<Vec<(u64, Option<[u8; KEY_LEN]>)>> {
    let mut out = Vec::new();
    let mut r = EbmlReader::new(input);
    while let Some(e) = r.next()? {
        if e.id != SEGMENT {
            continue;
        }
        let mut r2 = EbmlReader::new(e.body);
        while let Some(e2) = r2.next()? {
            if e2.id != TRACKS {
                continue;
            }
            let mut r3 = EbmlReader::new(e2.body);
            while let Some(e3) = r3.next()? {
                if e3.id == TRACK_ENTRY {
                    out.push(parse_track_entry_kid(e3.body)?);
                }
            }
        }
    }
    Ok(out)
}

fn parse_track_entry_kid(te: &[u8]) -> Result<(u64, Option<[u8; KEY_LEN]>)> {
    let mut track_number = 0u64;
    let mut kid = None;
    let mut r = EbmlReader::new(te);
    while let Some(e) = r.next()? {
        match e.id {
            TRACK_NUMBER => track_number = read_uint(e.body),
            CONTENT_ENCODINGS => kid = find_content_enc_kid(e.body)?,
            _ => {}
        }
    }
    Ok((track_number, kid))
}

fn find_content_enc_kid(encodings: &[u8]) -> Result<Option<[u8; KEY_LEN]>> {
    let mut r = EbmlReader::new(encodings);
    while let Some(e) = r.next()? {
        if e.id != CONTENT_ENCODING {
            continue;
        }
        let mut r2 = EbmlReader::new(e.body);
        while let Some(e2) = r2.next()? {
            if e2.id != CONTENT_ENCRYPTION {
                continue;
            }
            let mut r3 = EbmlReader::new(e2.body);
            while let Some(e3) = r3.next()? {
                if e3.id == CONTENT_ENC_KEY_ID && e3.body.len() == KEY_LEN {
                    let mut kid = [0u8; KEY_LEN];
                    kid.copy_from_slice(e3.body);
                    return Ok(Some(kid));
                }
            }
        }
    }
    Ok(None)
}


const TRACK_TYPE: u32 = 0x83;
const CODEC_ID: u32 = 0x86;
const LANGUAGE: u32 = 0x22B59C;
const VIDEO: u32 = 0xE0;
const PIXEL_WIDTH: u32 = 0xB0;
const PIXEL_HEIGHT: u32 = 0xBA;
const AUDIO: u32 = 0xE1;
const SAMPLING_FREQUENCY: u32 = 0xB5;
const CHANNELS: u32 = 0x9F;
const BIT_DEPTH: u32 = 0x6264;
const CONTENT_ENC_ALGO: u32 = 0x47E1;
const CONTENT_ENC_AES_SETTINGS: u32 = 0x47E7;
const AES_SETTINGS_CIPHER_MODE: u32 = 0x47E8;

pub(crate) struct WebmTrackMeta {
    pub track_number: u64,
    pub stream_type: &'static str,
    pub codec_id: String,
    pub language: Option<String>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub sampling_frequency: Option<f64>,
    pub num_channels: Option<u64>,
    pub bit_depth: Option<u64>,
    pub encrypted: bool,
    pub kid: Option<[u8; KEY_LEN]>,
    pub scheme: Option<String>,
    pub iv_size: Option<u8>,
    pub pattern: Option<String>,
}

pub(crate) fn harvest_webm_track_meta(input: &[u8]) -> Result<Vec<WebmTrackMeta>> {
    let mut out = Vec::new();
    let mut r = EbmlReader::new(input);
    while let Some(e) = r.next()? {
        if e.id != SEGMENT {
            continue;
        }
        let mut r2 = EbmlReader::new(e.body);
        while let Some(e2) = r2.next()? {
            if e2.id != TRACKS {
                continue;
            }
            let mut r3 = EbmlReader::new(e2.body);
            while let Some(e3) = r3.next()? {
                if e3.id == TRACK_ENTRY {
                    out.push(parse_track_entry_meta(e3.body)?);
                }
            }
        }
    }
    Ok(out)
}

fn parse_track_entry_meta(te: &[u8]) -> Result<WebmTrackMeta> {
    let mut m = WebmTrackMeta {
        track_number: 0,
        stream_type: "Unknown",
        codec_id: String::new(),
        language: None,
        width: None,
        height: None,
        sampling_frequency: None,
        num_channels: None,
        bit_depth: None,
        encrypted: false,
        kid: None,
        scheme: None,
        iv_size: None,
        pattern: None,
    };
    let mut r = EbmlReader::new(te);
    while let Some(e) = r.next()? {
        match e.id {
            TRACK_NUMBER => m.track_number = read_uint(e.body),
            TRACK_TYPE => {
                m.stream_type = match e.body.first().copied().unwrap_or(0) {
                    1 => "Video",
                    2 => "Audio",
                    0x11 | 0x12 => "Subtitle",
                    _ => "Unknown",
                }
            }
            CODEC_ID => m.codec_id = String::from_utf8_lossy(e.body).into_owned(),
            LANGUAGE => m.language = Some(String::from_utf8_lossy(e.body).into_owned()),
            VIDEO => {
                let mut vr = EbmlReader::new(e.body);
                while let Some(ve) = vr.next()? {
                    match ve.id {
                        PIXEL_WIDTH => m.width = Some(read_uint(ve.body) as u32),
                        PIXEL_HEIGHT => m.height = Some(read_uint(ve.body) as u32),
                        _ => {}
                    }
                }
            }
            AUDIO => {
                let mut ar = EbmlReader::new(e.body);
                while let Some(ae) = ar.next()? {
                    match ae.id {
                        SAMPLING_FREQUENCY => m.sampling_frequency = Some(read_float(ae.body)),
                        CHANNELS => m.num_channels = Some(read_uint(ae.body)),
                        BIT_DEPTH => m.bit_depth = Some(read_uint(ae.body)),
                        _ => {}
                    }
                }
            }
            CONTENT_ENCODINGS => parse_content_encodings_meta(e.body, &mut m)?,
            _ => {}
        }
    }
    Ok(m)
}

fn parse_content_encodings_meta(encodings: &[u8], m: &mut WebmTrackMeta) -> Result<()> {
    let mut r = EbmlReader::new(encodings);
    while let Some(e) = r.next()? {
        if e.id != CONTENT_ENCODING {
            continue;
        }
        let mut cipher: u8 = 0;
        let mut kid: Option<[u8; KEY_LEN]> = None;
        let mut r2 = EbmlReader::new(e.body);
        while let Some(e2) = r2.next()? {
            match e2.id {
                CONTENT_ENCRYPTION => {
                    let mut r3 = EbmlReader::new(e2.body);
                    while let Some(e3) = r3.next()? {
                        match e3.id {
                            CONTENT_ENC_ALGO => {
                                let _ = e3.body.first().copied();
                            }
                            CONTENT_ENC_KEY_ID if e3.body.len() == KEY_LEN => {
                                let mut k = [0u8; KEY_LEN];
                                k.copy_from_slice(e3.body);
                                kid = Some(k);
                            }
                            CONTENT_ENC_AES_SETTINGS => {
                                let mut r4 = EbmlReader::new(e3.body);
                                while let Some(e4) = r4.next()? {
                                    if e4.id == AES_SETTINGS_CIPHER_MODE {
                                        cipher = e4.body.first().copied().unwrap_or(0);
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
        if kid.is_some() {
            m.encrypted = true;
            m.kid = kid;
            let cbcs = cipher == 2;
            m.scheme = Some(String::from(if cbcs { "cbcs" } else { "cenc" }));
            m.iv_size = Some(if cbcs { 16 } else { 8 });
            m.pattern = Some(String::from(if cbcs { "1:9" } else { "0:0" }));
        }
    }
    Ok(())
}

fn read_float(body: &[u8]) -> f64 {
    match body.len() {
        4 => f32::from_be_bytes([body[0], body[1], body[2], body[3]]) as f64,
        8 => f64::from_be_bytes(body.try_into().unwrap()),
        _ => 0.0,
    }
}


fn rewrite_tracks(tracks: &[u8], track_keys: &BTreeMap<u64, [u8; KEY_LEN]>) -> Result<Vec<u8>> {
    rewrite_children(tracks, |id, body| {
        if id == TRACK_ENTRY {
            Ok(ElemAction::Replace(rewrite_track_entry(body, track_keys)?))
        } else {
            Ok(ElemAction::Keep)
        }
    })
}

fn rewrite_track_entry(te: &[u8], track_keys: &BTreeMap<u64, [u8; KEY_LEN]>) -> Result<Vec<u8>> {
    let mut track_number = 0u64;
    let mut r = EbmlReader::new(te);
    while let Some(e) = r.next()? {
        if e.id == TRACK_NUMBER {
            track_number = read_uint(e.body);
        }
    }
    let drop_encodings = track_keys.contains_key(&track_number);

    rewrite_children(te, |id, _body| {
        if id == CONTENT_ENCODINGS && drop_encodings {
            Ok(ElemAction::Drop)
        } else {
            Ok(ElemAction::Keep)
        }
    })
}

fn rewrite_cluster(cluster: &[u8], track_keys: &BTreeMap<u64, [u8; KEY_LEN]>) -> Result<Vec<u8>> {
    rewrite_children(cluster, |id, body| match id {
        SIMPLE_BLOCK => match rewrite_block_bytes(body, track_keys)? {
            Some(new_body) => Ok(ElemAction::Replace(new_body)),
            None => Ok(ElemAction::Keep),
        },
        BLOCK_GROUP => {
            let new_group = rewrite_children(body, |gid, gbody| {
                if gid == BLOCK {
                    match rewrite_block_bytes(gbody, track_keys)? {
                        Some(new_block) => Ok(ElemAction::Replace(new_block)),
                        None => Ok(ElemAction::Keep),
                    }
                } else {
                    Ok(ElemAction::Keep)
                }
            })?;
            Ok(ElemAction::Replace(new_group))
        }
        _ => Ok(ElemAction::Keep),
    })
}

enum LaceKind {
    Xiph,
    Ebml,
    FixedSize,
}

fn lace_kind_from_flags(flags: u8) -> Option<LaceKind> {
    match (flags & BLOCK_FLAG_LACING_MASK) >> 1 {
        0 => None,
        1 => Some(LaceKind::Xiph),
        2 => Some(LaceKind::FixedSize),
        3 => Some(LaceKind::Ebml),
        _ => unreachable!("2-bit field"),
    }
}

fn rewrite_block_bytes(body: &[u8], track_keys: &BTreeMap<u64, [u8; KEY_LEN]>) -> Result<Option<Vec<u8>>> {
    let (track_number, tn_len) = read_vint_value(body)
        .ok_or(Error::InvalidInput("webm block: truncated track-number VINT"))?;
    let Some(key) = track_keys.get(&track_number) else {
        return Ok(None);
    };
    if body.len() < tn_len + 3 {
        return Err(Error::BufferTooShort {
            need: tn_len + 3,
            have: body.len(),
            what: "webm block header (rel-ts + flags)",
        });
    }
    let flags = body[tn_len + 2];
    let mut header = body[..tn_len + 3].to_vec();
    let payload = &body[tn_len + 3..];

    let new_payload = match lace_kind_from_flags(flags) {
        None => decrypt_block_frame(payload, key)?,
        Some(kind) => {
            let frames = split_laced_frames(kind, payload)?;
            let mut decrypted = Vec::with_capacity(frames.len());
            for f in frames {
                decrypted.push(decrypt_block_frame(f, key)?);
            }
            let relaced = build_ebml_laced_payload(&decrypted)?;
            header[tn_len + 2] = (flags & !BLOCK_FLAG_LACING_MASK) | (0b11 << 1);
            relaced
        }
    };

    let mut out = Vec::with_capacity(header.len() + new_payload.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&new_payload);
    Ok(Some(out))
}

fn split_laced_frames(kind: LaceKind, payload: &[u8]) -> Result<Vec<&[u8]>> {
    let lace_head = *payload
        .first()
        .ok_or(Error::InvalidInput("webm block: truncated lace head"))?;
    let frame_count = lace_head as usize + 1;
    let mut pos = 1usize;
    let mut sizes: Vec<usize> = Vec::with_capacity(frame_count.saturating_sub(1));

    match kind {
        LaceKind::FixedSize => {}
        LaceKind::Xiph => {
            for _ in 0..frame_count - 1 {
                let mut size = 0usize;
                loop {
                    let b = *payload
                        .get(pos)
                        .ok_or(Error::InvalidInput("webm block: truncated Xiph lace size"))?;
                    pos += 1;
                    size += b as usize;
                    if b != 0xFF {
                        break;
                    }
                }
                sizes.push(size);
            }
        }
        LaceKind::Ebml => {
            let mut prev: i64 = 0;
            for i in 0..frame_count - 1 {
                let (raw, len) = read_vint_value(&payload[pos..])
                    .ok_or(Error::InvalidInput("webm block: truncated EBML lace size"))?;
                if i == 0 {
                    prev = raw as i64;
                } else {
                    let bias = (1i64 << (7 * len - 1)) - 1;
                    prev += raw as i64 - bias;
                }
                if prev < 0 {
                    return Err(Error::InvalidInput("webm block: EBML lace size underflow"));
                }
                sizes.push(prev as usize);
                pos += len;
            }
        }
    }

    let data = &payload[pos..];
    let mut frames = Vec::with_capacity(frame_count);
    if matches!(kind, LaceKind::FixedSize) {
        if frame_count == 0 || data.len() % frame_count != 0 {
            return Err(Error::InvalidInput(
                "webm block: fixed-size lace data not evenly divisible by frame count",
            ));
        }
        let size = data.len() / frame_count;
        let mut offset = 0usize;
        for _ in 0..frame_count {
            frames.push(&data[offset..offset + size]);
            offset += size;
        }
    } else {
        let mut offset = 0usize;
        for &size in &sizes {
            if offset + size > data.len() {
                return Err(Error::InvalidInput("webm block: lace frame size exceeds available data"));
            }
            frames.push(&data[offset..offset + size]);
            offset += size;
        }
        frames.push(&data[offset..]);
    }
    Ok(frames)
}

fn build_ebml_laced_payload(frames: &[Vec<u8>]) -> Result<Vec<u8>> {
    let frame_count = frames.len();
    if frame_count < 2 || frame_count > 256 {
        return Err(Error::InvalidInput("webm block: lace frame count out of range (2..=256)"));
    }
    let mut out = Vec::new();
    out.push((frame_count - 1) as u8);

    let mut prev = frames[0].len() as i64;
    out.extend_from_slice(&encode_size_vint(prev as u64, minimal_vint_width(prev as u64))?);
    for f in &frames[1..frame_count - 1] {
        let size = f.len() as i64;
        let delta = size - prev;
        let width = signed_vint_width(delta);
        let bias = (1i64 << (7 * width - 1)) - 1;
        out.extend_from_slice(&encode_size_vint((delta + bias) as u64, width)?);
        prev = size;
    }
    for f in frames {
        out.extend_from_slice(f);
    }
    Ok(out)
}

fn minimal_vint_width(value: u64) -> usize {
    for n in 1..=8 {
        let data_bits = 7 * n;
        let max = if data_bits >= 64 { u64::MAX } else { (1u64 << data_bits) - 1 };
        if value <= max {
            return n;
        }
    }
    8
}

fn signed_vint_width(delta: i64) -> usize {
    for n in 1..=8 {
        let bias = (1i64 << (7 * n - 1)) - 1;
        if delta >= -bias && delta <= bias + 1 {
            return n;
        }
    }
    8
}

fn decrypt_block_frame(frame: &[u8], key: &[u8; KEY_LEN]) -> Result<Vec<u8>> {
    let signal = *frame
        .first()
        .ok_or(Error::InvalidInput("webm: empty block frame"))?;

    if signal & SIGNAL_ENCRYPTED == 0 {
        return Ok(frame[1..].to_vec());
    }

    if frame.len() < 1 + WEBM_IV_SIZE {
        return Err(Error::BufferTooShort {
            need: 1 + WEBM_IV_SIZE,
            have: frame.len(),
            what: "webm encrypted frame (signal byte + IV)",
        });
    }
    let iv = &frame[1..1 + WEBM_IV_SIZE];

    if signal & SIGNAL_PARTITIONED == 0 {
        let mut data = frame[1 + WEBM_IV_SIZE..].to_vec();
        apply_ctr(iv, key, &[], &mut data)?;
        return Ok(data);
    }

    let after_iv = &frame[1 + WEBM_IV_SIZE..];
    let num_partitions = *after_iv
        .first()
        .ok_or(Error::InvalidInput("webm: truncated partitioned frame (missing num_partitions)"))?
        as usize;
    let offsets_end = 1 + num_partitions * 4;
    if after_iv.len() < offsets_end {
        return Err(Error::BufferTooShort {
            need: offsets_end,
            have: after_iv.len(),
            what: "webm partitioned frame (partition-offset table)",
        });
    }
    let mut offsets: Vec<u32> = Vec::with_capacity(num_partitions);
    for i in 0..num_partitions {
        let o = 1 + i * 4;
        offsets.push(u32::from_be_bytes([
            after_iv[o],
            after_iv[o + 1],
            after_iv[o + 2],
            after_iv[o + 3],
        ]));
    }
    let mut data = after_iv[offsets_end..].to_vec();
    let subsamples = partition_offsets_to_subsamples(&offsets, data.len())?;
    apply_ctr(iv, key, &subsamples, &mut data)?;
    Ok(data)
}

fn partition_offsets_to_subsamples(offsets: &[u32], data_len: usize) -> Result<Vec<SubSampleEntry>> {
    let mut boundaries: Vec<u64> = Vec::with_capacity(offsets.len() + 2);
    boundaries.push(0);
    boundaries.extend(offsets.iter().map(|&o| o as u64));
    boundaries.push(data_len as u64);

    let mut subsamples = Vec::new();
    let mut pending_clear: u64 = 0;
    for (run_index, w) in boundaries.windows(2).enumerate() {
        let (start, end) = (w[0], w[1]);
        if end < start {
            return Err(Error::InvalidInput(
                "webm: partition-offset table is not monotonically increasing",
            ));
        }
        let len = end - start;
        let is_cipher = run_index % 2 == 1;
        if is_cipher {
            let clear = u16::try_from(pending_clear).map_err(|_| {
                Error::InvalidInput("webm: partitioned frame's clear run exceeds 65535 bytes")
            })?;
            let cipher = u32::try_from(len)
                .map_err(|_| Error::InvalidInput("webm: partitioned frame's cipher run exceeds 4 GiB"))?;
            subsamples.push(SubSampleEntry {
                bytes_of_clear_data: clear,
                bytes_of_protected_data: cipher,
            });
            pending_clear = 0;
        } else {
            pending_clear += len;
        }
    }
    if pending_clear > 0 {
        let clear = u16::try_from(pending_clear).map_err(|_| {
            Error::InvalidInput("webm: partitioned frame's trailing clear run exceeds 65535 bytes")
        })?;
        subsamples.push(SubSampleEntry {
            bytes_of_clear_data: clear,
            bytes_of_protected_data: 0,
        });
    }
    Ok(subsamples)
}


enum ElemAction {
    Keep,
    Drop,
    Replace(Vec<u8>),
}

fn rewrite_children(buf: &[u8], mut f: impl FnMut(u32, &[u8]) -> Result<ElemAction>) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(buf.len());
    let mut r = EbmlReader::new(buf);
    while let Some(e) = r.next()? {
        match f(e.id, e.body)? {
            ElemAction::Keep => out.extend_from_slice(e.span),
            ElemAction::Drop => {}
            ElemAction::Replace(new_body) => {
                out.extend_from_slice(e.id_bytes);
                if e.unknown {
                    out.extend_from_slice(e.size_field);
                } else {
                    out.extend_from_slice(&encode_size_vint(new_body.len() as u64, e.size_len)?);
                }
                out.extend_from_slice(&new_body);
            }
        }
    }
    Ok(out)
}

fn encode_size_vint(value: u64, width: usize) -> Result<Vec<u8>> {
    if width == 0 || width > 8 {
        return Err(Error::InvalidInput("webm: unsupported EBML size width"));
    }
    let data_bits = 7 * width;
    let max = if data_bits >= 64 { u64::MAX } else { (1u64 << data_bits) - 1 };
    if value > max {
        return Err(Error::InvalidInput(
            "webm: shrunk element size unexpectedly overflows its original width",
        ));
    }
    let marker_bit = 7 * width;
    let encoded: u64 = value | (1u64 << marker_bit);
    Ok(encoded.to_be_bytes()[8 - width..].to_vec())
}

struct Elem<'a> {
    id: u32,
    id_bytes: &'a [u8],
    size_field: &'a [u8],
    size_len: usize,
    unknown: bool,
    body: &'a [u8],
    span: &'a [u8],
}

struct EbmlReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> EbmlReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn next(&mut self) -> Result<Option<Elem<'a>>> {
        if self.pos >= self.buf.len() {
            return Ok(None);
        }
        let start = self.pos;
        let rest = &self.buf[start..];
        let (_id, id_len) =
            read_element_id(rest).ok_or(Error::InvalidInput("webm: truncated element ID"))?;
        let id_bytes = &rest[..id_len];
        let mut id: u32 = 0;
        for &b in id_bytes {
            id = (id << 8) | b as u32;
        }

        let after_id = &rest[id_len..];
        let (size, size_len, unknown) =
            read_vint(after_id).ok_or(Error::InvalidInput("webm: truncated element size"))?;
        let size_field = &after_id[..size_len];

        let body_start = start + id_len + size_len;
        if body_start > self.buf.len() {
            return Err(Error::BufferTooShort {
                need: body_start,
                have: self.buf.len(),
                what: "webm element body",
            });
        }
        let body_end = if unknown {
            self.buf.len()
        } else {
            (body_start + size as usize).min(self.buf.len())
        };
        let body = &self.buf[body_start..body_end];
        let span = &self.buf[start..body_end];
        self.pos = body_end;
        Ok(Some(Elem {
            id,
            id_bytes,
            size_field,
            size_len,
            unknown,
            body,
            span,
        }))
    }
}

fn read_element_id(buf: &[u8]) -> Option<(u32, usize)> {
    let first = *buf.first()?;
    if first == 0 {
        return None;
    }
    let len = first.leading_zeros() as usize + 1;
    if len > 4 || buf.len() < len {
        return None;
    }
    let mut id: u32 = 0;
    for &b in &buf[..len] {
        id = (id << 8) | b as u32;
    }
    Some((id, len))
}

fn read_vint(buf: &[u8]) -> Option<(u64, usize, bool)> {
    let first = *buf.first()?;
    if first == 0 {
        return None;
    }
    let len = first.leading_zeros() as usize + 1;
    if buf.len() < len {
        return None;
    }
    let first_mask: u8 = if len >= 8 { 0 } else { 0xFF >> len };
    let mut value = (first & first_mask) as u64;
    for &b in &buf[1..len] {
        value = (value << 8) | b as u64;
    }
    let data_bits = 7 * len;
    let max = if data_bits >= 64 { u64::MAX } else { (1u64 << data_bits) - 1 };
    Some((value, len, value == max))
}

fn read_vint_value(buf: &[u8]) -> Option<(u64, usize)> {
    read_vint(buf).map(|(v, len, _)| (v, len))
}

fn read_uint(body: &[u8]) -> u64 {
    let mut v: u64 = 0;
    for &b in body.iter().take(8) {
        v = (v << 8) | b as u64;
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vint_size_roundtrip() {
        let enc = encode_size_vint(300, 2).unwrap();
        assert_eq!(enc.len(), 2);
        let (val, len, unknown) = read_vint(&enc).unwrap();
        assert_eq!(val, 300);
        assert_eq!(len, 2);
        assert!(!unknown);
    }

    #[test]
    fn vint_size_width_matches_shaka_test_vector() {
        assert_eq!(WEBM_IV_SIZE, 8);
        assert_eq!(SIGNAL_ENCRYPTED, 0x01);
        assert_eq!(SIGNAL_PARTITIONED, 0x02);
    }

    #[test]
    fn clear_frame_drops_only_signal_byte() {
        let frame = [0x00u8, 0xFC, 0x11, 0x22];
        let out = decrypt_block_frame(&frame, &[0u8; 16]).unwrap();
        assert_eq!(out, vec![0xFC, 0x11, 0x22]);
    }

    #[test]
    fn partition_offsets_build_expected_subsamples() {
        let subs = partition_offsets_to_subsamples(&[19], 211).unwrap();
        assert_eq!(
            subs,
            vec![SubSampleEntry {
                bytes_of_clear_data: 19,
                bytes_of_protected_data: 192,
            }]
        );
    }

    #[test]
    fn partition_offsets_reject_non_monotonic_table() {
        assert!(partition_offsets_to_subsamples(&[50, 10], 100).is_err());
    }

    #[test]
    fn partitioned_frame_leaves_clear_run_byte_for_byte_unchanged() {
        #[rustfmt::skip]
        let frame: &[u8] = &[
            0x03, 0x9b, 0x29, 0x36, 0x19, 0x17, 0xe3, 0x16, 0x45, 0x01, 0x00, 0x00, 0x00, 0x13,
            0x86, 0x00, 0x40, 0x92, 0x9c, 0x7c, 0x51, 0xc0, 0x00, 0x0b, 0x64, 0xa4, 0xaf, 0xad,
            0x80, 0x63, 0xdf, 0xd8, 0x85, 0x75, 0x84, 0xdd, 0x9a, 0x9b, 0x81, 0xd4, 0x76, 0x80,
            0xf0, 0xd1, 0xde, 0x8e, 0xe0, 0xfd, 0x7b, 0x7f, 0xbe, 0x43, 0x1c, 0xa8, 0xdf, 0x38,
            0x75, 0xde, 0x0c, 0xff, 0x62, 0xf8, 0x5d, 0x5d, 0xb4, 0x9e, 0x49, 0x37, 0x82, 0x0d,
            0x4a, 0xc8, 0x1e, 0xfa, 0xad, 0x2f, 0xf0, 0x6b, 0x0c, 0x13, 0x9a, 0x4f, 0x02, 0x1b,
            0x38, 0x6f, 0xae, 0xdf, 0x7e, 0x2f, 0x6b, 0x15, 0xa8, 0xfc, 0x3f, 0xa5, 0x3a, 0x16,
            0xab, 0x79, 0x4c, 0x37, 0x42, 0xa8, 0xc1, 0x38, 0xd3, 0xe6, 0x75, 0xfc, 0xce, 0xcd,
            0x65, 0xaf, 0xf9, 0x56, 0xf1, 0x7e, 0x49, 0x83, 0x3b, 0x0c, 0xbe, 0xde, 0xab, 0xee,
            0x14, 0x50, 0x59, 0x6c, 0x20, 0x38, 0x63, 0x2c, 0xf5, 0xaa, 0xd9, 0xc4, 0xba, 0x62,
            0x21, 0x64, 0xe4, 0xfe, 0xd1, 0x04, 0x12, 0x77, 0xc3, 0xcf, 0x21, 0x85, 0x90, 0x81,
            0x09, 0xb4, 0x3d, 0x0a, 0x39, 0x49, 0x64, 0xaf, 0x09, 0xe5, 0xf9, 0x13, 0xe6, 0xcc,
            0x0b, 0x31, 0xc6, 0x1d, 0x98, 0xf8, 0x26, 0x43, 0x80, 0x13, 0xa1, 0x42, 0xe4, 0x2a,
            0x95, 0x7b, 0x7b, 0x6e, 0xb0, 0xbc, 0x5a, 0x92, 0x44, 0x84, 0x3b, 0x62, 0xa0, 0xaa,
            0x25, 0x1e, 0x7e, 0x09, 0xd2, 0x8e, 0xef, 0x85, 0x98, 0x98, 0xcd, 0xd3, 0x81, 0x8f,
            0xb4, 0x0a, 0xff, 0xaf, 0x6d, 0x2a, 0x43, 0x55, 0x59, 0xb7, 0xd9, 0x0e, 0x77, 0x59,
            0x04,
        ];
        let key = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let out = decrypt_block_frame(frame, &key).unwrap();
        assert_eq!(out.len(), 211);
        assert_eq!(&out[..19], &frame[14..14 + 19]);
        assert_ne!(&out[19..], &frame[14 + 19..]);
    }

    #[test]
    fn content_enc_key_id_element_ids_match_real_asset() {
        #[rustfmt::skip]
        let content_encodings: &[u8] = &[
            0x62, 0x40, 0xAD,
              0x50, 0x31, 0x81, 0x00,
              0x50, 0x32, 0x81, 0x01,
              0x50, 0x33, 0x81, 0x01,
              0x50, 0x35, 0x9E,
                0x47, 0xE1, 0x81, 0x05,
                0x47, 0xE2, 0x90,
                  0xFE, 0xED, 0xF0, 0x0D, 0xEE, 0xDE, 0xAD, 0xBE,
                  0xEF, 0xF0, 0xBA, 0xAD, 0xF0, 0x0D, 0xD0, 0x0D,
                0x47, 0xE7, 0x84,
                  0x47, 0xE8, 0x81, 0x01,
        ];
        let kid = find_content_enc_kid(content_encodings).unwrap().unwrap();
        assert_eq!(
            kid,
            [
                0xFE, 0xED, 0xF0, 0x0D, 0xEE, 0xDE, 0xAD, 0xBE, 0xEF, 0xF0, 0xBA, 0xAD, 0xF0, 0x0D,
                0xD0, 0x0D,
            ]
        );
    }

    fn build_xiph_lace(frame_sizes: &[usize], frames_data: &[u8]) -> Vec<u8> {
        let mut out = vec![(frame_sizes.len() - 1) as u8];
        for &size in &frame_sizes[..frame_sizes.len() - 1] {
            let mut remaining = size;
            loop {
                if remaining >= 255 {
                    out.push(0xFF);
                    remaining -= 255;
                } else {
                    out.push(remaining as u8);
                    break;
                }
            }
        }
        out.extend_from_slice(frames_data);
        out
    }

    #[test]
    fn xiph_lace_splits_per_rfc9559_example() {
        let data: Vec<u8> = (0..2300u32).map(|i| (i % 256) as u8).collect();
        let payload = build_xiph_lace(&[800, 500, 1000], &data);
        let frames = split_laced_frames(LaceKind::Xiph, &payload).unwrap();
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].len(), 800);
        assert_eq!(frames[1].len(), 500);
        assert_eq!(frames[2].len(), 1000);
        assert_eq!(frames[0], &data[0..800]);
        assert_eq!(frames[2], &data[1300..2300]);
    }

    #[test]
    fn fixed_size_lace_splits_evenly() {
        let mut payload = vec![2u8];
        payload.extend(std::iter::repeat(0xAB).take(800 * 3));
        let frames = split_laced_frames(LaceKind::FixedSize, &payload).unwrap();
        assert_eq!(frames.len(), 3);
        assert!(frames.iter().all(|f| f.len() == 800));
    }

    #[test]
    fn ebml_lace_roundtrips_through_rebuild() {
        let frames: Vec<Vec<u8>> = vec![vec![0x11; 800], vec![0x22; 500], vec![0x33; 1000]];
        let payload = build_ebml_laced_payload(&frames).unwrap();
        let parsed = split_laced_frames(LaceKind::Ebml, &payload).unwrap();
        assert_eq!(parsed.len(), 3);
        for (parsed_frame, original) in parsed.iter().zip(&frames) {
            assert_eq!(parsed_frame, &original.as_slice());
        }
    }

    #[test]
    fn ebml_lace_roundtrips_with_equal_sizes() {
        let frames: Vec<Vec<u8>> = vec![vec![0x01; 64], vec![0x02; 64], vec![0x03; 64], vec![0x04; 64]];
        let payload = build_ebml_laced_payload(&frames).unwrap();
        let parsed = split_laced_frames(LaceKind::Ebml, &payload).unwrap();
        for (parsed_frame, original) in parsed.iter().zip(&frames) {
            assert_eq!(parsed_frame, &original.as_slice());
        }
    }

    #[test]
    fn rewrite_block_bytes_decrypts_each_laced_frame_independently() {
        let key = [0x42u8; 16];
        let raw_frames: Vec<Vec<u8>> = vec![
            [&[0x00u8][..], &[0xAAu8; 10][..]].concat(),
            [&[0x00u8][..], &[0xBBu8; 20][..]].concat(),
            [&[0x00u8][..], &[0xCCu8; 5][..]].concat(),
        ];
        let laced_payload = build_ebml_laced_payload(&raw_frames).unwrap();

        let mut body = vec![0x81];
        body.extend_from_slice(&[0x00, 0x00]);
        body.push(0x06);
        body.extend_from_slice(&laced_payload);

        let mut keys = BTreeMap::new();
        keys.insert(1u64, key);

        let out = rewrite_block_bytes(&body, &keys).unwrap().unwrap();
        assert_eq!(out[3], 0x06);
        let new_payload = &out[4..];
        let decrypted = split_laced_frames(LaceKind::Ebml, new_payload).unwrap();
        assert_eq!(decrypted.len(), 3);
        assert_eq!(decrypted[0], &[0xAAu8; 10][..]);
        assert_eq!(decrypted[1], &[0xBBu8; 20][..]);
        assert_eq!(decrypted[2], &[0xCCu8; 5][..]);
    }

    fn elem(id_bytes: &[u8], body: &[u8]) -> Vec<u8> {
        assert!(body.len() < 127);
        let mut out = id_bytes.to_vec();
        out.push(0x80 | body.len() as u8);
        out.extend_from_slice(body);
        out
    }

    fn build_minimal_webm(kid: [u8; KEY_LEN]) -> Vec<u8> {
        let track_number = elem(&[0xD7], &[0x01]);
        let key_id = elem(&[0x47, 0xE2], &kid);
        let content_encryption = elem(&[0x50, 0x35], &key_id);
        let content_encoding = elem(&[0x62, 0x40], &content_encryption);
        let content_encodings = elem(&[0x6D, 0x80], &content_encoding);
        let mut track_entry_body = track_number;
        track_entry_body.extend_from_slice(&content_encodings);
        let track_entry = elem(&[0xAE], &track_entry_body);
        let tracks = elem(&[0x16, 0x54, 0xAE, 0x6B], &track_entry);

        let mut block_body = vec![0x81, 0x00, 0x00, 0x00];
        block_body.extend((0u8..20).collect::<Vec<u8>>());
        let simple_block = elem(&[0xA3], &block_body);
        let cluster = elem(&[0x1F, 0x43, 0xB6, 0x75], &simple_block);

        let mut segment_body = tracks;
        segment_body.extend_from_slice(&cluster);
        elem(&[0x18, 0x53, 0x80, 0x67], &segment_body)
    }

    #[test]
    fn decrypt_webm_succeeds_on_well_formed_minimal_asset() {
        let kid = [0xAAu8; KEY_LEN];
        let input = build_minimal_webm(kid);
        let key = [0xBBu8; KEY_LEN];
        let out = decrypt_webm(&input, &[(kid, key)]).unwrap();
        assert!(out.len() < input.len());
        let frame: Vec<u8> = (0u8..20).collect();
        assert!(out.windows(frame.len()).any(|w| w == frame.as_slice()));
    }

    #[test]
    fn decrypt_webm_tolerates_segment_size_overrunning_truncated_buffer() {
        let kid = [0xAAu8; KEY_LEN];
        let mut input = build_minimal_webm(kid);

        let segment_body_len = input.len() - 5;
        let inflated = segment_body_len + 40;
        assert!(inflated < 127, "test fixture must stay in the 1-byte VINT range");
        input[4] = 0x80 | inflated as u8;

        let key = [0xBBu8; KEY_LEN];
        let out = decrypt_webm(&input, &[(kid, key)])
            .expect("a declared size past EOF must be tolerated, not a hard error");
        let frame: Vec<u8> = (0u8..20).collect();
        assert!(out.windows(frame.len()).any(|w| w == frame.as_slice()));
    }

    #[test]
    fn ebml_reader_still_errors_when_element_header_itself_is_truncated() {
        let mut r = EbmlReader::new(&[0x18, 0x53, 0x80]);
        assert!(r.next().is_err());
    }
}
