//! CENC decrypt — unprotect a Common-Encryption fMP4

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use bitforge::{Decrypt, Package, Parse};

use crate::box_types::{BOX_HEADER_MIN_SIZE, parse_box};
pub use crate::cenc::CencScheme;
use crate::cenc::{ProtectionSystemSpecificHeaderBox, SampleEncryptionEntry, TrackEncryptionBox};
use crate::cenc_crypto;
use crate::drm::{WIDEVINE_SYSTEM_ID, widevine_pssh_key_ids};
use crate::error::{Error, Result};
use crate::media::Media;
use crate::movie_fragment::{
    MovieFragmentBox, TFHD_BASE_DATA_OFFSET_PRESENT, TRUN_DATA_OFFSET_PRESENT,
    TrackFragmentHeaderBox, TrackFragmentRunBox,
};

const KEY_LEN: usize = 16;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyMap {
    keys: BTreeMap<[u8; KEY_LEN], [u8; KEY_LEN]>,
}

impl KeyMap {
    pub fn new() -> Self {
        Self {
            keys: BTreeMap::new(),
        }
    }

    pub fn with_key(mut self, kid: [u8; KEY_LEN], key: [u8; KEY_LEN]) -> Self {
        self.keys.insert(kid, key);
        self
    }

    pub fn insert(&mut self, kid: [u8; KEY_LEN], key: [u8; KEY_LEN]) {
        self.keys.insert(kid, key);
    }

    pub fn get(&self, kid: &[u8; KEY_LEN]) -> Option<&[u8; KEY_LEN]> {
        self.keys.get(kid)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TrackCrypto {
    pub(crate) track_id: u32,
    pub(crate) tenc: TrackEncryptionBox,
    original_format: [u8; 4],
    pub(crate) scheme: CencScheme,
    pub(crate) samples: Vec<SampleEncryptionEntry>,
    pub(crate) protected_stsd_indices: alloc::vec::Vec<u32>,
    pub(crate) seig: Option<SeigData>,
}

#[derive(Debug, Clone)]
pub struct CencDecryptor {
    file: Vec<u8>,
    tracks: Vec<TrackCrypto>,
}

impl CencDecryptor {
    pub fn from_fmp4(file: &[u8]) -> Result<Self> {
        let mut tracks = Vec::new();
        harvest_tracks(file, &mut tracks)?;
        if tracks.is_empty() {
            return Err(Error::UnexpectedBox {
                expected: "a protected track (sinf/tenc + senc)",
            });
        }
        Ok(Self {
            file: file.to_vec(),
            tracks,
        })
    }

    pub fn original_format(&self) -> [u8; 4] {
        self.tracks
            .first()
            .map(|t| t.original_format)
            .unwrap_or(*b"\0\0\0\0")
    }

    pub fn scheme(&self) -> Option<CencScheme> {
        self.tracks.first().map(|t| t.scheme)
    }

    pub fn track_encryption(&self) -> Option<&TrackEncryptionBox> {
        self.tracks.first().map(|t| &t.tenc)
    }

    pub fn sample_entries(&self) -> &[SampleEncryptionEntry] {
        self.tracks
            .first()
            .map(|t| t.samples.as_slice())
            .unwrap_or(&[])
    }

    pub fn demux(&self) -> Result<Media> {
        demux_protected(&self.file)
    }

    fn decrypt_sample(
        scheme: CencScheme,
        tenc: &TrackEncryptionBox,
        entry: &SampleEncryptionEntry,
        key: &[u8; KEY_LEN],
        data: &mut bytes::Bytes,
        scratch: &mut cenc_crypto::CbcScratch,
    ) -> Result<bool> {
        if !entry.is_encrypted {
            return Ok(false);
        }
        if tenc.default_per_sample_iv_size != 0 && entry.initialization_vector.is_empty() {
            return Err(Error::InvalidInput(
                "sample is marked encrypted but has no per-sample IV -- crypto metadata is \
                 missing or was not harvested correctly for this sample (not a legitimate \
                 clear-lead case)",
            ));
        }
        cenc_crypto::rewrite_in_place(data, |buf| match scheme {
            CencScheme::Cenc => {
                cenc_crypto::apply_ctr(&entry.initialization_vector, key, &entry.subsamples, buf)
            }
            CencScheme::Cbcs => cenc_crypto::cbcs_sample(tenc, entry, key, buf, scratch),
            CencScheme::Cbc1 => cenc_crypto::cbc1_sample(tenc, entry, key, buf, scratch),
            CencScheme::Cens => cenc_crypto::cens_sample(tenc, entry, key, buf),
            other => Err(Error::UnsupportedCencScheme { scheme: other }),
        })
    }
}

#[cfg(feature = "cli")]
pub(crate) type DecryptScratch = cenc_crypto::CbcScratch;

#[cfg(feature = "cli")]
pub(crate) fn decrypt_sample_slice(
    scheme: CencScheme,
    tenc: &TrackEncryptionBox,
    entry: &SampleEncryptionEntry,
    key: &[u8; KEY_LEN],
    data: &mut [u8],
    scratch: &mut DecryptScratch,
) -> Result<()> {
    if !entry.is_encrypted {
        return Ok(());
    }
    if tenc.default_per_sample_iv_size != 0 && entry.initialization_vector.is_empty() {
        return Err(Error::InvalidInput(
            "sample is marked encrypted but has no per-sample IV -- crypto metadata is missing \
             or was not harvested correctly for this sample (not a legitimate clear-lead case)",
        ));
    }
    match scheme {
        CencScheme::Cenc => {
            cenc_crypto::apply_ctr(&entry.initialization_vector, key, &entry.subsamples, data)
        }
        CencScheme::Cbcs => cenc_crypto::cbcs_sample(tenc, entry, key, data, scratch),
        CencScheme::Cbc1 => cenc_crypto::cbc1_sample(tenc, entry, key, data, scratch),
        CencScheme::Cens => cenc_crypto::cens_sample(tenc, entry, key, data),
        other => Err(Error::UnsupportedCencScheme { scheme: other }),
    }
}

impl Decrypt for CencDecryptor {
    type Media = Media;
    type Keys = KeyMap;
    type Error = Error;

    fn decrypt(&self, media: &mut Media, keys: &KeyMap) -> Result<()> {
        let mut scratch = cenc_crypto::CbcScratch::default();
        for track in media.tracks.iter_mut() {
            let crypto = self
                .tracks
                .iter()
                .find(|c| c.track_id == track.spec.track_id)
                .ok_or(Error::InvalidInput(
                    "no protected-source track matches this media track's track_id",
                ))?;
            if crypto.tenc.default_is_protected == 0 {
                continue;
            }
            let default_key = keys
                .get(&crypto.tenc.default_kid)
                .ok_or(Error::InvalidInput(
                    "no content key for the track's default_KID",
                ))?;
            if track.samples.len() != crypto.samples.len() {
                return Err(Error::InvalidInput(
                    "sample count mismatch between media and senc",
                ));
            }
            for (sample, entry) in track.samples.iter_mut().zip(crypto.samples.iter()) {
                let key = if let Some(kid) = entry.explicit_kid {
                    keys.get(&kid).ok_or(Error::InvalidInput(
                        "no content key for this sample's seig key_id",
                    ))?
                } else {
                    default_key
                };
                CencDecryptor::decrypt_sample(
                    crypto.scheme,
                    &crypto.tenc,
                    entry,
                    key,
                    &mut sample.data,
                    &mut scratch,
                )?;
            }
        }
        Ok(())
    }
}

fn is_av_track(trak: &[u8]) -> bool {
    const HDLR_HANDLER_TYPE_OFFSET: usize = BOX_HEADER_MIN_SIZE + FULL_HDR + 4;
    let Some(hdlr) = descend(trak, &[b"mdia", b"hdlr"]) else {
        return false;
    };
    hdlr.get(HDLR_HANDLER_TYPE_OFFSET..HDLR_HANDLER_TYPE_OFFSET + 4)
        .map(|t| t == b"vide" || t == b"soun" || t == b"clcp" || t == b"subp" || t == b"text" || t == b"subt")
        .unwrap_or(false)
}

pub fn decrypt_to_progressive_mp4(input: &[u8], keys: &KeyMap) -> Result<alloc::vec::Vec<u8>> {
    let decryptor = CencDecryptor::from_fmp4(input)?;
    let mut media = decryptor.demux()?;
    decryptor.decrypt(&mut media, keys)?;
    crate::progressive::ProgressiveMux::new(true).package(&media)
}

const FULL_HDR: usize = 4;
const STSD_ENTRY_COUNT: usize = 4;
const VISUAL_SAMPLE_ENTRY_HDR: usize = 78;
const VISUAL_SAMPLE_ENTRY_WIDTH_OFFSET: usize = BOX_HEADER_MIN_SIZE + 24;
const SAMPLE_FLAG_IS_NON_SYNC: u32 = 0x0001_0000;

fn read_visual_sample_entry_dims(entry: &[u8]) -> (u16, u16) {
    let w_off = VISUAL_SAMPLE_ENTRY_WIDTH_OFFSET;
    if entry.len() < w_off + 4 {
        return (0, 0);
    }
    let width = u16::from_be_bytes([entry[w_off], entry[w_off + 1]]);
    let height = u16::from_be_bytes([entry[w_off + 2], entry[w_off + 3]]);
    (width, height)
}

fn resolve_zero_kid_from_widevine_pssh(moov: &[u8]) -> Option<[u8; 16]> {
    let mut found: Vec<[u8; 16]> = Vec::new();
    for pssh in iter_child_boxes(moov, b"pssh") {
        let Ok(parsed) = ProtectionSystemSpecificHeaderBox::parse_box(pssh) else {
            continue;
        };
        if parsed.system_id != WIDEVINE_SYSTEM_ID {
            continue;
        }
        if !parsed.kids.is_empty() {
            for kid in parsed.kids {
                if !found.contains(&kid) {
                    found.push(kid);
                }
            }
        } else {
            for kid in widevine_pssh_key_ids(&parsed.data) {
                if !found.contains(&kid) {
                    found.push(kid);
                }
            }
        }
    }
    match found.len() {
        1 => Some(found[0]),
        _ => None,
    }
}

fn patch_zero_kids_from_pssh(moov: &[u8], tracks: &mut [TrackCrypto]) {
    if !tracks
        .iter()
        .any(|t| t.tenc.default_is_protected != 0 && t.tenc.default_kid == [0u8; 16])
    {
        return;
    }
    let Some(real_kid) = resolve_zero_kid_from_widevine_pssh(moov) else {
        return;
    };
    for crypto in tracks.iter_mut() {
        if crypto.tenc.default_is_protected != 0 && crypto.tenc.default_kid == [0u8; 16] {
            crypto.tenc.default_kid = real_kid;
        }
    }
}

pub(crate) fn progressive_aux_info_requires_mdat(moov: &[u8]) -> bool {
    let Some(moov) = find_top_box(moov, b"moov") else {
        return false;
    };
    for trak in iter_child_boxes(moov, b"trak") {
        let Some(stbl) = descend(trak, &[b"mdia", b"minf", b"stbl"]) else {
            continue;
        };
        let Some(stsd) = find_box(stbl, b"stsd") else {
            continue;
        };
        if find_sinf_in_stsd_indexed(stsd).is_none() {
            continue;
        }
        let has_in_stbl_senc = find_box(stbl, b"senc").is_some()
            || find_uuid_box(stbl, &PIFF_SAMPLE_ENCRYPTION_UUID).is_some();
        if has_in_stbl_senc {
            continue;
        }
        if find_box(stbl, b"saiz").is_some() && find_box(stbl, b"saio").is_some() {
            return true;
        }
    }
    false
}

pub(crate) fn fragment_aux_info_requires_mdat(moof: &[u8]) -> bool {
    for traf in iter_child_boxes(moof, b"traf") {
        let has_senc = find_box(traf, b"senc").is_some()
            || find_uuid_box(traf, &PIFF_SAMPLE_ENCRYPTION_UUID).is_some();
        if has_senc {
            continue;
        }
        if find_box(traf, b"saiz").is_some() && find_box(traf, b"saio").is_some() {
            return true;
        }
    }
    false
}

pub(crate) fn moof_sample_encryption_by_track(moof: &[u8]) -> Vec<(u32, bool)> {
    let mut out = Vec::new();
    for traf in iter_child_boxes(moof, b"traf") {
        let track_id = find_box(traf, b"tfhd")
            .and_then(|tfhd| {
                TrackFragmentHeaderBox::parse_body(&tfhd[BOX_HEADER_MIN_SIZE..]).ok()
            })
            .map(|h| h.track_id);
        let Some(track_id) = track_id else {
            continue;
        };
        let has = find_box(traf, b"senc").is_some()
            || find_uuid_box(traf, &PIFF_SAMPLE_ENCRYPTION_UUID).is_some()
            || (find_box(traf, b"saiz").is_some() && find_box(traf, b"saio").is_some());
        out.push((track_id, has));
    }
    out
}

pub(crate) fn harvest_tracks(file: &[u8], out: &mut Vec<TrackCrypto>) -> Result<()> {
    let moov = find_top_box(file, b"moov").ok_or(Error::UnexpectedBox { expected: "moov" })?;
    let fragmented = find_top_box(file, b"moof").is_some();
    for trak in iter_child_boxes(moov, b"trak") {
        if let Some(crypto) = harvest_track(file, trak, fragmented)? {
            out.push(crypto);
        }
    }
    patch_zero_kids_from_pssh(moov, out);
    if fragmented {
        let trex_defaults = harvest_trex_defaults(moov);
        harvest_fragment_senc(file, out, &trex_defaults, None)?;
    }
    Ok(())
}

fn harvest_track(file: &[u8], trak: &[u8], fragmented: bool) -> Result<Option<TrackCrypto>> {
    let Some(stbl) = descend(trak, &[b"mdia", b"minf", b"stbl"]) else {
        return Ok(None);
    };

    let Some(stsd) = find_box(stbl, b"stsd") else {
        return Ok(None);
    };
    let Some((sinf, _first_protected_index)) = find_sinf_in_stsd_indexed(stsd) else {
        return unprotected_av_track_crypto(trak, stsd);
    };
    let protected_stsd_indices = protected_stsd_index_list(stsd);
    let sinf_parsed = crate::cenc::ProtectionSchemeInfoBox::parse(sinf)?;
    let scheme = sinf_parsed
        .scheme_type
        .as_ref()
        .and_then(|s| CencScheme::from_four_cc(&s.scheme_type))
        .ok_or(Error::InvalidInput(
            "sinf missing or unknown schm scheme_type",
        ))?;
    let tenc = sinf_parsed
        .scheme_info
        .as_ref()
        .and_then(|si| si.tenc.clone())
        .ok_or(Error::UnexpectedBox {
            expected: "tenc inside schi",
        })?;
    let original_format = sinf_parsed.original_format.data_format;

    let tkhd = find_box(trak, b"tkhd").ok_or(Error::UnexpectedBox { expected: "tkhd" })?;
    let track_id = crate::init_segment::TrackHeaderBox::parse(tkhd)?.track_id;

    let samples = if fragmented {
        Vec::new()
    } else {
        let base_entries: Option<Vec<SampleEncryptionEntry>> =
            if let Some(senc) = find_box(stbl, b"senc") {
                Some(
                    parse_senc_box(senc, BOX_HEADER_MIN_SIZE, tenc.default_per_sample_iv_size)?
                        .entries,
                )
            } else if let Some(u) = find_uuid_box(stbl, &PIFF_SAMPLE_ENCRYPTION_UUID) {
                Some(
                    parse_senc_box(u, UUID_BOX_HEADER_SIZE, tenc.default_per_sample_iv_size)?
                        .entries,
                )
            } else {
                None
            };
        match base_entries {
            Some(entries) => {
                if entries.is_empty() && tenc.default_per_sample_iv_size == 0 {
                    let sample_count = stsz_sizes(stbl)?.len();
                    core::iter::repeat_with(|| SampleEncryptionEntry {
                        initialization_vector: Vec::new(),
                        subsamples: Vec::new(),
                        is_encrypted: true,
                        explicit_kid: None,
                    })
                    .take(sample_count)
                    .collect()
                } else {
                    entries
                }
            }
            None => {
                match resolve_aux_from_saiz_saio(
                    file,
                    stbl,
                    tenc.default_per_sample_iv_size,
                    0,
                ) {
                    Some(entries) => entries,
                    None => {
                        return Err(Error::UnexpectedBox {
                            expected: "senc or saiz/saio",
                        })?
                    }
                }
            }
        }
    };

    Ok(Some(TrackCrypto {
        track_id,
        tenc,
        original_format,
        scheme,
        samples,
        protected_stsd_indices,
        seig: parse_seig_from_stbl(stbl),
    }))
}

fn unprotected_av_track_crypto(trak: &[u8], stsd: &[u8]) -> Result<Option<TrackCrypto>> {
    if !is_av_track(trak) {
        return Ok(None);
    }
    let tkhd = find_box(trak, b"tkhd").ok_or(Error::UnexpectedBox { expected: "tkhd" })?;
    let track_id = crate::init_segment::TrackHeaderBox::parse(tkhd)?.track_id;
    Ok(Some(TrackCrypto {
        track_id,
        tenc: TrackEncryptionBox {
            version: 0,
            default_crypt_byte_block: 0,
            default_skip_byte_block: 0,
            default_is_protected: 0,
            default_per_sample_iv_size: 0,
            default_kid: [0u8; KEY_LEN],
            default_constant_iv: None,
        },
        original_format: stsd_first_entry_fourcc(stsd),
        scheme: CencScheme::Cenc,
        samples: Vec::new(),
        protected_stsd_indices: alloc::vec::Vec::new(),
        seig: None,
    }))
}

fn stsd_first_entry_fourcc(stsd: &[u8]) -> [u8; 4] {
    let body_start = BOX_HEADER_MIN_SIZE + FULL_HDR + STSD_ENTRY_COUNT;
    stsd.get(body_start + 4..body_start + 8)
        .and_then(|f| f.try_into().ok())
        .unwrap_or(*b"\0\0\0\0")
}

fn unprotected_track_spec(trak: &[u8]) -> Result<Option<ProtectedTrackSpec>> {
    if !is_av_track(trak) {
        return Ok(None);
    }
    let track_box = crate::init_segment::TrackBox::parse(trak)?;
    let spec = crate::media::track_spec_from_trak(&track_box)?;
    Ok(Some(ProtectedTrackSpec {
        track_id: spec.track_id,
        timescale: spec.timescale,
        codec_config: spec.config,
        edit_list: spec.edit_list,
    }))
}

const UUID_BOX_HEADER_SIZE: usize = BOX_HEADER_MIN_SIZE + 16;

const PIFF_SAMPLE_ENCRYPTION_UUID: [u8; 16] = [
    0xa2, 0x39, 0x4f, 0x52, 0x5a, 0x9b, 0x4f, 0x14, 0xa2, 0x44, 0x6c, 0x42, 0x7c, 0x64, 0x8d, 0xf4,
];

fn find_uuid_box<'a>(container: &'a [u8], uuid: &[u8; 16]) -> Option<&'a [u8]> {
    let body = &container[BOX_HEADER_MIN_SIZE.min(container.len())..];
    iter_boxes(body).find(|b| {
        &b[4..8] == b"uuid" && b.len() >= UUID_BOX_HEADER_SIZE && &b[8..24] == uuid.as_slice()
    })
}

fn parse_senc_box(
    senc: &[u8],
    header_len: usize,
    per_sample_iv_size: u8,
) -> Result<crate::cenc::SampleEncryptionBox> {
    if senc.len() < header_len + FULL_HDR {
        return Err(Error::BufferTooShort {
            need: header_len + FULL_HDR,
            have: senc.len(),
            what: "senc header",
        });
    }
    let version = senc[header_len];
    let flags = u32::from_be_bytes([
        0,
        senc[header_len + 1],
        senc[header_len + 2],
        senc[header_len + 3],
    ]);
    crate::cenc::SampleEncryptionBox::parse_body(
        &senc[header_len + FULL_HDR..],
        version,
        flags,
        per_sample_iv_size,
    )
}

fn resolve_aux_from_saiz_saio(
    file: &[u8],
    container: &[u8],
    per_sample_iv_size: u8,
    base_offset: u64,
) -> Option<Vec<SampleEncryptionEntry>> {
    let saiz = find_box(container, b"saiz")?;
    let saio = find_box(container, b"saio")?;

    let sizes = parse_saiz_sizes(saiz)?;
    let offsets = parse_saio_offsets(saio, base_offset)?;
    if sizes.is_empty() {
        return None;
    }

    let mut entries = Vec::with_capacity(sizes.len());
    if offsets.len() == 1 {
        let mut cur = offsets[0];
        for &sz in &sizes {
            let sz = sz as usize;
            if sz == 0 {
                entries.push(SampleEncryptionEntry {
                    initialization_vector: Vec::new(),
                    subsamples: Vec::new(),
                    is_encrypted: true,
                    explicit_kid: None,
                });
                continue;
            }
            let start = cur as usize;
            if start + sz > file.len() {
                return None;
            }
            entries.push(parse_one_aux_entry(&file[start..start + sz], per_sample_iv_size)?);
            cur += sz as u64;
        }
    } else if offsets.len() == sizes.len() {
        for (i, &sz) in sizes.iter().enumerate() {
            let sz = sz as usize;
            let start = offsets[i] as usize;
            if start + sz > file.len() {
                return None;
            }
            entries.push(parse_one_aux_entry(&file[start..start + sz], per_sample_iv_size)?);
        }
    } else {
        return None;
    }
    Some(entries)
}

fn parse_saiz_sizes(saiz: &[u8]) -> Option<Vec<u8>> {
    if saiz.len() < BOX_HEADER_MIN_SIZE + FULL_HDR + 1 + 4 {
        return None;
    }
    let mut off = BOX_HEADER_MIN_SIZE + FULL_HDR;
    let flags = u32::from_be_bytes([
        0,
        saiz[BOX_HEADER_MIN_SIZE + 1],
        saiz[BOX_HEADER_MIN_SIZE + 2],
        saiz[BOX_HEADER_MIN_SIZE + 3],
    ]);
    if flags & 0x1 != 0 {
        off += 8;
    }
    let default_size = saiz[off];
    off += 1;
    let count = u32::from_be_bytes(saiz[off..off + 4].try_into().ok()?) as usize;
    off += 4;
    let mut sizes = Vec::with_capacity(count);
    if default_size != 0 {
        for _ in 0..count {
            sizes.push(default_size);
        }
    } else {
        if saiz.len() < off + count {
            return None;
        }
        for i in 0..count {
            sizes.push(saiz[off + i]);
        }
    }
    Some(sizes)
}

fn parse_saio_offsets(saio: &[u8], base_offset: u64) -> Option<Vec<u64>> {
    if saio.len() < BOX_HEADER_MIN_SIZE + FULL_HDR + 4 {
        return None;
    }
    let version = saio[BOX_HEADER_MIN_SIZE];
    let mut off = BOX_HEADER_MIN_SIZE + FULL_HDR;
    let flags = u32::from_be_bytes([
        0,
        saio[BOX_HEADER_MIN_SIZE + 1],
        saio[BOX_HEADER_MIN_SIZE + 2],
        saio[BOX_HEADER_MIN_SIZE + 3],
    ]);
    if flags & 0x1 != 0 {
        off += 8;
    }
    let count = u32::from_be_bytes(saio[off..off + 4].try_into().ok()?) as usize;
    off += 4;
    let mut offsets = Vec::with_capacity(count);
    for _ in 0..count {
        let o = if version == 0 {
            if saio.len() < off + 4 {
                return None;
            }
            let v = u32::from_be_bytes(saio[off..off + 4].try_into().ok()?);
            off += 4;
            v as u64
        } else {
            if saio.len() < off + 8 {
                return None;
            }
            let v = u64::from_be_bytes(saio[off..off + 8].try_into().ok()?);
            off += 8;
            v
        };
        offsets.push(base_offset + o);
    }
    Some(offsets)
}

fn parse_one_aux_entry(aux: &[u8], per_sample_iv_size: u8) -> Option<SampleEncryptionEntry> {
    let iv_sz = per_sample_iv_size as usize;
    if aux.len() < iv_sz {
        return None;
    }
    let use_subs = aux.len() > iv_sz;
    let mut buf = Vec::with_capacity(4 + aux.len());
    buf.extend_from_slice(&1u32.to_be_bytes());
    buf.extend_from_slice(aux);
    let flags = if use_subs {
        crate::cenc::SENC_FLAG_USE_SUBSAMPLE_ENCRYPTION
    } else {
        0
    };
    let parsed =
        crate::cenc::SampleEncryptionBox::parse_body(&buf, 0, flags, per_sample_iv_size).ok()?;
    parsed.entries.into_iter().next()
}

    #[derive(Debug, Clone, Default)]
    pub(crate) struct SeigGroup {
        pub is_protected: bool,
        pub kid: Option<[u8; 16]>,
    }

    #[derive(Debug, Clone, Default)]
    pub(crate) struct SeigData {
        pub groups: Vec<SeigGroup>,
    }

    const SEIG_GROUPING_TYPE: &[u8; 4] = b"seig";

    fn parse_seig_groups(body: &[u8]) -> Result<Vec<SeigGroup>> {
        if body.len() < 8 {
            return Err(Error::BufferTooShort {
                need: 8,
                have: body.len(),
                what: "sgpd seig header",
            });
        }
        let version = body[0];
        let mut off = 4;
        if &body[off..off + 4] != SEIG_GROUPING_TYPE {
            return Ok(Vec::new());
        }
        off += 4;
        let default_length = if version >= 1 {
            let d = u32::from_be_bytes(body[off..off + 4].try_into().unwrap()) as usize;
            off += 4;
            d
        } else {
            0
        };
        if version >= 2 {
            off += 4;
        }
        let count = u32::from_be_bytes(body[off..off + 4].try_into().unwrap()) as usize;
        off += 4;
        let mut groups = Vec::with_capacity(count);
        for _ in 0..count {
            let (desc, next): (&[u8], usize) = if default_length != 0 {
                (&body[off..off + default_length], off + default_length)
            } else {
                let dl = u32::from_be_bytes(body[off..off + 4].try_into().unwrap()) as usize;
                off += 4;
                (&body[off..off + dl], off + dl)
            };
            groups.push(parse_seig_entry(desc, version)?);
            off = next;
        }
        Ok(groups)
    }

    fn parse_seig_entry(b: &[u8], _sgpd_version: u8) -> Result<SeigGroup> {
        if b.len() < 4 {
            return Err(Error::BufferTooShort {
                need: 4,
                have: b.len(),
                what: "seig entry header",
            });
        }
        let is_protected = b[2] != 0;
        let per_sample_iv_size = b[3];
        if !is_protected {
            return Ok(SeigGroup {
                is_protected: false,
                kid: None,
            });
        }
        if b.len() < 20 {
            return Err(Error::BufferTooShort {
                need: 20,
                have: b.len(),
                what: "seig key_id",
            });
        }
        let mut kid = [0u8; 16];
        kid.copy_from_slice(&b[4..20]);
        let _ = per_sample_iv_size;
        Ok(SeigGroup {
            is_protected: true,
            kid: Some(kid),
        })
    }

    fn parse_seig_sample_groups(body: &[u8], sample_count: usize) -> Result<Vec<u32>> {
        if body.len() < 8 {
            return Err(Error::BufferTooShort {
                need: 8,
                have: body.len(),
                what: "sbgp seig header",
            });
        }
        let version = body[0];
        let mut off = 4;
        if &body[off..off + 4] != SEIG_GROUPING_TYPE {
            return Ok(vec![0u32; sample_count]);
        }
        off += 4;
        let index_type = if version >= 1 {
            let t = u32::from_be_bytes(body[off..off + 4].try_into().unwrap());
            off += 4;
            t
        } else {
            0
        };
        let count = u32::from_be_bytes(body[off..off + 4].try_into().unwrap()) as usize;
        off += 4;
        let mut out = Vec::with_capacity(sample_count);
        for _ in 0..count {
            let sc = u32::from_be_bytes(body[off..off + 4].try_into().unwrap()) as usize;
            off += 4;
            let gdi = if version >= 1 && index_type == 1 {
                let v = u64::from_be_bytes(body[off..off + 8].try_into().unwrap());
                off += 8;
                (v & 0xFFFF_FFFF) as u32
            } else {
                let v = u32::from_be_bytes(body[off..off + 4].try_into().unwrap());
                off += 4;
                v
            };
            for _ in 0..sc {
                out.push(gdi & 0xFFFF);
            }
        }
        out.resize(sample_count, 0);
        Ok(out)
    }

    fn parse_seig_from_stbl(stbl: &[u8]) -> Option<SeigData> {
        let sgpd = find_box(stbl, b"sgpd")?;
        let body = &sgpd[BOX_HEADER_MIN_SIZE..];
        if body.len() < 8 || &body[4..8] != SEIG_GROUPING_TYPE {
            return None;
        }
        parse_seig_groups(body).ok().map(|groups| SeigData { groups })
    }

    pub(crate) struct AuxSource<'a> {
        pub(crate) data: &'a [u8],
        pub(crate) data_base_offset: u64,
        pub(crate) moof_file_offset: u64,
    }

    fn harvest_fragment_senc(
        file: &[u8],
        tracks: &mut [TrackCrypto],
        trex_defaults: &BTreeMap<u32, TrexDefaults>,
        aux: Option<&AuxSource<'_>>,
    ) -> Result<()> {
    for moof in iter_top_boxes(file, b"moof") {
        let moof_off = match aux {
            Some(a) => a.moof_file_offset as usize,
            None => moof.as_ptr() as usize - file.as_ptr() as usize,
        };
        for traf in iter_child_boxes(moof, b"traf") {
            let Some(tfhd) = find_box(traf, b"tfhd") else {
                continue;
            };
            if tfhd.len() < BOX_HEADER_MIN_SIZE + FULL_HDR {
                return Err(Error::BufferTooShort {
                    need: BOX_HEADER_MIN_SIZE + FULL_HDR,
                    have: tfhd.len(),
                    what: "tfhd header",
                });
            }
            let tfhd_parsed = TrackFragmentHeaderBox::parse_body(&tfhd[BOX_HEADER_MIN_SIZE..])?;
            let saio_base_offset = tfhd_parsed
                .base_data_offset
                .unwrap_or(moof_off as u64);

            let Some(crypto) = tracks
                .iter_mut()
                .find(|t| t.track_id == tfhd_parsed.track_id)
            else {
                continue;
            };

            let sdi = tfhd_parsed
                .sample_description_index
                .or_else(|| {
                    trex_defaults
                        .get(&tfhd_parsed.track_id)
                        .and_then(|t| t.default_sample_description_index)
                })
                .unwrap_or(1);
            let is_clear_lead = !crypto.protected_stsd_indices.contains(&sdi);

            let synthesize_placeholders =
                |traf: &[u8], is_encrypted: bool| -> Result<Vec<SampleEncryptionEntry>> {
                    let sample_count = traf_trun_sample_count(traf)?;
                    Ok(core::iter::repeat_with(|| SampleEncryptionEntry {
                        initialization_vector: Vec::new(),
                        subsamples: Vec::new(),
                        is_encrypted,
                        explicit_kid: None,
                    })
                    .take(sample_count)
                    .collect())
                };

            let base_entries = {
                let senc_found = find_box(traf, b"senc")
                    .map(|b| (b, BOX_HEADER_MIN_SIZE))
                    .or_else(|| {
                        find_uuid_box(traf, &PIFF_SAMPLE_ENCRYPTION_UUID)
                            .map(|b| (b, UUID_BOX_HEADER_SIZE))
                    });
                let parsed_senc = match senc_found {
                    Some((senc, header_len)) => Some(parse_senc_box(
                        senc,
                        header_len,
                        crypto.tenc.default_per_sample_iv_size,
                    )?),
                    None => None,
                };
                match parsed_senc {
                    Some(senc_parsed) => {
                        if senc_parsed.entries.is_empty()
                            && crypto.tenc.default_per_sample_iv_size == 0
                        {
                            synthesize_placeholders(traf, true)?
                        } else {
                            senc_parsed.entries
                        }
                    }
                    None => {
                        let (resolve_file, resolve_base): (&[u8], u64) = match aux {
                            Some(a) => (
                                a.data,
                                saio_base_offset.saturating_sub(a.data_base_offset),
                            ),
                            None => (file, saio_base_offset),
                        };
                        let has_saiz_saio =
                            find_box(traf, b"saiz").is_some() && find_box(traf, b"saio").is_some();
                        match resolve_aux_from_saiz_saio(
                            resolve_file,
                            traf,
                            crypto.tenc.default_per_sample_iv_size,
                            resolve_base,
                        ) {
                            Some(entries) => entries,
                            None if has_saiz_saio => {
                                return Err(Error::InvalidInput(
                                    "fragment carries saiz/saio sample auxiliary info but its \
                                     records fall outside the available file data -- refusing \
                                     to decrypt with placeholder IVs, which would silently \
                                     corrupt constant-IV (cbcs/cens) content",
                                ));
                            }
                            None => synthesize_placeholders(traf, true)?,
                        }
                    }
                }
            };

            let seig_groups = find_box(traf, b"sgpd")
                .filter(|b| &b[BOX_HEADER_MIN_SIZE + 4..BOX_HEADER_MIN_SIZE + 8] == SEIG_GROUPING_TYPE)
                .and_then(|b| parse_seig_groups(&b[BOX_HEADER_MIN_SIZE..]).ok())
                .or_else(|| crypto.seig.as_ref().map(|d| d.groups.clone()));
            let local_groups = find_box(traf, b"sbgp")
                .filter(|b| &b[BOX_HEADER_MIN_SIZE + 4..BOX_HEADER_MIN_SIZE + 8] == SEIG_GROUPING_TYPE)
                .and_then(|b| {
                    traf_trun_sample_count(traf)
                        .ok()
                        .and_then(|sc| parse_seig_sample_groups(&b[BOX_HEADER_MIN_SIZE..], sc).ok())
                });

            if let (Some(lg), Some(groups)) = (&local_groups, seig_groups) {
                for (i, mut base) in base_entries.into_iter().enumerate() {
                    let had_iv = base.is_encrypted && !base.initialization_vector.is_empty();
                    let g = lg.get(i).copied().unwrap_or(0);
                    let (enc, kid) = if g == 0 {
                        (had_iv && !is_clear_lead, None)
                    } else if let Some(grp) = groups.get((g - 1) as usize) {
                        if !grp.is_protected {
                            (had_iv, None)
                        } else {
                            (true, grp.kid)
                        }
                    } else {
                        (had_iv && !is_clear_lead, None)
                    };
                    base.is_encrypted = enc;
                    base.explicit_kid = kid;
                    crypto.samples.push(base);
                }
                continue;
            }

            if is_clear_lead {
                crypto.samples.extend(synthesize_placeholders(traf, false)?);
            } else {
                crypto.samples.extend(base_entries);
            }
        }
    }
    Ok(())
}

fn traf_trun_sample_count(traf: &[u8]) -> Result<usize> {
    let mut total = 0usize;
    for trun in
        iter_boxes(&traf[BOX_HEADER_MIN_SIZE.min(traf.len())..]).filter(|b| &b[4..8] == b"trun")
    {
        if trun.len() < BOX_HEADER_MIN_SIZE {
            return Err(Error::BufferTooShort {
                need: BOX_HEADER_MIN_SIZE,
                have: trun.len(),
                what: "trun header",
            });
        }
        let parsed = TrackFragmentRunBox::parse_body(&trun[BOX_HEADER_MIN_SIZE..])?;
        total += parsed.samples.len();
    }
    Ok(total)
}

fn find_sinf_in_stsd(stsd: &[u8]) -> Option<&[u8]> {
    find_sinf_in_stsd_indexed(stsd).map(|(sinf, _index)| sinf)
}

fn find_sinf_in_stsd_indexed(stsd: &[u8]) -> Option<(&[u8], u32)> {
    let body_start = BOX_HEADER_MIN_SIZE + FULL_HDR + STSD_ENTRY_COUNT;
    if body_start > stsd.len() {
        return None;
    }
    for (i, entry) in iter_boxes(&stsd[body_start..]).enumerate() {
        let ty = &entry[4..8];
        if ty == b"encv" || ty == b"enca" {
            let child_start = if ty == b"encv" {
                BOX_HEADER_MIN_SIZE + VISUAL_SAMPLE_ENTRY_HDR
            } else {
                BOX_HEADER_MIN_SIZE + 28
            };
            if child_start <= entry.len() {
                let mut fallback: Option<&[u8]> = None;
                for sinf in iter_boxes(&entry[child_start..]).filter(|b| &b[4..8] == b"sinf") {
                    if fallback.is_none() {
                        fallback = Some(sinf);
                    }
                    let recognized = crate::cenc::ProtectionSchemeInfoBox::parse(sinf)
                        .ok()
                        .and_then(|p| p.scheme_type)
                        .is_some_and(|s| CencScheme::from_four_cc(&s.scheme_type).is_some());
                    if recognized {
                        return Some((sinf, (i + 1) as u32));
                    }
                }
                if let Some(sinf) = fallback {
                    return Some((sinf, (i + 1) as u32));
                }
            }
        }
    }
    None
}

fn protected_stsd_index_list(stsd: &[u8]) -> alloc::vec::Vec<u32> {
    let body_start = BOX_HEADER_MIN_SIZE + FULL_HDR + STSD_ENTRY_COUNT;
    if body_start > stsd.len() {
        return alloc::vec::Vec::new();
    }
    iter_boxes(&stsd[body_start..])
        .enumerate()
        .filter(|(_, entry)| &entry[4..8] == b"encv" || &entry[4..8] == b"enca")
        .map(|(i, _)| (i + 1) as u32)
        .collect()
}

fn find_protected_entry<'a>(stsd: &'a [u8], wanted: &[u8; 4]) -> Option<&'a [u8]> {
    let body_start = BOX_HEADER_MIN_SIZE + FULL_HDR + STSD_ENTRY_COUNT;
    iter_boxes(&stsd[body_start.min(stsd.len())..]).find(|entry| &entry[4..8] == wanted)
}

pub(crate) struct ProtectedTrackSpec {
    pub(crate) track_id: u32,
    pub(crate) timescale: u32,
    pub(crate) codec_config: crate::pipeline::CodecConfig,
    pub(crate) edit_list: Option<crate::timing::EditListBox>,
}

fn track_edit_list(trak: &[u8]) -> Option<crate::timing::EditListBox> {
    let edts = find_box(trak, b"edts")?;
    crate::init_segment::EditBox::parse(edts).ok()?.elst
}

fn protected_track_spec(trak: &[u8], movie_timescale: u32) -> Result<Option<ProtectedTrackSpec>> {
    use crate::AVCConfigurationBox;
    use crate::HEVCConfigurationBox;
    use crate::pipeline::CodecConfig;

    let Some(stbl) = descend(trak, &[b"mdia", b"minf", b"stbl"]) else {
        return Ok(None);
    };
    let timescale = descend(trak, &[b"mdia"])
        .and_then(|mdia| find_box(mdia, b"mdhd"))
        .and_then(mdhd_timescale)
        .unwrap_or(movie_timescale);

    let Some(stsd) = find_box(stbl, b"stsd") else {
        return Ok(None);
    };
    let Some(sinf) = find_sinf_in_stsd(stsd) else {
        return Ok(None);
    };
    let sinf_parsed = crate::cenc::ProtectionSchemeInfoBox::parse(sinf)?;
    let codec_config = match &sinf_parsed.original_format.data_format {
        b"avc1" => {
            let (avc_config, entry_width, entry_height) = find_avcc_config(stsd)?;
            let (width, height) = if entry_width != 0 && entry_height != 0 {
                (entry_width, entry_height)
            } else {
                avc_config
                    .dimensions()
                    .unwrap_or((entry_width, entry_height))
            };
            CodecConfig::Avc {
                config: AVCConfigurationBox::new(avc_config),
                width,
                height,
            }
        }
        b"hvc1" | b"hev1" | b"dvhe" | b"dvh1" => {
            let (hevc_config, entry_width, entry_height) = find_hvcc_config(stsd)?;
            let (width, height) = if entry_width != 0 && entry_height != 0 {
                (entry_width, entry_height)
            } else {
                hevc_config
                    .dimensions()
                    .unwrap_or((entry_width, entry_height))
            };
            CodecConfig::Hevc {
                config: HEVCConfigurationBox::new(hevc_config),
                width,
                height,
            }
        }
        b"av01" => {
            let entry = find_protected_entry(stsd, b"encv").ok_or(Error::UnexpectedBox {
                expected: "encv entry for av01 original_format",
            })?;
            let av1 = crate::av1::Av1SampleEntry::parse_entry(entry)?;
            let (width, height) = if av1.visual.width != 0 && av1.visual.height != 0 {
                (av1.visual.width, av1.visual.height)
            } else {
                av1.config
                    .dimensions()
                    .unwrap_or((av1.visual.width, av1.visual.height))
            };
            CodecConfig::Av1 {
                config: av1.config,
                width,
                height,
            }
        }
        b"vp09" => {
            let entry = find_protected_entry(stsd, b"encv").ok_or(Error::UnexpectedBox {
                expected: "encv entry for vp09 original_format",
            })?;
            let vp9 = crate::vp9::Vp9SampleEntry::parse_entry(entry)?;
            CodecConfig::Vp9 {
                config: vp9.config,
                width: vp9.visual.width,
                height: vp9.visual.height,
            }
        }
        b"vp08" => {
            let entry = find_protected_entry(stsd, b"encv").ok_or(Error::UnexpectedBox {
                expected: "encv entry for vp08 original_format",
            })?;
            let vp8 = crate::vp9::Vp8SampleEntry::parse_entry(entry)?;
            CodecConfig::Vp8 {
                config: vp8.config,
                width: vp8.visual.width,
                height: vp8.visual.height,
            }
        }
        b"vvc1" | b"vvi1" => {
            let entry = find_protected_entry(stsd, b"encv").ok_or(Error::UnexpectedBox {
                expected: "encv entry for vvc1/vvi1 original_format",
            })?;
            let vvc = crate::sample_entries::VVCSampleEntry::bare_parse(entry)?;
            let (width, height) = vvc
                .config
                .config
                .dimensions()
                .unwrap_or((vvc.visual.width, vvc.visual.height));
            CodecConfig::Vvc {
                config: vvc.config,
                width,
                height,
            }
        }
        b"mp4v" => {
            let entry = find_protected_entry(stsd, b"encv").ok_or(Error::UnexpectedBox {
                expected: "encv entry for mp4v original_format",
            })?;
            let mp4v = crate::sample_entries::Mp4vSampleEntry::bare_parse(entry)?;
            let esds = crate::mp4esds::EsdsBox::parse_body(crate::media::config_box_body(
                &mp4v.config_boxes,
                b"esds",
            )?)?;
            CodecConfig::Mpeg2Video {
                esds,
                width: mp4v.visual.width,
                height: mp4v.visual.height,
            }
        }
        b"mp4a" => {
            let (esds, channel_count, sample_rate, sample_size) = find_esds_config(stsd)?;
            const OTI_MPEG2_AUDIO: u8 = 0x69;
            const OTI_MPEG1_AUDIO: u8 = 0x6B;
            let oti = esds
                .es_descriptor
                .decoder_config
                .as_ref()
                .map(|dc| dc.object_type_indication.0);
            if oti == Some(OTI_MPEG2_AUDIO) || oti == Some(OTI_MPEG1_AUDIO) {
                CodecConfig::MpegAudio {
                    esds,
                    layer: crate::mpeg_legacy::MpegAudioLayer::LayerII,
                    channel_count,
                    sample_rate,
                    sample_size,
                }
            } else {
                CodecConfig::Aac {
                    esds,
                    channel_count,
                    sample_rate,
                    sample_size,
                }
            }
        }
        b"Opus" => {
            let entry = find_protected_entry(stsd, b"enca").ok_or(Error::UnexpectedBox {
                expected: "enca entry for Opus original_format",
            })?;
            let opus = crate::init_segment::OpusSampleEntry::parse(entry)?;
            let config = crate::opus::OpusSpecificBox::parse(crate::media::config_box_body(
                &opus.config_boxes,
                b"dOps",
            )?)?;
            CodecConfig::Opus {
                config,
                channel_count: opus.channelcount,
                sample_rate: opus.samplerate >> 16,
                sample_size: opus.samplesize,
            }
        }
        b"fLaC" => {
            let entry = find_protected_entry(stsd, b"enca").ok_or(Error::UnexpectedBox {
                expected: "enca entry for fLaC original_format",
            })?;
            let flac = crate::init_segment::FlacSampleEntry::parse(entry)?;
            let config = crate::flac::FlacSpecificBox::parse(crate::media::config_box_body(
                &flac.config_boxes,
                b"dfLa",
            )?)?;
            CodecConfig::Flac {
                config,
                channel_count: flac.channelcount,
                sample_rate: flac.samplerate >> 16,
                sample_size: flac.samplesize,
            }
        }
        b"ac-3" => {
            let entry = find_protected_entry(stsd, b"enca").ok_or(Error::UnexpectedBox {
                expected: "enca entry for ac-3 original_format",
            })?;
            let ac3 = crate::init_segment::Ac3SampleEntry::parse(entry)?;
            let config = crate::ac3::Ac3SpecificBox::parse(crate::media::config_box_body(
                &ac3.config_boxes,
                b"dac3",
            )?)?;
            CodecConfig::Ac3 {
                config,
                channel_count: ac3.channelcount,
                sample_rate: ac3.samplerate >> 16,
                sample_size: ac3.samplesize,
            }
        }
        b"ec-3" => {
            let entry = find_protected_entry(stsd, b"enca").ok_or(Error::UnexpectedBox {
                expected: "enca entry for ec-3 original_format",
            })?;
            let ec3 = crate::init_segment::Ec3SampleEntry::parse(entry)?;
            let config = crate::ac3::Ec3SpecificBox::parse(crate::media::config_box_body(
                &ec3.config_boxes,
                b"dec3",
            )?)?;
            CodecConfig::Eac3 {
                config,
                channel_count: ec3.channelcount,
                sample_rate: ec3.samplerate >> 16,
                sample_size: ec3.samplesize,
            }
        }
        b"dtsc" | b"dtsh" | b"dtsl" | b"dtse" => {
            let entry = find_protected_entry(stsd, b"enca").ok_or(Error::UnexpectedBox {
                expected: "enca entry for dtsc/dtsh/dtsl/dtse original_format",
            })?;
            let dts = crate::init_segment::DtsSampleEntry::parse(entry)?;
            let config = crate::dts::DtsSpecificBox::parse(crate::media::config_box_body(
                &dts.config_boxes,
                b"ddts",
            )?)?;
            CodecConfig::Dts {
                config,
                codec_fourcc: sinf_parsed.original_format.data_format,
                channel_count: dts.channelcount,
                sample_rate: dts.samplerate >> 16,
                sample_size: dts.samplesize,
            }
        }
        b"mha1" | b"mha2" | b"mhm1" | b"mhm2" => {
            let entry = find_protected_entry(stsd, b"enca").ok_or(Error::UnexpectedBox {
                expected: "enca entry for mha1/mha2/mhm1/mhm2 original_format",
            })?;
            let mha = crate::init_segment::MhaSampleEntry::parse(entry)?;
            let config = crate::mpegh::MHADecoderConfigurationRecord::parse(
                crate::media::config_box_body(&mha.config_boxes, &crate::mpegh::MHAC_FOURCC)?,
            )?;
            CodecConfig::MpegH {
                config,
                channel_count: mha.channelcount,
                sample_rate: mha.samplerate >> 16,
                sample_size: mha.samplesize,
            }
        }
        b"ac-4" => {
            let entry = find_protected_entry(stsd, b"enca").ok_or(Error::UnexpectedBox {
                expected: "enca entry for ac-4 original_format",
            })?;
            let ac4 = crate::init_segment::Ac4SampleEntry::parse(entry)?;
            let config = crate::ac4::Ac4SpecificBox::parse(crate::media::config_box_body(
                &ac4.config_boxes,
                &crate::ac4::DAC4_FOURCC,
            )?)?;
            CodecConfig::Ac4 {
                config,
                channel_count: ac4.channelcount,
                sample_rate: ac4.samplerate >> 16,
                sample_size: ac4.samplesize,
            }
        }
        _ => {
            return Err(Error::UnexpectedBox {
                expected: "avc1/hvc1/hev1/av01/vp09/vvc1/vvi1/mp4v/mp4a/Opus/fLaC/ac-3/ec-3/\
                           dtsc/dtsh/dtsl/dtse/mha1/mha2/mhm1/mhm2/ac-4 original_format \
                           (protected AVC/HEVC/AV1/VP9/VVC/MPEG-2 video or AAC/Opus/FLAC/AC-3/\
                           E-AC-3/DTS/MPEG-H/AC-4 audio)",
            });
        }
    };

    let tkhd = find_box(trak, b"tkhd").ok_or(Error::UnexpectedBox { expected: "tkhd" })?;
    let track_id = crate::init_segment::TrackHeaderBox::parse(tkhd)?.track_id;

    Ok(Some(ProtectedTrackSpec {
        track_id,
        timescale,
        codec_config,
        edit_list: track_edit_list(trak),
    }))
}

#[cfg(feature = "cli")]
pub(crate) fn harvest_moov_track_specs(
    moov_bytes: &[u8],
) -> Result<(u32, Vec<ProtectedTrackSpec>)> {
    let movie_timescale = mvhd_timescale(moov_bytes).unwrap_or(1000);
    let mut out = Vec::new();
    for trak in iter_child_boxes(moov_bytes, b"trak") {
        if let Some(spec) = protected_track_spec(trak, movie_timescale)? {
            out.push(spec);
        } else if let Some(spec) = unprotected_track_spec(trak)? {
            out.push(spec);
        }
    }
    Ok((movie_timescale, out))
}

#[cfg(feature = "cli")]
fn strip_traf_sample_encryption(traf_bytes: &[u8]) -> Vec<u8> {
    let body = &traf_bytes[BOX_HEADER_MIN_SIZE.min(traf_bytes.len())..];
    let mut new_body = Vec::with_capacity(body.len());
    for child in iter_boxes(body) {
        let child_type = &child[4..8];
        if child_type == b"senc" || child_type == b"saiz" || child_type == b"saio" {
            continue;
        }
        if child_type == b"uuid"
            && child.len() >= BOX_HEADER_MIN_SIZE + 16
            && child[BOX_HEADER_MIN_SIZE..BOX_HEADER_MIN_SIZE + 16] == PIFF_SAMPLE_ENCRYPTION_UUID
        {
            continue;
        }
        new_body.extend_from_slice(child);
    }
    let mut out = Vec::with_capacity(8 + new_body.len());
    out.extend_from_slice(&((8 + new_body.len()) as u32).to_be_bytes());
    out.extend_from_slice(b"traf");
    out.extend_from_slice(&new_body);
    out
}

#[cfg(feature = "cli")]
fn fullbox_flags(box_bytes: &[u8]) -> Option<u32> {
    let raw = box_bytes.get(BOX_HEADER_MIN_SIZE..BOX_HEADER_MIN_SIZE + FULL_HDR)?;
    Some(u32::from_be_bytes(raw.try_into().ok()?) & 0x00FF_FFFF)
}

#[cfg(feature = "cli")]
fn child_spans(body: &[u8]) -> alloc::vec::Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 8 <= body.len() {
        let size = u32::from_be_bytes(body[off..off + 4].try_into().unwrap()) as usize;
        if size < 8 || off + size > body.len() {
            break;
        }
        out.push((off, size));
        off += size;
    }
    out
}

#[cfg(feature = "cli")]
fn patch_traf_data_offsets(traf: &mut [u8], moof_delta: i64, bytes_removed_before: i64) {
    let body_start = BOX_HEADER_MIN_SIZE.min(traf.len());
    for (off, _size) in child_spans(&traf[body_start..]) {
        let abs = body_start + off;
        if traf.len() < abs + 8 {
            continue;
        }
        let box_type = &traf[abs + 4..abs + 8];
        if box_type == b"tfhd" && fullbox_flags(&traf[abs..]).is_some_and(|f| f & TFHD_BASE_DATA_OFFSET_PRESENT != 0)
        {
            let f = abs + BOX_HEADER_MIN_SIZE + FULL_HDR + 4;
            if traf.len() >= f + 8 {
                let old = u64::from_be_bytes(traf[f..f + 8].try_into().unwrap());
                let new = (old as i64 - bytes_removed_before - moof_delta).max(0) as u64;
                traf[f..f + 8].copy_from_slice(&new.to_be_bytes());
            }
        } else if box_type == b"trun" && fullbox_flags(&traf[abs..]).is_some_and(|f| f & TRUN_DATA_OFFSET_PRESENT != 0)
        {
            let f = abs + BOX_HEADER_MIN_SIZE + FULL_HDR + 4;
            if traf.len() >= f + 4 {
                let old = i32::from_be_bytes(traf[f..f + 4].try_into().unwrap());
                traf[f..f + 4].copy_from_slice(&((old as i64 - moof_delta) as i32).to_be_bytes());
            }
        }
    }
}

#[cfg(feature = "cli")]
pub(crate) fn strip_sample_encryption_boxes(moof_bytes: &[u8], bytes_removed_before: u64) -> (Vec<u8>, u64) {
    let body = &moof_bytes[BOX_HEADER_MIN_SIZE.min(moof_bytes.len())..];
    let mut children: Vec<Vec<u8>> = Vec::new();
    for child in iter_boxes(body) {
        if &child[4..8] == b"traf" {
            children.push(strip_traf_sample_encryption(child));
        } else {
            children.push(child.to_vec());
        }
    }
    let new_len: usize = 8 + children.iter().map(|c| c.len()).sum::<usize>();
    let moof_delta = moof_bytes.len() as i64 - new_len as i64;

    for child in &mut children {
        if child.len() >= 8 && &child[4..8] == b"traf" {
            patch_traf_data_offsets(child, moof_delta, bytes_removed_before as i64);
        }
    }

    let mut out = Vec::with_capacity(new_len);
    out.extend_from_slice(&(new_len as u32).to_be_bytes());
    out.extend_from_slice(b"moof");
    for child in children {
        out.extend_from_slice(&child);
    }
    (out, bytes_removed_before + moof_delta as u64)
}

#[cfg(feature = "cli")]
pub(crate) fn harvest_moov_crypto(moov_bytes: &[u8]) -> Result<Vec<TrackCrypto>> {
    let mut out = Vec::new();
    for trak in iter_child_boxes(moov_bytes, b"trak") {
        if let Some(crypto) = harvest_track(moov_bytes, trak, true)? {
            out.push(crypto);
        }
    }
    patch_zero_kids_from_pssh(moov_bytes, &mut out);
    Ok(out)
}

fn stsd_has_residual_protection_markers(stsd: &[u8]) -> bool {
    let body_start = BOX_HEADER_MIN_SIZE + FULL_HDR + STSD_ENTRY_COUNT;
    if body_start > stsd.len() {
        return false;
    }
    iter_boxes(&stsd[body_start..]).any(|entry| {
        entry.len() >= 8
            && (matches!(&entry[4..8], b"encv" | b"enca" | b"encs" | b"enct")
                || find_box(entry, b"sinf").is_some())
    })
}

#[cfg(feature = "cli")]
pub(crate) fn harvest_moov_residual_protection(moov_bytes: &[u8]) -> BTreeMap<u32, bool> {
    let mut out = BTreeMap::new();
    for trak in iter_child_boxes(moov_bytes, b"trak") {
        let Some(tkhd) = find_box(trak, b"tkhd") else {
            continue;
        };
        let Ok(parsed_tkhd) = crate::init_segment::TrackHeaderBox::parse(tkhd) else {
            continue;
        };
        let Some(stsd) = descend(trak, &[b"mdia", b"minf", b"stbl", b"stsd"]) else {
            continue;
        };
        out.insert(parsed_tkhd.track_id, stsd_has_residual_protection_markers(stsd));
    }
    out
}

fn demux_protected(file: &[u8]) -> Result<Media> {
    use crate::media::{Media, Track};
    use crate::pipeline::{Sample, TrackSpec};

    let moov = find_top_box(file, b"moov").ok_or(Error::UnexpectedBox { expected: "moov" })?;
    let movie_timescale = mvhd_timescale(moov).unwrap_or(1000);
    let fragmented = find_top_box(file, b"moof").is_some();
    let trex_defaults = harvest_trex_defaults(moov);

    let mut tracks = Vec::new();
    for trak in iter_child_boxes(moov, b"trak") {
        let spec = match protected_track_spec(trak, movie_timescale)? {
            Some(spec) => spec,
            None => match unprotected_track_spec(trak)? {
                Some(spec) => spec,
                None => continue,
            },
        };

        let samples = if fragmented {
            collect_fragment_samples(file, spec.track_id, &trex_defaults)?
        } else {
            let Some(stbl) = descend(trak, &[b"mdia", b"minf", b"stbl"]) else {
                continue;
            };
            let sizes = stsz_sizes(stbl)?;
            let sample_offsets = sample_file_offsets(stbl, &sizes)?;

            let durations: Vec<u32> = find_box(stbl, b"stts")
                .and_then(|s| crate::timing::TimeToSampleBox::parse(s).ok())
                .map(|stts| {
                    crate::container::progressive_demux::expand_stts(&stts, sizes.len())
                })
                .transpose()?
                .unwrap_or_else(|| vec![0u32; sizes.len()]);

            let composition_offsets: Vec<i32> = find_box(stbl, b"ctts")
                .and_then(|c| crate::timing::CompositionOffsetBox::parse(c).ok())
                .map(|ctts| {
                    crate::container::progressive_demux::expand_ctts(Some(&ctts), sizes.len())
                })
                .transpose()?
                .unwrap_or_else(|| vec![0i32; sizes.len()]);

            let mut samples = Vec::with_capacity(sizes.len());
            let mut dts_cursor: i64 = 0;
            for (i, (&size, &offset)) in sizes.iter().zip(sample_offsets.iter()).enumerate() {
                let end = offset
                    .checked_add(size)
                    .ok_or(Error::InvalidInput("sample offset + size overflow"))?;
                if end > file.len() {
                    return Err(Error::BufferTooShort {
                        need: end,
                        have: file.len(),
                        what: "protected sample data",
                    });
                }
                let dts = dts_cursor;
                let pts = dts + composition_offsets[i] as i64;
                samples.push(Sample {
                    data: file[offset..end].to_vec().into(),
                    dts: Some(dts),
                    pts: Some(pts),
                    duration: Some(durations[i]),
                    flags: crate::ir::SampleFlags::SYNC,
                    provenance: None,
                });
                dts_cursor += durations[i] as i64;
            }
            samples
        };

        let mut track = Track::new(
            TrackSpec::new(spec.track_id, spec.timescale, spec.codec_config),
            samples,
        );
        track.spec.edit_list = spec.edit_list;
        tracks.push(track);
    }

    if tracks.is_empty() {
        return Err(Error::UnexpectedBox {
            expected: "a protected AVC, HEVC, AV1, VP9, AAC, or Opus track",
        });
    }
    Ok(Media::new(tracks, movie_timescale))
}

fn collect_fragment_samples(
    file: &[u8],
    target_track_id: u32,
    trex_defaults: &BTreeMap<u32, TrexDefaults>,
) -> Result<Vec<crate::pipeline::Sample>> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    let mut pending_moof: Option<(usize, MovieFragmentBox)> = None;
    let mut next_dts: i64 = 0;
    let mut seeded = false;
    while offset + BOX_HEADER_MIN_SIZE <= file.len() {
        let (bx, consumed) = parse_box(&file[offset..])?;
        if bx.header.box_type.is(b"moof") {
            let moof = MovieFragmentBox::parse_body(bx.body)?;
            pending_moof = Some((offset, moof));
        } else if bx.header.box_type.is(b"mdat")
            && let Some((moof_off, moof)) = pending_moof.take()
        {
            if !seeded {
                if let Some(tfdt) = moof
                    .traf
                    .iter()
                    .find(|t| t.tfhd.track_id == target_track_id)
                    .and_then(|t| t.tfdt.as_ref())
                {
                    next_dts = tfdt.base_media_decode_time() as i64;
                }
                seeded = true;
            }
            absorb_protected_fragment(
                file,
                moof_off,
                &moof,
                target_track_id,
                trex_defaults,
                &mut next_dts,
                &mut out,
            )?;
        }
        if consumed == 0 {
            break;
        }
        offset += consumed;
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct TrexDefaults {
    pub(crate) sample_duration: Option<u32>,
    pub(crate) sample_size: Option<u32>,
    pub(crate) sample_flags: Option<u32>,
    pub(crate) default_sample_description_index: Option<u32>,
}

pub(crate) fn harvest_trex_defaults(moov: &[u8]) -> BTreeMap<u32, TrexDefaults> {
    let mut out = BTreeMap::new();
    let Some(mvex) = find_box(moov, b"mvex") else {
        return out;
    };
    for trex in iter_child_boxes(mvex, b"trex") {
        if trex.len() < 32 {
            continue;
        }
        let track_id = u32::from_be_bytes([trex[12], trex[13], trex[14], trex[15]]);
        out.insert(
            track_id,
            TrexDefaults {
                sample_duration: Some(u32::from_be_bytes([
                    trex[20], trex[21], trex[22], trex[23],
                ])),
                sample_size: Some(u32::from_be_bytes([trex[24], trex[25], trex[26], trex[27]])),
                sample_flags: Some(u32::from_be_bytes([trex[28], trex[29], trex[30], trex[31]])),
                default_sample_description_index: Some(u32::from_be_bytes([
                    trex[16], trex[17], trex[18], trex[19],
                ])),
            },
        );
    }
    out
}

fn resolve_trun_sample(
    tfhd: &TrackFragmentHeaderBox,
    trun: &TrackFragmentRunBox,
    i: usize,
    ts: &crate::movie_fragment::TrunSample,
    trex: Option<&TrexDefaults>,
) -> Result<(u32, u32, bool, i64)> {
    let size = ts
        .sample_size
        .or(tfhd.default_sample_size)
        .or(trex.and_then(|t| t.sample_size))
        .ok_or(Error::InvalidInput(
            "trun sample has no size (no trun.sample_size, no tfhd default_sample_size, no \
             trex default_sample_size)",
        ))?;
    let duration = ts
        .sample_duration
        .or(tfhd.default_sample_duration)
        .or(trex.and_then(|t| t.sample_duration))
        .unwrap_or(0);
    let per_sample = if i == 0 && trun.first_sample_flags.is_some() {
        trun.first_sample_flags
    } else {
        ts.sample_flags
    };
    let flags = per_sample
        .or(tfhd.default_sample_flags)
        .or(trex.and_then(|t| t.sample_flags))
        .unwrap_or(0);
    let is_sync = flags & SAMPLE_FLAG_IS_NON_SYNC == 0;
    let composition_offset = ts.sample_composition_time_offset.unwrap_or(0);
    Ok((size, duration, is_sync, composition_offset))
}

fn absorb_protected_fragment(
    file: &[u8],
    moof_off: usize,
    moof: &MovieFragmentBox,
    target_track_id: u32,
    trex_defaults: &BTreeMap<u32, TrexDefaults>,
    next_dts: &mut i64,
    out: &mut Vec<crate::pipeline::Sample>,
) -> Result<()> {
    use crate::pipeline::Sample;

    for traf in &moof.traf {
        let tfhd = &traf.tfhd;
        if tfhd.track_id != target_track_id {
            continue;
        }
        let trex = trex_defaults.get(&tfhd.track_id);
        let base_offset = tfhd.base_data_offset.unwrap_or(moof_off as u64) as i64;
        let mut run_end = base_offset;
        for trun in &traf.trun {
            let base = if trun.data_offset.is_some() {
                base_offset + trun.data_offset.unwrap_or(0) as i64
            } else {
                run_end
            };
            let mut cursor = base;
            for (i, ts) in trun.samples.iter().enumerate() {
                let (size, duration, is_sync, composition_offset) =
                    resolve_trun_sample(tfhd, trun, i, ts, trex)?;
                let size = size as usize;

                let start = usize::try_from(cursor)
                    .map_err(|_| Error::InvalidInput("negative sample data offset"))?;
                let end = start
                    .checked_add(size)
                    .ok_or(Error::InvalidInput("sample offset + size overflow"))?;
                if end > file.len() {
                    return Err(Error::BufferTooShort {
                        need: end,
                        have: file.len(),
                        what: "protected fragment sample data",
                    });
                }
                let dts = *next_dts;
                let pts = dts + composition_offset;
                out.push(Sample {
                    data: file[start..end].to_vec().into(),
                    dts: Some(dts),
                    pts: Some(pts),
                    duration: Some(duration),
                    flags: crate::ir::SampleFlags::new(is_sync),
                    provenance: None,
                });
                *next_dts += duration as i64;
                cursor += size as i64;
                run_end = cursor;
            }
        }
    }
    Ok(())
}

#[cfg(feature = "cli")]
#[derive(Debug, Clone, Copy)]
pub(crate) struct FragmentSampleLayout {
    pub(crate) file_offset: u64,
    pub(crate) size: u32,
    pub(crate) dts: i64,
    pub(crate) pts: i64,
    pub(crate) duration: u32,
    pub(crate) is_sync: bool,
}

#[cfg(feature = "cli")]
pub(crate) fn fragment_sample_layout(
    moof_off: u64,
    moof: &MovieFragmentBox,
    target_track_ids: &[u32],
    next_dts: &mut BTreeMap<u32, i64>,
    trex_defaults: &BTreeMap<u32, TrexDefaults>,
) -> Result<BTreeMap<u32, Vec<FragmentSampleLayout>>> {
    let mut out: BTreeMap<u32, Vec<FragmentSampleLayout>> = BTreeMap::new();
    for traf in &moof.traf {
        let tfhd = &traf.tfhd;
        if !target_track_ids.contains(&tfhd.track_id) {
            continue;
        }
        let trex = trex_defaults.get(&tfhd.track_id);
        let seed = traf
            .tfdt
            .as_ref()
            .map(|t| t.base_media_decode_time() as i64)
            .unwrap_or(0);
        let dts_cursor = next_dts.entry(tfhd.track_id).or_insert(seed);
        let track_out: &mut Vec<FragmentSampleLayout> = out.entry(tfhd.track_id).or_default();

        let base_offset = tfhd.base_data_offset.unwrap_or(moof_off) as i64;
        let mut run_end = base_offset;
        for trun in &traf.trun {
            let base = if trun.data_offset.is_some() {
                base_offset + trun.data_offset.unwrap_or(0) as i64
            } else {
                run_end
            };
            let mut cursor = base;
            for (i, ts) in trun.samples.iter().enumerate() {
                let (size, duration, is_sync, composition_offset) =
                    resolve_trun_sample(tfhd, trun, i, ts, trex)?;
                let file_offset = u64::try_from(cursor)
                    .map_err(|_| Error::InvalidInput("negative sample data offset"))?;
                let dts = *dts_cursor;
                let pts = dts + composition_offset;
                track_out.push(FragmentSampleLayout {
                    file_offset,
                    size,
                    dts,
                    pts,
                    duration,
                    is_sync,
                });
                *dts_cursor += duration as i64;
                cursor += size as i64;
                run_end = cursor;
            }
        }
    }
    Ok(out)
}

#[cfg(feature = "cli")]
pub(crate) struct FragmentTrackSamples {
    pub(crate) track_id: u32,
    pub(crate) layout: Vec<FragmentSampleLayout>,
    pub(crate) crypto: Vec<SampleEncryptionEntry>,
}

#[cfg(feature = "cli")]
pub(crate) fn harvest_fragment(
    moof_off: u64,
    moof_bytes: &[u8],
    tracks: &[TrackCrypto],
    target_track_ids: &[u32],
    next_dts: &mut BTreeMap<u32, i64>,
    trex_defaults: &BTreeMap<u32, TrexDefaults>,
    aux_source: Option<&[u8]>,
) -> Result<Vec<FragmentTrackSamples>> {
    let (bx, _) = parse_box(moof_bytes)?;
    let moof = MovieFragmentBox::parse_body(bx.body)?;

    let mut crypto_scratch: Vec<TrackCrypto> = tracks
        .iter()
        .filter(|t| target_track_ids.contains(&t.track_id))
        .map(|t| TrackCrypto {
            track_id: t.track_id,
            tenc: t.tenc.clone(),
            original_format: t.original_format,
            scheme: t.scheme,
            samples: Vec::new(),
            protected_stsd_indices: t.protected_stsd_indices.clone(),
            seig: t.seig.clone(),
        })
        .collect();
    let aux = aux_source.map(|data| AuxSource {
        data,
        data_base_offset: 0,
        moof_file_offset: moof_off,
    });
    harvest_fragment_senc(moof_bytes, &mut crypto_scratch, trex_defaults, aux.as_ref())?;

    let mut layouts =
        fragment_sample_layout(moof_off, &moof, target_track_ids, next_dts, trex_defaults)?;

    let mut out = Vec::with_capacity(crypto_scratch.len());
    for tc in crypto_scratch {
        let Some(layout) = layouts.remove(&tc.track_id) else {
            continue;
        };
        out.push(FragmentTrackSamples {
            track_id: tc.track_id,
            layout,
            crypto: tc.samples,
        });
    }
    Ok(out)
}

fn find_avcc_config(
    stsd: &[u8],
) -> Result<(crate::avc_config::AVCDecoderConfigurationRecord, u16, u16)> {
    let body_start = BOX_HEADER_MIN_SIZE + FULL_HDR + STSD_ENTRY_COUNT;
    for entry in iter_boxes(&stsd[body_start.min(stsd.len())..]) {
        if &entry[4..8] == b"encv" {
            let child_start = BOX_HEADER_MIN_SIZE + VISUAL_SAMPLE_ENTRY_HDR;
            if child_start <= entry.len()
                && let Some(avcc) = iter_boxes(&entry[child_start..]).find(|b| &b[4..8] == b"avcC")
            {
                let cfg = crate::AVCConfigurationBox::parse_body(&avcc[BOX_HEADER_MIN_SIZE..])?;
                let (width, height) = read_visual_sample_entry_dims(entry);
                return Ok((cfg.config, width, height));
            }
        }
    }
    Err(Error::UnexpectedBox {
        expected: "avcC inside encv",
    })
}

fn find_hvcc_config(
    stsd: &[u8],
) -> Result<(crate::hevc_config::HEVCDecoderConfigurationRecord, u16, u16)> {
    let body_start = BOX_HEADER_MIN_SIZE + FULL_HDR + STSD_ENTRY_COUNT;
    for entry in iter_boxes(&stsd[body_start.min(stsd.len())..]) {
        if &entry[4..8] == b"encv" {
            let child_start = BOX_HEADER_MIN_SIZE + VISUAL_SAMPLE_ENTRY_HDR;
            if child_start <= entry.len()
                && let Some(hvcc) = iter_boxes(&entry[child_start..]).find(|b| &b[4..8] == b"hvcC")
            {
                let cfg = crate::hevc_config::HEVCConfigurationBox::parse_body(
                    &hvcc[BOX_HEADER_MIN_SIZE..],
                )?;
                let (width, height) = read_visual_sample_entry_dims(entry);
                return Ok((cfg.config, width, height));
            }
        }
    }
    Err(Error::UnexpectedBox {
        expected: "hvcC inside encv",
    })
}

fn find_esds_config(stsd: &[u8]) -> Result<(crate::mp4esds::EsdsBox, u16, u32, u16)> {
    const AUDIO_SAMPLE_ENTRY_HDR: usize = 28;
    let body_start = BOX_HEADER_MIN_SIZE + FULL_HDR + STSD_ENTRY_COUNT;
    for entry in iter_boxes(&stsd[body_start.min(stsd.len())..]) {
        if &entry[4..8] == b"enca" {
            let fixed_start = BOX_HEADER_MIN_SIZE;
            let child_start = fixed_start + AUDIO_SAMPLE_ENTRY_HDR;
            if child_start > entry.len() {
                continue;
            }
            let channel_count =
                u16::from_be_bytes([entry[fixed_start + 16], entry[fixed_start + 17]]);
            let sample_size =
                u16::from_be_bytes([entry[fixed_start + 18], entry[fixed_start + 19]]);
            let sample_rate = u32::from_be_bytes([
                entry[fixed_start + 24],
                entry[fixed_start + 25],
                entry[fixed_start + 26],
                entry[fixed_start + 27],
            ]) >> 16;
            if let Some(esds) = iter_boxes(&entry[child_start..]).find(|b| &b[4..8] == b"esds") {
                let cfg = crate::mp4esds::EsdsBox::parse_body(&esds[BOX_HEADER_MIN_SIZE..])?;
                return Ok((cfg, channel_count, sample_rate, sample_size));
            }
        }
    }
    Err(Error::UnexpectedBox {
        expected: "esds inside enca",
    })
}

fn iter_boxes(data: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut offset = 0usize;
    core::iter::from_fn(move || {
        if offset + BOX_HEADER_MIN_SIZE > data.len() {
            return None;
        }
        let (bx, consumed) = parse_box(&data[offset..]).ok()?;
        if consumed == 0 {
            return None;
        }
        let size = if bx.header.size == 0 {
            data.len() - offset
        } else {
            (bx.header.size as usize).min(data.len() - offset)
        };
        let start = offset;
        offset += consumed;
        Some(&data[start..start + size])
    })
}

fn iter_child_boxes<'a>(
    container: &'a [u8],
    fourcc: &'a [u8; 4],
) -> impl Iterator<Item = &'a [u8]> {
    let body = &container[BOX_HEADER_MIN_SIZE.min(container.len())..];
    iter_boxes(body).filter(move |b| &b[4..8] == fourcc)
}

fn iter_top_boxes<'a>(file: &'a [u8], fourcc: &[u8; 4]) -> impl Iterator<Item = &'a [u8]> {
    iter_boxes(file).filter(move |b| b[4..8] == *fourcc)
}

fn find_box<'a>(container: &'a [u8], fourcc: &[u8; 4]) -> Option<&'a [u8]> {
    let body = &container[BOX_HEADER_MIN_SIZE.min(container.len())..];
    iter_boxes(body).find(|b| &b[4..8] == fourcc)
}

fn find_top_box<'a>(file: &'a [u8], fourcc: &[u8; 4]) -> Option<&'a [u8]> {
    iter_boxes(file).find(|b| &b[4..8] == fourcc)
}

fn descend<'a>(start: &'a [u8], path: &[&[u8; 4]]) -> Option<&'a [u8]> {
    let mut cur = start;
    for fourcc in path {
        cur = find_box(cur, fourcc)?;
    }
    Some(cur)
}

fn mvhd_timescale(moov: &[u8]) -> Option<u32> {
    let mvhd = find_box(moov, b"mvhd")?;
    let version = mvhd.get(BOX_HEADER_MIN_SIZE)?;
    let ts_off = if *version == 1 {
        BOX_HEADER_MIN_SIZE + FULL_HDR + 16
    } else {
        BOX_HEADER_MIN_SIZE + FULL_HDR + 8
    };
    Some(u32::from_be_bytes([
        *mvhd.get(ts_off)?,
        *mvhd.get(ts_off + 1)?,
        *mvhd.get(ts_off + 2)?,
        *mvhd.get(ts_off + 3)?,
    ]))
}

fn mdhd_timescale(mdhd: &[u8]) -> Option<u32> {
    let version = mdhd.get(BOX_HEADER_MIN_SIZE)?;
    let ts_off = if *version == 1 {
        BOX_HEADER_MIN_SIZE + FULL_HDR + 16
    } else {
        BOX_HEADER_MIN_SIZE + FULL_HDR + 8
    };
    Some(u32::from_be_bytes([
        *mdhd.get(ts_off)?,
        *mdhd.get(ts_off + 1)?,
        *mdhd.get(ts_off + 2)?,
        *mdhd.get(ts_off + 3)?,
    ]))
}

#[cfg(feature = "cli")]
fn mdhd_duration_language(mdhd: &[u8]) -> Option<(u64, [u8; 3])> {
    let version = *mdhd.get(BOX_HEADER_MIN_SIZE)?;
    let (dur_off, dur_size) = if version == 1 {
        (BOX_HEADER_MIN_SIZE + FULL_HDR + 20, 8usize)
    } else {
        (BOX_HEADER_MIN_SIZE + FULL_HDR + 12, 4usize)
    };
    let duration = if dur_size == 8 {
        u64::from_be_bytes(mdhd.get(dur_off..dur_off + 8)?.try_into().ok()?)
    } else {
        u32::from_be_bytes(mdhd.get(dur_off..dur_off + 4)?.try_into().ok()?) as u64
    };
    let lang_off = dur_off + dur_size;
    let packed = u16::from_be_bytes(mdhd.get(lang_off..lang_off + 2)?.try_into().ok()?);
    let language = [
        (((packed >> 10) & 0x1F) as u8) + 0x60,
        (((packed >> 5) & 0x1F) as u8) + 0x60,
        ((packed & 0x1F) as u8) + 0x60,
    ];
    Some((duration, language))
}

#[cfg(feature = "cli")]
fn find_track_pasp(trak: &[u8]) -> Option<(u32, u32)> {
    let stbl = descend(trak, &[b"mdia", b"minf", b"stbl"])?;
    let stsd = find_box(stbl, b"stsd")?;
    let body_start = BOX_HEADER_MIN_SIZE + FULL_HDR + STSD_ENTRY_COUNT;
    let entry = iter_boxes(&stsd[body_start.min(stsd.len())..]).next()?;
    let child_start = BOX_HEADER_MIN_SIZE + VISUAL_SAMPLE_ENTRY_HDR;
    if child_start > entry.len() {
        return None;
    }
    let pasp = iter_boxes(&entry[child_start..]).find(|b| &b[4..8] == b"pasp")?;
    let cfg = crate::visual_ext::PixelAspectRatioBox::parse(&pasp[BOX_HEADER_MIN_SIZE..]).ok()?;
    Some((cfg.h_spacing, cfg.v_spacing))
}

#[cfg(feature = "cli")]
pub(crate) struct TrackDumpExtras {
    pub(crate) track_id: u32,
    pub(crate) duration: u64,
    pub(crate) language: [u8; 3],
    pub(crate) pixel_aspect: Option<(u32, u32)>,
}

#[cfg(feature = "cli")]
pub(crate) fn harvest_moov_dump_extras(moov_bytes: &[u8]) -> Result<Vec<TrackDumpExtras>> {
    let mut out = Vec::new();
    for trak in iter_child_boxes(moov_bytes, b"trak") {
        let tkhd = find_box(trak, b"tkhd").ok_or(Error::UnexpectedBox { expected: "tkhd" })?;
        let track_id = crate::init_segment::TrackHeaderBox::parse(tkhd)?.track_id;
        let (duration, language) = descend(trak, &[b"mdia"])
            .and_then(|mdia| find_box(mdia, b"mdhd"))
            .and_then(mdhd_duration_language)
            .unwrap_or((0, *b"und"));
        let pixel_aspect = find_track_pasp(trak);
        out.push(TrackDumpExtras {
            track_id,
            duration,
            language,
            pixel_aspect,
        });
    }
    Ok(out)
}

fn stsz_sizes(stbl: &[u8]) -> Result<Vec<usize>> {
    let stsz = find_box(stbl, b"stsz").ok_or(Error::UnexpectedBox { expected: "stsz" })?;
    let base = BOX_HEADER_MIN_SIZE + FULL_HDR;
    let need = base + 8;
    if stsz.len() < need {
        return Err(Error::BufferTooShort {
            need,
            have: stsz.len(),
            what: "stsz header",
        });
    }
    let sample_size =
        u32::from_be_bytes([stsz[base], stsz[base + 1], stsz[base + 2], stsz[base + 3]]);
    let count = u32::from_be_bytes([
        stsz[base + 4],
        stsz[base + 5],
        stsz[base + 6],
        stsz[base + 7],
    ]) as usize;
    let mut sizes = Vec::with_capacity(count);
    if sample_size != 0 {
        for _ in 0..count {
            sizes.push(sample_size as usize);
        }
    } else {
        let table = base + 8;
        let end = table + count * 4;
        if stsz.len() < end {
            return Err(Error::BufferTooShort {
                need: end,
                have: stsz.len(),
                what: "stsz sample_size table",
            });
        }
        for i in 0..count {
            let o = table + i * 4;
            sizes.push(
                u32::from_be_bytes([stsz[o], stsz[o + 1], stsz[o + 2], stsz[o + 3]]) as usize,
            );
        }
    }
    Ok(sizes)
}

fn sample_file_offsets(stbl: &[u8], sizes: &[usize]) -> Result<Vec<usize>> {
    let stsc = find_box(stbl, b"stsc").ok_or(Error::UnexpectedBox { expected: "stsc" })?;
    let stco = find_box(stbl, b"stco").ok_or(Error::UnexpectedBox { expected: "stco" })?;
    let sc_base = BOX_HEADER_MIN_SIZE + FULL_HDR;

    if stco.len() < sc_base + 4 {
        return Err(Error::BufferTooShort {
            need: sc_base + 4,
            have: stco.len(),
            what: "stco header",
        });
    }
    let chunk_count = u32::from_be_bytes([
        stco[sc_base],
        stco[sc_base + 1],
        stco[sc_base + 2],
        stco[sc_base + 3],
    ]) as usize;
    let mut chunk_offsets = Vec::with_capacity(chunk_count);
    let co_table = sc_base + 4;
    if stco.len() < co_table + chunk_count * 4 {
        return Err(Error::BufferTooShort {
            need: co_table + chunk_count * 4,
            have: stco.len(),
            what: "stco chunk offsets",
        });
    }
    for i in 0..chunk_count {
        let o = co_table + i * 4;
        chunk_offsets
            .push(u32::from_be_bytes([stco[o], stco[o + 1], stco[o + 2], stco[o + 3]]) as usize);
    }

    if stsc.len() < sc_base + 4 {
        return Err(Error::BufferTooShort {
            need: sc_base + 4,
            have: stsc.len(),
            what: "stsc header",
        });
    }
    let entry_count = u32::from_be_bytes([
        stsc[sc_base],
        stsc[sc_base + 1],
        stsc[sc_base + 2],
        stsc[sc_base + 3],
    ]) as usize;
    let sc_table = sc_base + 4;
    if stsc.len() < sc_table + entry_count * 12 {
        return Err(Error::BufferTooShort {
            need: sc_table + entry_count * 12,
            have: stsc.len(),
            what: "stsc entries",
        });
    }
    let mut samples_per_chunk = Vec::with_capacity(chunk_count);
    for c in 0..chunk_count {
        let chunk_no = (c + 1) as u32;
        let mut spc = 0u32;
        for e in 0..entry_count {
            let o = sc_table + e * 12;
            let first_chunk = u32::from_be_bytes([stsc[o], stsc[o + 1], stsc[o + 2], stsc[o + 3]]);
            let per = u32::from_be_bytes([stsc[o + 4], stsc[o + 5], stsc[o + 6], stsc[o + 7]]);
            if first_chunk <= chunk_no {
                spc = per;
            } else {
                break;
            }
        }
        samples_per_chunk.push(spc);
    }

    let mut offsets = Vec::with_capacity(sizes.len());
    let mut sample_idx = 0usize;
    for (c, &chunk_base) in chunk_offsets.iter().enumerate() {
        let per = samples_per_chunk.get(c).copied().unwrap_or(0) as usize;
        let mut cursor = chunk_base;
        for _ in 0..per {
            if sample_idx >= sizes.len() {
                break;
            }
            offsets.push(cursor);
            cursor += sizes[sample_idx];
            sample_idx += 1;
        }
    }
    if offsets.len() != sizes.len() {
        return Err(Error::InvalidInput(
            "stsc/stco sample-to-chunk mapping did not cover all samples",
        ));
    }
    Ok(offsets)
}

#[cfg(test)]
mod fragment_default_chain_tests {
    use std::collections::BTreeMap;

    use crate::box_types::{BOX_HEADER_MIN_SIZE, parse_box};
    use crate::cenc::{CencScheme, TrackEncryptionBox};
    use crate::crypto::cenc_decrypt::{
        fragment_sample_layout, harvest_fragment_senc, resolve_trun_sample, AuxSource, SeigData,
        SeigGroup, TrackCrypto, TrexDefaults,
    };
    use crate::movie_fragment::{
        MovieFragmentBox, TrackFragmentHeaderBox, TrackFragmentRunBox, TRUN_DATA_OFFSET_PRESENT,
        TRUN_FIRST_SAMPLE_FLAGS_PRESENT, TRUN_SAMPLE_COMPOSITION_TIME_OFFSET_PRESENT,
        TRUN_SAMPLE_DURATION_PRESENT, TRUN_SAMPLE_FLAGS_PRESENT, TRUN_SAMPLE_SIZE_PRESENT,
    };

    const SAMPLE_FLAG_IS_NON_SYNC: u32 = 0x0001_0000;

    fn box_hdr(box_type: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut b = Vec::with_capacity(payload.len() + 8);
        b.extend_from_slice(&((payload.len() + 8) as u32).to_be_bytes());
        b.extend_from_slice(box_type);
        b.extend_from_slice(payload);
        b
    }

    fn make_tfhd(track_id: u32, sdi: Option<u32>) -> Vec<u8> {
        let mut body = Vec::new();
        let mut flags = 0u32;
        if sdi.is_some() {
            flags |= crate::movie_fragment::TFHD_SAMPLE_DESCRIPTION_INDEX_PRESENT;
        }
        body.extend_from_slice(&flags.to_be_bytes());
        body.extend_from_slice(&track_id.to_be_bytes());
        if let Some(s) = sdi {
            body.extend_from_slice(&s.to_be_bytes());
        }
        box_hdr(b"tfhd", &body)
    }

    fn make_trun(
        version: u8,
        flags: u32,
        sample_count: u32,
        data_offset: Option<i32>,
        first_sample_flags: Option<u32>,
        samples: &[(Option<u32>, Option<u32>, Option<u32>, Option<u32>)],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        let verflags = ((version as u32) << 24) | (flags & 0x00FF_FFFF);
        body.extend_from_slice(&verflags.to_be_bytes());
        body.extend_from_slice(&sample_count.to_be_bytes());
        if flags & TRUN_DATA_OFFSET_PRESENT != 0 {
            body.extend_from_slice(&data_offset.unwrap_or(0).to_be_bytes());
        }
        if flags & TRUN_FIRST_SAMPLE_FLAGS_PRESENT != 0 {
            body.extend_from_slice(&first_sample_flags.unwrap_or(0).to_be_bytes());
        }
        for (dur, sz, fl, cto) in samples {
            if flags & TRUN_SAMPLE_DURATION_PRESENT != 0 {
                body.extend_from_slice(&dur.unwrap_or(0).to_be_bytes());
            }
            if flags & TRUN_SAMPLE_SIZE_PRESENT != 0 {
                body.extend_from_slice(&sz.unwrap_or(0).to_be_bytes());
            }
            if flags & TRUN_SAMPLE_FLAGS_PRESENT != 0 {
                body.extend_from_slice(&fl.unwrap_or(0).to_be_bytes());
            }
            if flags & TRUN_SAMPLE_COMPOSITION_TIME_OFFSET_PRESENT != 0 {
                body.extend_from_slice(&cto.unwrap_or(0).to_be_bytes());
            }
        }
        box_hdr(b"trun", &body)
    }

    fn make_mfhd() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_be_bytes());
        body.extend_from_slice(&1u32.to_be_bytes());
        box_hdr(b"mfhd", &body)
    }

    fn make_moof(traf_children: &[Vec<u8>]) -> Vec<u8> {
        let mut traf_body = Vec::new();
        for c in traf_children {
            traf_body.extend_from_slice(c);
        }
        let traf = box_hdr(b"traf", &traf_body);
        let mfhd = make_mfhd();
        let mut moof_body = Vec::new();
        moof_body.extend_from_slice(&mfhd);
        moof_body.extend_from_slice(&traf);
        box_hdr(b"moof", &moof_body)
    }

    fn make_track(protected_indices: &[u32]) -> TrackCrypto {
        TrackCrypto {
            track_id: 1,
            tenc: TrackEncryptionBox {
                version: 0,
                default_crypt_byte_block: 0,
                default_skip_byte_block: 0,
                default_is_protected: 1,
                default_per_sample_iv_size: 16,
                default_kid: [0u8; 16],
                default_constant_iv: None,
            },
            original_format: *b"avc1",
            scheme: CencScheme::Cenc,
            samples: Vec::new(),
            protected_stsd_indices: protected_indices.to_vec(),
            seig: None,
        }
    }

    fn make_sgpd_seig(groups: &[(bool, Option<[u8; 16]>)]) -> Vec<u8> {
        let entry_len: usize = 1 + 1 + 1 + 1 + 16;
        let mut body = Vec::new();
        body.push(1);
        body.extend_from_slice(&[0, 0, 1]);
        body.extend_from_slice(b"seig");
        body.extend_from_slice(&(entry_len as u32).to_be_bytes());
        body.extend_from_slice(&(groups.len() as u32).to_be_bytes());
        for (protected, kid) in groups {
            let mut desc = vec![0u8; entry_len];
            if *protected {
                desc[2] = 1;
                desc[3] = 16;
                desc[4..20].copy_from_slice(&kid.unwrap_or([0u8; 16]));
            }
            body.extend_from_slice(&desc);
        }
        box_hdr(b"sgpd", &body)
    }

    fn make_sbgp_seig(runs: &[(u32, u32)]) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(1);
        body.extend_from_slice(&[0, 0, 0]);
        body.extend_from_slice(b"seig");
        body.extend_from_slice(&0u32.to_be_bytes());
        body.extend_from_slice(&(runs.len() as u32).to_be_bytes());
        for (sc, gi) in runs {
            body.extend_from_slice(&sc.to_be_bytes());
            body.extend_from_slice(&gi.to_be_bytes());
        }
        box_hdr(b"sbgp", &body)
    }

    fn make_saiz(default_size: u8, count: u32) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_be_bytes());
        body.push(default_size);
        body.extend_from_slice(&count.to_be_bytes());
        box_hdr(b"saiz", &body)
    }

    fn make_saio_v0(offsets: &[u32]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_be_bytes());
        body.extend_from_slice(&(offsets.len() as u32).to_be_bytes());
        for o in offsets {
            body.extend_from_slice(&o.to_be_bytes());
        }
        box_hdr(b"saio", &body)
    }

    #[test]
    fn fragmented_saiz_saio_resolves_real_iv_via_aux_source_and_errors_without_it() {
        let tfhd = make_tfhd(1, Some(1));
        let trun = make_trun(
            0,
            TRUN_DATA_OFFSET_PRESENT | TRUN_SAMPLE_SIZE_PRESENT,
            1,
            Some(0),
            None,
            &[(None, Some(4), None, None)],
        );
        let saiz = make_saiz(16, 1);
        let saio_placeholder = make_saio_v0(&[0]);
        let moof_len = make_moof(&[tfhd.clone(), trun.clone(), saiz.clone(), saio_placeholder]).len();
        let saio = make_saio_v0(&[moof_len as u32]);
        let moof = make_moof(&[tfhd, trun, saiz, saio]);
        assert_eq!(moof.len(), moof_len, "saio offset value must not change box sizes");

        let real_iv = [0xABu8; 16];
        let mut full_file = moof.clone();
        full_file.extend_from_slice(&real_iv);
        full_file.extend_from_slice(&[0u8; 4]);

        let trex = BTreeMap::new();

        let mut tracks_no_aux = vec![make_track(&[1])];
        let err = harvest_fragment_senc(&moof, &mut tracks_no_aux, &trex, None);
        assert!(
            err.is_err(),
            "saiz/saio pointing outside the available buffer must error, not synthesize a placeholder IV"
        );

        let aux = AuxSource {
            data: &full_file,
            data_base_offset: 0,
            moof_file_offset: 0,
        };
        let mut tracks = vec![make_track(&[1])];
        harvest_fragment_senc(&moof, &mut tracks, &trex, Some(&aux)).unwrap();
        assert_eq!(tracks[0].samples.len(), 1);
        assert_eq!(
            tracks[0].samples[0].initialization_vector,
            real_iv.to_vec(),
            "must resolve the real IV from the aux buffer, not a placeholder"
        );
        assert!(tracks[0].samples[0].is_encrypted);
    }

    #[test]
    fn clear_lead_respects_trex_default_sample_description_index() {
        let mut tracks = vec![make_track(&[1])];
        let tfhd = make_tfhd(1, None);
        let trun = make_trun(0, TRUN_DATA_OFFSET_PRESENT, 2, Some(0), None, &[]);
        let moof = make_moof(&[tfhd, trun]);
        let mut trex = BTreeMap::new();
        trex.insert(
            1u32,
            TrexDefaults {
                sample_duration: None,
                sample_size: None,
                sample_flags: None,
                default_sample_description_index: Some(2),
            },
        );
        harvest_fragment_senc(&moof, &mut tracks, &trex, None).unwrap();
        assert_eq!(tracks[0].samples.len(), 2);
        assert!(
            tracks[0].samples.iter().all(|s| !s.is_encrypted),
            "fragment whose trex default sdi -> clear entry must be clear-lead"
        );

        let mut tracks2 = vec![make_track(&[1])];
        let tfhd2 = make_tfhd(1, Some(1));
        let trun2 = make_trun(0, TRUN_DATA_OFFSET_PRESENT, 2, Some(0), None, &[]);
        let moof2 = make_moof(&[tfhd2, trun2]);
        harvest_fragment_senc(&moof2, &mut tracks2, &trex, None).unwrap();
        assert!(
            tracks2[0].samples.iter().all(|s| s.is_encrypted),
            "explicit tfhd sdi=1 must be treated as protected"
        );
    }

    #[test]
    fn missing_sdi_defaults_to_1() {
        let mut tracks = vec![make_track(&[1])];
        let tfhd = make_tfhd(1, None);
        let trun = make_trun(0, TRUN_DATA_OFFSET_PRESENT, 2, Some(0), None, &[]);
        let moof = make_moof(&[tfhd, trun]);
        let trex = BTreeMap::new();
        harvest_fragment_senc(&moof, &mut tracks, &trex, None).unwrap();
        assert!(
            tracks[0].samples.iter().all(|s| s.is_encrypted),
            "omitted sdi with no trex default must default to index 1 (protected here)"
        );
    }

    #[test]
    fn first_sample_flags_overrides_per_sample_for_sample0() {
        let tfhd_bytes = make_tfhd(1, None);
        let tfhd = TrackFragmentHeaderBox::parse_body(&tfhd_bytes[BOX_HEADER_MIN_SIZE..]).unwrap();
        let flags =
            TRUN_FIRST_SAMPLE_FLAGS_PRESENT | TRUN_SAMPLE_FLAGS_PRESENT | TRUN_SAMPLE_SIZE_PRESENT;
        let trun_bytes = make_trun(
            0,
            flags,
            2,
            None,
            Some(SAMPLE_FLAG_IS_NON_SYNC),
            &[
                (None, Some(1), Some(0), None),
                (None, Some(1), Some(0), None),
            ],
        );
        let trun = TrackFragmentRunBox::parse_body(&trun_bytes[BOX_HEADER_MIN_SIZE..]).unwrap();

        let (_sz, _dur, is_sync0, _cto) =
            resolve_trun_sample(&tfhd, &trun, 0, &trun.samples[0], None).unwrap();
        assert!(
            !is_sync0,
            "sample 0 must use first_sample_flags, not the per-sample entry"
        );
        let (_sz, _dur, is_sync1, _cto) =
            resolve_trun_sample(&tfhd, &trun, 1, &trun.samples[1], None).unwrap();
        assert!(is_sync1, "sample 1 falls back to its per-sample flags");
    }

    #[test]
    fn trun_data_offset_continues_across_runs_in_same_traf() {
        let tfhd = make_tfhd(1, None);
        let trun0 = make_trun(
            0,
            TRUN_DATA_OFFSET_PRESENT | TRUN_SAMPLE_SIZE_PRESENT,
            2,
            Some(100),
            None,
            &[(None, Some(10), None, None), (None, Some(10), None, None)],
        );
        let trun1 = make_trun(
            0,
            TRUN_SAMPLE_SIZE_PRESENT,
            2,
            None,
            None,
            &[(None, Some(10), None, None), (None, Some(10), None, None)],
        );
        let moof = make_moof(&[tfhd, trun0, trun1]);
        let (bx, _) = parse_box(&moof).unwrap();
        let moof_parsed = MovieFragmentBox::parse_body(bx.body).unwrap();
        let mut next_dts = BTreeMap::new();
        let trex = BTreeMap::new();
        let layout =
            fragment_sample_layout(0, &moof_parsed, &[1u32], &mut next_dts, &trex).unwrap();
        let s = &layout[&1];
        assert_eq!(s.len(), 4, "expected 4 samples across 2 truns");
        assert_eq!(s[0].file_offset, 100);
        assert_eq!(s[1].file_offset, 110);
        assert_eq!(
            s[2].file_offset, 120,
            "2nd trun must continue after the 1st trun's last sample"
        );
        assert_eq!(s[3].file_offset, 130);
        assert_ne!(s[2].file_offset, 0, "bug: 2nd trun reset to base offset");
    }

    #[test]
    fn trun_v0_composition_time_offset_is_unsigned() {
        let bytes = make_trun(
            0,
            TRUN_DATA_OFFSET_PRESENT | TRUN_SAMPLE_COMPOSITION_TIME_OFFSET_PRESENT,
            1,
            Some(0),
            None,
            &[(None, None, None, Some(0xFFFF_FFF0))],
        );
        let trun = TrackFragmentRunBox::parse_body(&bytes[BOX_HEADER_MIN_SIZE..]).unwrap();
        assert_eq!(
            trun.samples[0].sample_composition_time_offset,
            Some(0xFFFF_FFF0u64 as i64)
        );
        let bytes1 = make_trun(
            1,
            TRUN_DATA_OFFSET_PRESENT | TRUN_SAMPLE_COMPOSITION_TIME_OFFSET_PRESENT,
            1,
            Some(0),
            None,
            &[(None, None, None, Some(0xFFFF_FFFB))],
        );
        let trun1 = TrackFragmentRunBox::parse_body(&bytes1[BOX_HEADER_MIN_SIZE..]).unwrap();
        assert_eq!(trun1.samples[0].sample_composition_time_offset, Some(-5i64));
    }

    #[test]
    fn seig_traf_sgpd_sbgp_drives_clear_lead_and_group_kid() {
        let kid2 = [2u8; 16];
        let mut tracks = vec![make_track(&[1])];
        let tfhd = make_tfhd(1, Some(1));
        let trun = make_trun(0, TRUN_DATA_OFFSET_PRESENT, 2, Some(0), None, &[]);
        let sgpd = make_sgpd_seig(&[(false, None), (true, Some(kid2))]);
        let sbgp = make_sbgp_seig(&[(1, 1), (1, 2)]);
        let moof = make_moof(&[tfhd, trun, sgpd, sbgp]);
        let trex = BTreeMap::new();
        harvest_fragment_senc(&moof, &mut tracks, &trex, None).unwrap();
        let samples = &tracks[0].samples;
        assert_eq!(samples.len(), 2);
        assert!(
            !samples[0].is_encrypted,
            "seig group 1 (is_protected==0) must clear-lead sample 0"
        );
        assert_eq!(samples[0].explicit_kid, None);
        assert!(
            samples[1].is_encrypted,
            "seig group 2 protected must keep sample 1 encrypted"
        );
        assert_eq!(
            samples[1].explicit_kid,
            Some(kid2),
            "seig group 2 key_id must rotate sample 1's content key"
        );
    }

    #[test]
    fn seig_moov_groups_fallback_with_traf_sbgp() {
        let kid3 = [3u8; 16];
        let mut tracks = vec![make_track(&[1])];
        tracks[0].seig = Some(SeigData {
            groups: vec![
                SeigGroup {
                    is_protected: false,
                    kid: None,
                },
                SeigGroup {
                    is_protected: true,
                    kid: Some(kid3),
                },
            ],
        });
        let tfhd = make_tfhd(1, Some(1));
        let trun = make_trun(0, TRUN_DATA_OFFSET_PRESENT, 2, Some(0), None, &[]);
        let sbgp = make_sbgp_seig(&[(1, 1), (1, 2)]);
        let moof = make_moof(&[tfhd, trun, sbgp]);
        let trex = BTreeMap::new();
        harvest_fragment_senc(&moof, &mut tracks, &trex, None).unwrap();
        let samples = &tracks[0].samples;
        assert!(!samples[0].is_encrypted, "clear-lead group must mark sample 0 clear");
        assert!(samples[1].is_encrypted, "protected group must mark sample 1 encrypted");
        assert_eq!(samples[1].explicit_kid, Some(kid3), "group kid must carry onto sample 1");
    }

    #[test]
    fn whole_file_progressive_stts_and_ctts_populated_from_source() {
        let bytes = std::fs::read("tests/fixtures/enc_saiz_saio.mp4")
            .expect("enc_saiz_saio.mp4 fixture present");
        let media = crate::cenc_decrypt::CencDecryptor::from_fmp4(&bytes)
            .expect("from_fmp4")
            .demux()
            .expect("demux");
        assert!(!media.tracks.is_empty(), "must decode at least one track");
        let mut any_nonzero_composition_offset = false;
        for track in &media.tracks {
            assert!(!track.samples.is_empty(), "track has samples");
            for s in &track.samples {
                assert!(
                    s.duration.unwrap_or(0) > 0,
                    "whole-file demux must populate per-sample durations from stts (was 0 -> broken stts)"
                );
                assert!(
                    s.dts.is_some() && s.pts.is_some(),
                    "whole-file demux must populate dts/pts from stts+ctts, not leave them None \
                     (composition_offset() silently reads back 0 otherwise)"
                );
                if s.composition_offset() != 0 {
                    any_nonzero_composition_offset = true;
                }
            }
        }
        assert!(
            any_nonzero_composition_offset,
            "this fixture's video track has a non-trivial ctts -- expected at least one sample \
             with a real (non-zero) composition offset once ctts is actually read"
        );
    }
}
