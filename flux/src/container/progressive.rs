//! Progressive (single-file, non-fragmented) MP4 packager

use alloc::vec;
use alloc::vec::Vec;

use bitforge::{Package, Parse, Serialize};

use crate::error::{Error, Result};
use crate::init_segment::{
    ChunkLargeOffsetBox, ChunkOffsetBox, MovieBox, SampleSizeBox, SampleToChunkBox, StblChild,
    StscEntry, SyncSampleBox,
};
use crate::media::{Media, Track};
use crate::pipeline::{CodecConfig, Sample, build_init_segment};
use crate::segments::FileTypeBox;
use crate::timing::{CompositionOffsetBox, CttsEntry, EditListBox, SttsEntry, TimeToSampleBox};

const DEFAULT_MOVIE_TIMESCALE: u32 = 1000;
const FTYP_MAJOR_BRAND: [u8; 4] = *b"isom";
const FTYP_MINOR_VERSION: u32 = 512;
const MDAT_HEADER_LEN: usize = 8;
const MDAT_LARGESIZE_HEADER_LEN: usize = 16;
const SAMPLE_DESCRIPTION_INDEX: u32 = 1;

#[derive(Debug, Clone, Default)]
pub struct ProgressiveMux {
    pub faststart: bool,
}

impl ProgressiveMux {
    pub fn new(faststart: bool) -> Self {
        Self { faststart }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct SampleMeta {
    pub(crate) duration: Option<u32>,
    pub(crate) composition_offset: i32,
    pub(crate) size: u32,
    pub(crate) is_sync: bool,
}

impl SampleMeta {
    fn from_sample(s: &Sample) -> Self {
        Self {
            duration: s.duration,
            composition_offset: s.composition_offset(),
            size: s.data.len() as u32,
            is_sync: s.flags.is_sync,
        }
    }
}

const SAFE_MAX_TRACK_TICKS: u64 = 1 << 31;

/// `preferred_timescale` (0 = none): an audio track keeps its sample rate as media timescale when that still fits the 32-bit tick budget
pub(crate) fn rescale_track_timing_if_needed(
    timescale: u32,
    preferred_timescale: u32,
    metas: &mut [SampleMeta],
) -> u32 {
    if timescale == 0 || metas.is_empty() {
        return timescale;
    }
    let total_ticks: u64 = metas.iter().map(|m| u64::from(m.duration.unwrap_or(0))).sum();
    if total_ticks <= SAFE_MAX_TRACK_TICKS {
        return timescale;
    }

    let new_timescale = ((SAFE_MAX_TRACK_TICKS * u64::from(timescale)) / total_ticks)
        .clamp(1000, u64::from(timescale)) as u32;
    // ffmpeg's mov demuxer reads an audio edit list's media_time as a sample count, so it is only right when the media timescale equals the sample rate
    let new_timescale = if preferred_timescale >= 1000 && preferred_timescale <= new_timescale {
        preferred_timescale
    } else {
        new_timescale
    };

    let rescale = |ticks: u64| -> u64 {
        ((ticks as u128 * u128::from(new_timescale) + u128::from(timescale) / 2)
            / u128::from(timescale)) as u64
    };
    let rescale_signed = |ticks: i64| -> i64 {
        let sign = ticks.signum();
        sign * rescale(ticks.unsigned_abs()) as i64
    };

    let mut cumulative_orig: u64 = 0;
    let mut cumulative_new: u64 = 0;
    for meta in metas.iter_mut() {
        let dur = u64::from(meta.duration.unwrap_or(0));
        cumulative_orig += dur;
        let next_cumulative_new = rescale(cumulative_orig);
        meta.duration = Some((next_cumulative_new - cumulative_new) as u32);
        cumulative_new = next_cumulative_new;
        meta.composition_offset = rescale_signed(i64::from(meta.composition_offset)) as i32;
    }

    new_timescale
}

pub(crate) fn rescale_track_samples_if_needed(
    timescale: u32,
    preferred_timescale: u32,
    samples: &mut [Sample],
) -> u32 {
    if samples.is_empty() {
        return timescale;
    }
    let mut metas: Vec<SampleMeta> = samples.iter().map(SampleMeta::from_sample).collect();
    let new_timescale = rescale_track_timing_if_needed(timescale, preferred_timescale, &mut metas);
    if new_timescale == timescale {
        return timescale;
    }
    let mut cumulative_dts: i64 = 0;
    for (s, m) in samples.iter_mut().zip(metas.iter()) {
        let dur = m.duration.unwrap_or(0);
        s.duration = Some(dur);
        s.dts = Some(cumulative_dts);
        s.pts = Some(cumulative_dts + i64::from(m.composition_offset));
        cumulative_dts += i64::from(dur);
    }
    new_timescale
}

/// Re-express an edit list's `media_time` values after the track's media timescale changed from `old_timescale` to `new_timescale`
pub(crate) fn rescale_edit_list_media_time(
    edit_list: &mut Option<EditListBox>,
    old_timescale: u32,
    new_timescale: u32,
) {
    if old_timescale == 0 || old_timescale == new_timescale {
        return;
    }
    let Some(elst) = edit_list.as_mut() else {
        return;
    };
    for entry in &mut elst.entries {
        // A negative media_time (-1) marks an empty edit (a pure delay): it carries no media position to rescale.
        if entry.media_time < 0 {
            continue;
        }
        entry.media_time = ((entry.media_time as u128 * u128::from(new_timescale)
            + u128::from(old_timescale) / 2)
            / u128::from(old_timescale)) as i64;
    }
}

fn codec_compatible_brand(config: &CodecConfig) -> Option<[u8; 4]> {
    match config {
        CodecConfig::Avc { .. } => Some(*b"avc1"),
        CodecConfig::Hevc { .. } => Some(*b"hvc1"),
        CodecConfig::Vvc { .. } => Some(*b"vvc1"),
        CodecConfig::Av1 { .. } => Some(*b"av01"),
        CodecConfig::Vp9 { .. } => Some(*b"vp09"),
        _ => None,
    }
}

fn build_stts(samples: &[SampleMeta]) -> TimeToSampleBox {
    let mut entries: Vec<SttsEntry> = Vec::new();
    for s in samples {
        let delta = s.duration.unwrap_or(0);
        match entries.last_mut() {
            Some(last) if last.sample_delta == delta => last.sample_count += 1,
            _ => entries.push(SttsEntry {
                sample_count: 1,
                sample_delta: delta,
            }),
        }
    }
    TimeToSampleBox {
        version: 0,
        flags: 0,
        entries,
    }
}

fn build_ctts(samples: &[SampleMeta]) -> Option<CompositionOffsetBox> {
    if samples.iter().all(|s| s.composition_offset == 0) {
        return None;
    }
    let mut entries: Vec<CttsEntry> = Vec::new();
    for s in samples {
        match entries.last_mut() {
            Some(last) if last.sample_offset == s.composition_offset => last.sample_count += 1,
            _ => entries.push(CttsEntry {
                sample_count: 1,
                sample_offset: s.composition_offset,
            }),
        }
    }
    Some(CompositionOffsetBox {
        version: 1,
        flags: 0,
        entries,
    })
}

fn build_stss(samples: &[SampleMeta]) -> Option<SyncSampleBox> {
    if samples.iter().all(|s| s.is_sync) {
        return None;
    }
    let entries: Vec<u32> = samples
        .iter()
        .enumerate()
        .filter_map(|(i, s)| if s.is_sync { Some(i as u32 + 1) } else { None })
        .collect();
    Some(SyncSampleBox {
        version: 0,
        flags: 0,
        entries,
    })
}

fn build_stbl_children(
    stsd: StblChild,
    samples: &[SampleMeta],
    chunk_offset: u64,
    use_co64: bool,
) -> Vec<StblChild> {
    let stsz = SampleSizeBox {
        version: 0,
        flags: 0,
        sample_size: 0,
        entries: samples.iter().map(|s| s.size).collect(),
    };
    let stsc = SampleToChunkBox {
        version: 0,
        flags: 0,
        entries: vec![StscEntry {
            first_chunk: 1,
            samples_per_chunk: samples.len() as u32,
            sample_description_index: SAMPLE_DESCRIPTION_INDEX,
        }],
    };

    let mut children = vec![
        stsd,
        StblChild::Stts(build_stts(samples)),
        StblChild::Stsc(stsc),
        StblChild::Stsz(stsz),
    ];
    if let Some(ctts) = build_ctts(samples) {
        children.insert(2, StblChild::Ctts(ctts));
    }
    if use_co64 {
        children.push(StblChild::Co64(ChunkLargeOffsetBox {
            version: 0,
            flags: 0,
            entries: vec![chunk_offset],
        }));
    } else {
        children.push(StblChild::Stco(ChunkOffsetBox {
            version: 0,
            flags: 0,
            entries: vec![chunk_offset as u32],
        }));
    }
    if let Some(stss) = build_stss(samples) {
        children.push(StblChild::Stss(stss));
    }
    children
}

fn set_track_stbl(
    moov: &mut MovieBox,
    track_index: usize,
    new_children: Vec<StblChild>,
) -> Result<()> {
    let trak = moov
        .tracks
        .get_mut(track_index)
        .ok_or(Error::UnexpectedBox { expected: "trak" })?;
    let stbl = trak
        .mdia
        .as_mut()
        .and_then(|m| m.minf.as_mut())
        .and_then(|m| m.stbl.as_mut())
        .ok_or(Error::UnexpectedBox { expected: "stbl" })?;
    stbl.children = new_children;
    Ok(())
}

fn take_stsd(moov: &MovieBox, track_index: usize) -> Result<StblChild> {
    let trak = moov
        .tracks
        .get(track_index)
        .ok_or(Error::UnexpectedBox { expected: "trak" })?;
    let stbl = trak
        .mdia
        .as_ref()
        .and_then(|m| m.minf.as_ref())
        .and_then(|m| m.stbl.as_ref())
        .ok_or(Error::UnexpectedBox { expected: "stbl" })?;
    stbl.children
        .iter()
        .find(|c| matches!(c, StblChild::Stsd(_)))
        .cloned()
        .ok_or(Error::UnexpectedBox { expected: "stsd" })
}

impl Package for ProgressiveMux {
    type Media = Media;
    type Output = Vec<u8>;
    type Error = Error;

    fn package(&mut self, media: &Media) -> Result<Vec<u8>> {
        if media.tracks.is_empty() {
            return Err(Error::InvalidInput("cannot package a Media with no tracks"));
        }
        let movie_timescale = if media.movie_timescale == 0 {
            DEFAULT_MOVIE_TIMESCALE
        } else {
            media.movie_timescale
        };
        let track_samples_meta: Vec<Vec<SampleMeta>> = media
            .tracks
            .iter()
            .map(|t| t.samples.iter().map(SampleMeta::from_sample).collect())
            .collect();

        let layout = self.build_layout(&media.tracks, movie_timescale, &track_samples_meta)?;

        let mut mdat_payload: Vec<u8> =
            Vec::with_capacity(layout.mdat_payload_len.min(usize::MAX as u64) as usize);
        for track in &media.tracks {
            for s in &track.samples {
                mdat_payload.extend_from_slice(&s.data);
            }
        }
        debug_assert_eq!(mdat_payload.len() as u64, layout.mdat_payload_len);

        let mut out = Vec::with_capacity(
            layout.ftyp.len() + layout.moov.len() + layout.mdat_header.len() + mdat_payload.len(),
        );
        out.extend_from_slice(&layout.ftyp);
        if self.faststart {
            out.extend_from_slice(&layout.moov);
            out.extend_from_slice(&layout.mdat_header);
            out.extend_from_slice(&mdat_payload);
        } else {
            out.extend_from_slice(&layout.mdat_header);
            out.extend_from_slice(&mdat_payload);
            out.extend_from_slice(&layout.moov);
        }
        Ok(out)
    }
}

struct ProgressiveLayout {
    ftyp: Vec<u8>,
    moov: Vec<u8>,
    mdat_header: Vec<u8>,
    mdat_payload_len: u64,
}

impl ProgressiveMux {
    fn build_layout(
        &self,
        tracks: &[Track],
        movie_timescale: u32,
        track_samples_meta: &[Vec<SampleMeta>],
    ) -> Result<ProgressiveLayout> {
        let specs: Vec<_> = tracks.iter().map(|t| t.spec.clone()).collect();
        let init = build_init_segment(&specs, movie_timescale)?;
        let moov_bytes =
            find_top_box(&init, b"moov").ok_or(Error::UnexpectedBox { expected: "moov" })?;
        let mut moov = MovieBox::parse(moov_bytes)?;
        moov.mvex = None;
        set_track_durations(&mut moov, tracks, track_samples_meta, movie_timescale);

        let mut rel_chunk_offsets: Vec<u64> = Vec::with_capacity(tracks.len());
        let mut mdat_payload_len = 0u64;
        for meta in track_samples_meta {
            rel_chunk_offsets.push(mdat_payload_len);
            mdat_payload_len += meta.iter().map(|s| s.size as u64).sum::<u64>();
        }
        let needs_largesize = MDAT_HEADER_LEN as u64 + mdat_payload_len > u32::MAX as u64;
        let mdat_header_len = if needs_largesize {
            MDAT_LARGESIZE_HEADER_LEN
        } else {
            MDAT_HEADER_LEN
        };

        let mut compatible_brands = vec![*b"isom", *b"iso2", *b"mp41"];
        if let Some(codec_brand) = tracks.iter().find_map(|t| codec_compatible_brand(&t.spec.config))
        {
            compatible_brands.push(codec_brand);
        }
        let ftyp = FileTypeBox {
            major_brand: FTYP_MAJOR_BRAND,
            minor_version: FTYP_MINOR_VERSION,
            compatible_brands,
        };
        let ftyp_len = ftyp.serialized_len();

        let stsds: Vec<StblChild> = (0..tracks.len())
            .map(|i| take_stsd(&moov, i))
            .collect::<Result<_>>()?;

        let mut use_co64 = false;
        let (moov_out, mdat_payload_offset) = loop {
            let provisional = self.assemble_moov(
                &mut moov.clone(),
                &stsds,
                track_samples_meta,
                &rel_chunk_offsets,
                0,
                use_co64,
            )?;
            let moov_size = provisional.len();

            let mdat_payload_offset = if self.faststart {
                (ftyp_len + moov_size + mdat_header_len) as u64
            } else {
                (ftyp_len + mdat_header_len) as u64
            };

            let needs_co64 = rel_chunk_offsets
                .iter()
                .any(|&rel| mdat_payload_offset + rel > u32::MAX as u64);
            if needs_co64 && !use_co64 {
                use_co64 = true;
                continue;
            }

            let moov_out = self.assemble_moov(
                &mut moov.clone(),
                &stsds,
                track_samples_meta,
                &rel_chunk_offsets,
                mdat_payload_offset,
                use_co64,
            )?;
            debug_assert_eq!(moov_out.len(), moov_size, "moov size must be offset-stable");
            break (moov_out, mdat_payload_offset);
        };

        let actual_payload_offset = if self.faststart {
            (ftyp_len + moov_out.len() + mdat_header_len) as u64
        } else {
            (ftyp_len + mdat_header_len) as u64
        };
        debug_assert_eq!(actual_payload_offset, mdat_payload_offset);

        let mut ftyp_buf = vec![0u8; ftyp_len];
        let n = ftyp.serialize_into(&mut ftyp_buf)?;
        ftyp_buf.truncate(n);

        let mut mdat_header = vec![0u8; mdat_header_len];
        if needs_largesize {
            mdat_header[0..4].copy_from_slice(&1u32.to_be_bytes());
            mdat_header[4..8].copy_from_slice(b"mdat");
            mdat_header[8..16]
                .copy_from_slice(&(mdat_header_len as u64 + mdat_payload_len).to_be_bytes());
        } else {
            mdat_header[0..4].copy_from_slice(
                &((mdat_header_len as u64 + mdat_payload_len) as u32).to_be_bytes(),
            );
            mdat_header[4..8].copy_from_slice(b"mdat");
        }

        Ok(ProgressiveLayout {
            ftyp: ftyp_buf,
            moov: moov_out,
            mdat_header,
            mdat_payload_len,
        })
    }

    #[cfg(feature = "cli")]
    pub(crate) fn open_streaming(
        &self,
        tracks: &[Track],
        movie_timescale: u32,
        track_samples_meta: &[Vec<SampleMeta>],
    ) -> Result<Vec<u8>> {
        if !self.faststart {
            return Err(Error::InvalidInput(
                "ProgressiveMux::open_streaming requires faststart = true \
                 (moov-after-mdat streaming is not implemented)",
            ));
        }
        if tracks.is_empty() {
            return Err(Error::InvalidInput("cannot package a Media with no tracks"));
        }
        let layout = self.build_layout(tracks, movie_timescale, track_samples_meta)?;
        let mut header =
            Vec::with_capacity(layout.ftyp.len() + layout.moov.len() + layout.mdat_header.len());
        header.extend_from_slice(&layout.ftyp);
        header.extend_from_slice(&layout.moov);
        header.extend_from_slice(&layout.mdat_header);
        Ok(header)
    }

    #[cfg(feature = "cli")]
    pub(crate) fn open_streaming_interleaved(
        &self,
        tracks: &[Track],
        movie_timescale: u32,
        track_samples_meta: &[Vec<SampleMeta>],
        track_chunks: &[Vec<(u64, u32)>],
    ) -> Result<Vec<u8>> {
        if !self.faststart {
            return Err(Error::InvalidInput(
                "ProgressiveMux::open_streaming_interleaved requires faststart = true \
                 (moov-after-mdat streaming is not implemented)",
            ));
        }
        if tracks.is_empty() {
            return Err(Error::InvalidInput("cannot package a Media with no tracks"));
        }

        let specs: Vec<_> = tracks.iter().map(|t| t.spec.clone()).collect();
        let init = build_init_segment(&specs, movie_timescale)?;
        let moov_bytes =
            find_top_box(&init, b"moov").ok_or(Error::UnexpectedBox { expected: "moov" })?;
        let mut moov = MovieBox::parse(moov_bytes)?;
        moov.mvex = None;
        set_track_durations(&mut moov, tracks, track_samples_meta, movie_timescale);

        let mdat_payload_len: u64 = track_samples_meta
            .iter()
            .flat_map(|m| m.iter())
            .map(|s| s.size as u64)
            .sum();
        let needs_largesize = MDAT_HEADER_LEN as u64 + mdat_payload_len > u32::MAX as u64;
        let mdat_header_len = if needs_largesize {
            MDAT_LARGESIZE_HEADER_LEN
        } else {
            MDAT_HEADER_LEN
        };

        let mut compatible_brands = vec![*b"isom", *b"iso2", *b"mp41"];
        if let Some(codec_brand) =
            tracks.iter().find_map(|t| codec_compatible_brand(&t.spec.config))
        {
            compatible_brands.push(codec_brand);
        }
        let ftyp = FileTypeBox {
            major_brand: FTYP_MAJOR_BRAND,
            minor_version: FTYP_MINOR_VERSION,
            compatible_brands,
        };
        let ftyp_len = ftyp.serialized_len();

        let stsds: Vec<StblChild> = (0..tracks.len())
            .map(|i| take_stsd(&moov, i))
            .collect::<Result<_>>()?;

        let mut use_co64 = false;
        let moov_out = loop {
            let provisional = Self::assemble_moov_interleaved(
                &mut moov.clone(),
                &stsds,
                track_samples_meta,
                track_chunks,
                0,
                use_co64,
            )?;
            let moov_size = provisional.len();

            let mdat_payload_offset = (ftyp_len + moov_size + mdat_header_len) as u64;

            let needs_co64 = track_chunks
                .iter()
                .flat_map(|c| c.iter())
                .any(|&(rel, _)| mdat_payload_offset + rel > u32::MAX as u64);
            if needs_co64 && !use_co64 {
                use_co64 = true;
                continue;
            }

            let moov_out = Self::assemble_moov_interleaved(
                &mut moov.clone(),
                &stsds,
                track_samples_meta,
                track_chunks,
                mdat_payload_offset,
                use_co64,
            )?;
            debug_assert_eq!(moov_out.len(), moov_size, "moov size must be offset-stable");
            break moov_out;
        };

        let mut ftyp_buf = vec![0u8; ftyp_len];
        let n = ftyp.serialize_into(&mut ftyp_buf)?;
        ftyp_buf.truncate(n);

        let mut mdat_header = vec![0u8; mdat_header_len];
        if needs_largesize {
            mdat_header[0..4].copy_from_slice(&1u32.to_be_bytes());
            mdat_header[4..8].copy_from_slice(b"mdat");
            mdat_header[8..16]
                .copy_from_slice(&(mdat_header_len as u64 + mdat_payload_len).to_be_bytes());
        } else {
            mdat_header[0..4].copy_from_slice(
                &((mdat_header_len as u64 + mdat_payload_len) as u32).to_be_bytes(),
            );
            mdat_header[4..8].copy_from_slice(b"mdat");
        }

        let mut header = Vec::with_capacity(ftyp_buf.len() + moov_out.len() + mdat_header.len());
        header.extend_from_slice(&ftyp_buf);
        header.extend_from_slice(&moov_out);
        header.extend_from_slice(&mdat_header);
        Ok(header)
    }

    #[cfg(feature = "cli")]
    fn assemble_moov_interleaved(
        moov: &mut MovieBox,
        stsds: &[StblChild],
        track_samples_meta: &[Vec<SampleMeta>],
        track_chunks: &[Vec<(u64, u32)>],
        mdat_payload_offset: u64,
        use_co64: bool,
    ) -> Result<Vec<u8>> {
        for (i, meta) in track_samples_meta.iter().enumerate() {
            let abs_chunks: Vec<(u64, u32)> = track_chunks[i]
                .iter()
                .map(|&(rel, count)| (mdat_payload_offset + rel, count))
                .collect();
            let children = build_stbl_children_multi(stsds[i].clone(), meta, &abs_chunks, use_co64);
            set_track_stbl(moov, i, children)?;
        }
        let mut buf = vec![0u8; moov.serialized_len()];
        let n = moov.serialize_into(&mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }
}

#[cfg(feature = "cli")]
fn build_stbl_children_multi(
    stsd: StblChild,
    samples: &[SampleMeta],
    chunks: &[(u64, u32)],
    use_co64: bool,
) -> Vec<StblChild> {
    let stsz = SampleSizeBox {
        version: 0,
        flags: 0,
        sample_size: 0,
        entries: samples.iter().map(|s| s.size).collect(),
    };

    let mut stsc_entries: Vec<StscEntry> = Vec::new();
    let mut last_count: Option<u32> = None;
    for (idx, &(_, count)) in chunks.iter().enumerate() {
        if last_count != Some(count) {
            stsc_entries.push(StscEntry {
                first_chunk: idx as u32 + 1,
                samples_per_chunk: count,
                sample_description_index: SAMPLE_DESCRIPTION_INDEX,
            });
            last_count = Some(count);
        }
    }
    if stsc_entries.is_empty() {
        stsc_entries.push(StscEntry {
            first_chunk: 1,
            samples_per_chunk: 0,
            sample_description_index: SAMPLE_DESCRIPTION_INDEX,
        });
    }

    let mut children = vec![
        stsd,
        StblChild::Stts(build_stts(samples)),
        StblChild::Stsc(SampleToChunkBox {
            version: 0,
            flags: 0,
            entries: stsc_entries,
        }),
        StblChild::Stsz(stsz),
    ];
    if let Some(ctts) = build_ctts(samples) {
        children.insert(2, StblChild::Ctts(ctts));
    }
    if use_co64 {
        children.push(StblChild::Co64(ChunkLargeOffsetBox {
            version: 0,
            flags: 0,
            entries: chunks.iter().map(|&(off, _)| off).collect(),
        }));
    } else {
        children.push(StblChild::Stco(ChunkOffsetBox {
            version: 0,
            flags: 0,
            entries: chunks.iter().map(|&(off, _)| off as u32).collect(),
        }));
    }
    if let Some(stss) = build_stss(samples) {
        children.push(StblChild::Stss(stss));
    }
    children
}

impl ProgressiveMux {
    fn assemble_moov(
        &self,
        moov: &mut MovieBox,
        stsds: &[StblChild],
        track_samples_meta: &[Vec<SampleMeta>],
        rel_chunk_offsets: &[u64],
        mdat_payload_offset: u64,
        use_co64: bool,
    ) -> Result<Vec<u8>> {
        for (i, meta) in track_samples_meta.iter().enumerate() {
            let abs_offset = mdat_payload_offset + rel_chunk_offsets[i];
            let children = build_stbl_children(stsds[i].clone(), meta, abs_offset, use_co64);
            set_track_stbl(moov, i, children)?;
        }
        let mut buf = vec![0u8; moov.serialized_len()];
        let n = moov.serialize_into(&mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }
}

fn set_track_durations(
    moov: &mut MovieBox,
    tracks: &[Track],
    track_samples_meta: &[Vec<SampleMeta>],
    movie_timescale: u32,
) {
    let mut max_movie_duration = 0u64;
    for (i, track) in tracks.iter().enumerate() {
        let media_duration: u64 = track_samples_meta[i]
            .iter()
            .map(|s| s.duration.unwrap_or(0) as u64)
            .sum();
        let ts = if track.timescale() == 0 {
            1
        } else {
            track.timescale()
        } as u64;
        let movie_duration = media_duration * movie_timescale as u64 / ts;
        if movie_duration > max_movie_duration {
            max_movie_duration = movie_duration;
        }
        if let Some(trak) = moov.tracks.get_mut(i) {
            trak.tkhd.duration = movie_duration;
            if movie_duration > u32::MAX as u64 {
                trak.tkhd.version = 1;
            }
            if let Some(mdhd) = trak.mdia.as_mut().and_then(|m| m.mdhd.as_mut()) {
                mdhd.duration = media_duration;
                if media_duration > u32::MAX as u64 {
                    mdhd.version = 1;
                }
            }
            if let Some(elst) = trak.edts.as_mut().and_then(|e| e.elst.as_mut()) {
                for entry in &mut elst.entries {
                    let playable = media_duration.saturating_sub(entry.media_time.max(0) as u64);
                    let full = (playable * movie_timescale as u64).div_ceil(ts);
                    
                    // Some packagers write segment_duration in milliseconds against a different movie timescale (e.g. 10 MHz), so the
                    // edit covers only a sliver of the track and players trim the stream to ~0s: restore the full length.
                    let in_ms = playable * 1000 / ts;
                    let bogus = movie_timescale != 1000
                        && entry.media_time >= 0
                        && entry.segment_duration != 0
                        && entry.segment_duration.abs_diff(in_ms) <= in_ms / 100 + 1;
                    if entry.segment_duration != 0 && !bogus {
                        continue;
                    }
                    let numerator = media_duration * movie_timescale as u64;
                    entry.segment_duration = if bogus { full } else { numerator.div_ceil(ts) };
                    if entry.segment_duration > u32::MAX as u64 {
                        elst.version = 1;
                    }
                }
            }
        }
    }
    moov.mvhd.duration = max_movie_duration;
    if max_movie_duration > u32::MAX as u64 {
        moov.mvhd.version = 1;
    }
}

fn find_top_box<'a>(data: &'a [u8], fourcc: &[u8; 4]) -> Option<&'a [u8]> {
    let mut offset = 0usize;
    while offset + 8 <= data.len() {
        let (bx, consumed) = crate::box_types::parse_box(&data[offset..]).ok()?;
        if bx.header.box_type.is(fourcc) {
            let end = if bx.header.size == 0 {
                data.len()
            } else {
                offset + bx.header.size as usize
            };
            return Some(&data[offset..end]);
        }
        if consumed == 0 {
            break;
        }
        offset += consumed;
    }
    None
}

#[cfg(test)]
mod edit_list_rescale_tests {
    use super::*;
    use crate::timing::EditListEntry;

    fn elst(entries: &[(u64, i64)]) -> Option<EditListBox> {
        Some(EditListBox {
            version: 0,
            flags: 0,
            entries: entries
                .iter()
                .map(|&(segment_duration, media_time)| EditListEntry {
                    segment_duration,
                    media_time,
                    media_rate_integer: 1,
                    media_rate_fraction: 0,
                })
                .collect(),
        })
    }

    fn media_times(e: &Option<EditListBox>) -> Vec<i64> {
        e.as_ref().unwrap().entries.iter().map(|x| x.media_time).collect()
    }

    #[test]
    fn media_time_follows_a_timescale_change() {
        // Real-world case: 10 MHz track rescaled to 414156 / 414170 (Rakuten audio/video).
        let mut audio = elst(&[(5_185_152, 426_667)]);
        rescale_edit_list_media_time(&mut audio, 10_000_000, 414_156);
        assert_eq!(media_times(&audio), vec![17_671]);

        let mut video = elst(&[(5_185_770, 834_168)]);
        rescale_edit_list_media_time(&mut video, 10_000_000, 414_170);
        assert_eq!(media_times(&video), vec![34_549]);
    }

    #[test]
    fn segment_duration_and_rate_are_untouched() {
        let mut e = elst(&[(1234, 1_000_000)]);
        rescale_edit_list_media_time(&mut e, 10_000_000, 1_000_000);
        let entry = e.unwrap().entries[0];
        assert_eq!(entry.media_time, 100_000);
        assert_eq!(entry.segment_duration, 1234);
        assert_eq!((entry.media_rate_integer, entry.media_rate_fraction), (1, 0));
    }

    #[test]
    fn empty_edit_marker_is_preserved() {
        let mut e = elst(&[(500, -1), (900, 2_000_000)]);
        rescale_edit_list_media_time(&mut e, 10_000_000, 1_000_000);
        assert_eq!(media_times(&e), vec![-1, 200_000]);
    }

    #[test]
    fn zero_media_time_stays_zero() {
        let mut e = elst(&[(900, 0)]);
        rescale_edit_list_media_time(&mut e, 10_000_000, 414_156);
        assert_eq!(media_times(&e), vec![0]);
    }

    #[test]
    fn unchanged_or_invalid_timescale_is_a_noop() {
        let mut same = elst(&[(900, 12_345)]);
        rescale_edit_list_media_time(&mut same, 48_000, 48_000);
        assert_eq!(media_times(&same), vec![12_345]);

        let mut zero_old = elst(&[(900, 12_345)]);
        rescale_edit_list_media_time(&mut zero_old, 0, 48_000);
        assert_eq!(media_times(&zero_old), vec![12_345]);
    }

    #[test]
    fn missing_edit_list_is_a_noop() {
        let mut none: Option<EditListBox> = None;
        rescale_edit_list_media_time(&mut none, 10_000_000, 414_156);
        assert!(none.is_none());
    }

    #[test]
    fn rounds_to_nearest_tick() {
        // 3 * 1/3 = 1 ; 2 * 1/3 = 0.67 -> 1 ; 1 * 1/3 = 0.33 -> 0
        let mut e = elst(&[(1, 3), (1, 2), (1, 1)]);
        rescale_edit_list_media_time(&mut e, 3, 1);
        assert_eq!(media_times(&e), vec![1, 1, 0]);
    }
    fn metas(count: usize, duration: u32) -> Vec<SampleMeta> {
        (0..count)
            .map(|_| SampleMeta { duration: Some(duration), composition_offset: 0, size: 1, is_sync: true })
            .collect()
    }

    // 243_056 AAC frames of 1024 ticks at 10 MHz units (scaled): total ticks > 2^31 -> rescale needed.
    fn long_audio_metas() -> Vec<SampleMeta> {
        metas(243_056, 213_333)
    }

    #[test]
    fn timescale_untouched_when_ticks_fit() {
        let mut m = metas(100, 1024);
        assert_eq!(rescale_track_timing_if_needed(48_000, 48_000, &mut m), 48_000);
        assert_eq!(m[0].duration, Some(1024));
    }

    #[test]
    fn audio_prefers_its_sample_rate_when_it_fits() {
        let mut m = long_audio_metas();
        let total: u64 = m.iter().map(|x| u64::from(x.duration.unwrap())).sum();
        assert!(total > (1u64 << 31));
        let new_ts = rescale_track_timing_if_needed(10_000_000, 48_000, &mut m);
        assert_eq!(new_ts, 48_000);
        let rescaled: u64 = m.iter().map(|x| u64::from(x.duration.unwrap())).sum();
        assert!(rescaled <= (1u64 << 31));
        // 5_185.152 s of audio at 48 kHz
        assert!((rescaled as i64 - 248_887_296).abs() < 48_000);
    }

    #[test]
    fn without_a_preferred_timescale_the_legacy_choice_is_kept() {
        let mut m = long_audio_metas();
        let new_ts = rescale_track_timing_if_needed(10_000_000, 0, &mut m);
        assert_ne!(new_ts, 48_000);
        assert!(new_ts < 10_000_000 && new_ts >= 1000);
    }

    #[test]
    fn preferred_timescale_too_large_for_the_budget_is_ignored() {
        let mut m = long_audio_metas();
        let new_ts = rescale_track_timing_if_needed(10_000_000, 9_000_000, &mut m);
        assert!(new_ts < 9_000_000);
    }

    #[test]
    fn sample_rate_audio_edit_list_ends_up_as_the_aac_priming() {
        // Rakuten audio: 10 MHz -> 48 kHz turns media_time 426667 into the 2048-sample AAC priming.
        let mut e = elst(&[(5_185_152, 426_667)]);
        rescale_edit_list_media_time(&mut e, 10_000_000, 48_000);
        assert_eq!(media_times(&e), vec![2048]);
    }
    #[test]
    fn version_1_edit_list_survives_rescale_and_roundtrips() {
        use bitforge::{Parse, Serialize};
        let mut e = Some(EditListBox {
            version: 1,
            flags: 0,
            entries: vec![EditListEntry {
                segment_duration: 6_000_000_000,
                media_time: 5_000_000_000,
                media_rate_integer: 1,
                media_rate_fraction: 0,
            }],
        });
        rescale_edit_list_media_time(&mut e, 10_000_000, 48_000);
        let elst = e.unwrap();
        assert_eq!(elst.entries[0].media_time, 24_000_000);
        assert_eq!(elst.entries[0].segment_duration, 6_000_000_000);
        let mut bytes = vec![0u8; elst.serialized_len()];
        elst.serialize_into(&mut bytes).unwrap();
        let parsed = EditListBox::parse(&bytes).unwrap();
        assert_eq!(parsed.entries, elst.entries);
    }

    #[test]
    fn empty_edit_followed_by_a_real_edit_is_scaled_independently() {
        let mut e = elst(&[(1000, -1), (9000, 426_667), (500, 0)]);
        rescale_edit_list_media_time(&mut e, 10_000_000, 48_000);
        assert_eq!(media_times(&e), vec![-1, 2048, 0]);
    }
}
