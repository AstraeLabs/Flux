//! The any-to-any hub impls over the [`crate::ir`] media IR.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::marker::PhantomData;

use bitforge::{Parse, Unpackage};

use crate::ac3::{Ac3SpecificBox, Ec3SpecificBox};
use crate::ac4::Ac4SpecificBox;
use crate::box_types::{BOX_HEADER_MIN_SIZE, parse_box};
use crate::dts::DtsSpecificBox;
use crate::error::{Error, Result};
use crate::flac::FlacSpecificBox;
use crate::init_segment::{MovieBox, OpaqueBox, SampleEntryVariant, StblChild, TrackBox};
use crate::ir::{CodecConfig, Sample, SubtitleFormat, TrackSpec};
use crate::movie_fragment::MovieFragmentBox;
use crate::mp4esds::EsdsBox;
use crate::mpeg_legacy::{Mpeg2SeqHeader, MpegAudioFrameHeader, MpegAudioLayer};
use crate::mpegh::{MHAC_FOURCC, MHADecoderConfigurationRecord};
use crate::opus::OpusSpecificBox;

pub use crate::ir::{Media, SkippedTrack, Track, TrackEncryption};

const SAMPLE_FLAG_IS_NON_SYNC: u32 = 0x0001_0000;

const OTI_MPEG2_AUDIO: u8 = 0x69;
const OTI_MPEG1_AUDIO: u8 = 0x6B;

#[derive(Debug, Default, Clone)]
pub struct Fmp4Demux<'a> {
    _marker: PhantomData<&'a [u8]>,
}

impl Fmp4Demux<'_> {
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

struct TrackBuilder {
    spec: TrackSpec,
    samples: Vec<Sample>,
    start_decode_time: Option<u64>,
    next_dts: i64,
}

impl<'a> Unpackage for Fmp4Demux<'a> {
    type Input = &'a [u8];
    type Media = Media;
    type Error = Error;

    fn unpackage(&mut self, input: &'a [u8]) -> Result<Media> {
        let moov_bytes =
            find_top_box(input, b"moov").ok_or(Error::UnexpectedBox { expected: "moov" })?;
        let moov = MovieBox::parse(moov_bytes)?;
        let movie_timescale = moov.mvhd.timescale;

        let mut builders: Vec<TrackBuilder> = Vec::with_capacity(moov.tracks.len());
        let mut skipped: Vec<SkippedTrack> = Vec::new();
        for trak in &moov.tracks {
            match track_spec_from_trak(trak) {
                Ok(spec) => builders.push(TrackBuilder {
                    spec,
                    samples: Vec::new(),
                    start_decode_time: None,
                    next_dts: 0,
                }),
                Err(err) => skipped.push(skipped_track(err)),
            }
        }

        let mut offset = 0usize;
        let mut pending_moof: Option<(usize, MovieFragmentBox)> = None;
        while offset + BOX_HEADER_MIN_SIZE <= input.len() {
            let (bx, consumed) = parse_box(&input[offset..])?;
            let ty = bx.header.box_type.0;
            if &ty == b"moof" {
                let moof = MovieFragmentBox::parse_body(bx.body)?;
                pending_moof = Some((offset, moof));
            } else if &ty == b"mdat"
                && let Some((moof_off, moof)) = pending_moof.take()
            {
                absorb_fragment(input, moof_off, &moof, &mut builders, moov.mvex.as_ref())?;
            }
            if consumed == 0 {
                break;
            }
            offset += consumed;
        }

        let tracks = builders
            .into_iter()
            .map(|mut b| {
                refine_legacy_config(&mut b.spec.config, &b.samples);
                Track {
                    spec: b.spec,
                    samples: b.samples,
                    start_decode_time: b.start_decode_time.unwrap_or(0),
                    encryption: None,
                }
            })
            .collect();
        Ok(Media {
            tracks,
            movie_timescale,
            skipped,
        })
    }
}

fn absorb_fragment(
    file: &[u8],
    moof_off: usize,
    moof: &MovieFragmentBox,
    builders: &mut [TrackBuilder],
    mvex: Option<&crate::init_segment::MovieExtendsBox>,
) -> Result<()> {
    for traf in &moof.traf {
        let tfhd = &traf.tfhd;
        let Some(builder) = builders
            .iter_mut()
            .find(|b| b.spec.track_id == tfhd.track_id)
        else {
            continue;
        };
        let trex = mvex.and_then(|m| m.trex.iter().find(|t| t.track_id == tfhd.track_id));
        if let Some(tfdt) = &traf.tfdt {
            let base = tfdt.base_media_decode_time();
            if builder.start_decode_time.is_none() {
                builder.start_decode_time = Some(base);
            }
            builder.next_dts = base as i64;
        }
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
                let size = ts
                    .sample_size
                    .or(tfhd.default_sample_size)
                    .or(trex.map(|t| t.default_sample_size))
                    .ok_or(Error::InvalidInput(
                        "trun sample has no size (no trun.sample_size, no tfhd \
                         default_sample_size, no trex default_sample_size)",
                    ))? as usize;
                let duration = ts
                    .sample_duration
                    .or(tfhd.default_sample_duration)
                    .or(trex.map(|t| t.default_sample_duration))
                    .unwrap_or(0);
                let per_sample = if i == 0 && trun.first_sample_flags.is_some() {
                    trun.first_sample_flags
                } else {
                    ts.sample_flags
                };
                let flags = per_sample
                    .or(tfhd.default_sample_flags)
                    .or(trex.map(|t| t.default_sample_flags))
                    .unwrap_or(0);
                let is_sync = flags & SAMPLE_FLAG_IS_NON_SYNC == 0;
                let composition_offset = ts.sample_composition_time_offset.unwrap_or(0);

                let start = usize::try_from(cursor)
                    .map_err(|_| Error::InvalidInput("negative sample data offset"))?;
                let end = start + size;
                if end > file.len() {
                    return Err(Error::BufferTooShort {
                        need: end,
                        have: file.len(),
                        what: "fragment sample data",
                    });
                }
                let dts = builder.next_dts;
                let pts = dts + composition_offset;
                builder.samples.push(Sample {
                    data: file[start..end].to_vec().into(),
                    dts: Some(dts),
                    pts: Some(pts),
                    duration: Some(duration),
                    flags: crate::ir::SampleFlags::new(is_sync),
                    provenance: None,
                });
                builder.next_dts += duration as i64;
                cursor += size as i64;
                run_end = cursor;
            }
        }
    }
    Ok(())
}

pub(crate) fn find_top_box<'a>(data: &'a [u8], fourcc: &[u8; 4]) -> Option<&'a [u8]> {
    let mut offset = 0usize;
    while offset + BOX_HEADER_MIN_SIZE <= data.len() {
        let (bx, consumed) = parse_box(&data[offset..]).ok()?;
        if &bx.header.box_type.0 == fourcc {
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

pub(crate) fn track_spec_from_trak(trak: &TrackBox) -> Result<TrackSpec> {
    let track_id = trak.tkhd.track_id;
    let mdia = trak
        .mdia
        .as_ref()
        .ok_or(Error::UnexpectedBox { expected: "mdia" })?;
    let timescale = mdia
        .mdhd
        .as_ref()
        .ok_or(Error::UnexpectedBox { expected: "mdhd" })?
        .timescale;
    let minf = mdia
        .minf
        .as_ref()
        .ok_or(Error::UnexpectedBox { expected: "minf" })?;
    let stbl = minf
        .stbl
        .as_ref()
        .ok_or(Error::UnexpectedBox { expected: "stbl" })?;
    let stsd = stbl
        .children
        .iter()
        .find_map(|c| match c {
            StblChild::Stsd(s) => Some(s),
            _ => None,
        })
        .ok_or(Error::UnexpectedBox { expected: "stsd" })?;
    let entry = stsd.entries.first().ok_or(Error::UnexpectedBox {
        expected: "stsd entry",
    })?;

    let config = codec_config_from_entry(entry)?;
    let mut spec = TrackSpec::new(track_id, timescale, config);
    spec.edit_list = trak.edts.as_ref().and_then(|e| e.elst.clone());
    Ok(spec)
}

pub(crate) fn skipped_track(err: Error) -> SkippedTrack {
    let fourcc = match &err {
        Error::UnsupportedSampleEntry { fourcc } => fourcc.clone(),
        _ => String::from("unknown"),
    };
    SkippedTrack {
        fourcc,
        reason: err.to_string(),
    }
}

fn codec_config_from_entry(entry: &SampleEntryVariant) -> Result<CodecConfig> {
    match entry {
        SampleEntryVariant::Avc1(avc) => {
            let (width, height) = if avc.visual.width != 0 && avc.visual.height != 0 {
                (avc.visual.width, avc.visual.height)
            } else {
                avc.config
                    .config
                    .dimensions()
                    .unwrap_or((avc.visual.width, avc.visual.height))
            };
            Ok(CodecConfig::Avc {
                config: avc.config.clone(),
                width,
                height,
            })
        }
        SampleEntryVariant::Hevc1(hevc) => {
            let (width, height) = if hevc.visual.width != 0 && hevc.visual.height != 0 {
                (hevc.visual.width, hevc.visual.height)
            } else {
                hevc.config
                    .config
                    .dimensions()
                    .unwrap_or((hevc.visual.width, hevc.visual.height))
            };
            Ok(CodecConfig::Hevc {
                config: hevc.config.clone(),
                width,
                height,
            })
        }
        SampleEntryVariant::Vvc(vvc) => {
            let (width, height) = vvc
                .config
                .config
                .dimensions()
                .unwrap_or((vvc.visual.width, vvc.visual.height));
            Ok(CodecConfig::Vvc {
                config: vvc.config.clone(),
                width,
                height,
            })
        }
        SampleEntryVariant::Av01(av1) => {
            let (width, height) = if av1.visual.width != 0 && av1.visual.height != 0 {
                (av1.visual.width, av1.visual.height)
            } else {
                av1.config
                    .dimensions()
                    .unwrap_or((av1.visual.width, av1.visual.height))
            };
            Ok(CodecConfig::Av1 {
                config: av1.config.clone(),
                width,
                height,
            })
        }
        SampleEntryVariant::Vp09(vp9) => Ok(CodecConfig::Vp9 {
            config: vp9.config.clone(),
            width: vp9.visual.width,
            height: vp9.visual.height,
        }),
        SampleEntryVariant::Vp08(vp8) => Ok(CodecConfig::Vp8 {
            config: vp8.config.clone(),
            width: vp8.visual.width,
            height: vp8.visual.height,
        }),
        SampleEntryVariant::Mp4v(mp4v) => {
            let esds = EsdsBox::parse_body(config_box_body(&mp4v.config_boxes, b"esds")?)?;
            Ok(CodecConfig::Mpeg2Video {
                esds,
                width: mp4v.visual.width,
                height: mp4v.visual.height,
            })
        }
        SampleEntryVariant::Mp4a(mp4a) => {
            let esds = esds_from_config_boxes(&mp4a.config_boxes)?;
            let oti = esds
                .es_descriptor
                .decoder_config
                .as_ref()
                .map(|dc| dc.object_type_indication.0);
            if oti == Some(OTI_MPEG2_AUDIO) || oti == Some(OTI_MPEG1_AUDIO) {
                Ok(CodecConfig::MpegAudio {
                    esds,
                    layer: MpegAudioLayer::LayerII,
                    channel_count: mp4a.channelcount,
                    sample_rate: mp4a.samplerate >> 16,
                    sample_size: mp4a.samplesize,
                })
            } else {
                Ok(CodecConfig::Aac {
                    esds,
                    channel_count: mp4a.channelcount,
                    sample_rate: mp4a.samplerate >> 16,
                    sample_size: mp4a.samplesize,
                })
            }
        }
        SampleEntryVariant::Ac3(ac3) => {
            let config = Ac3SpecificBox::parse(config_box_body(&ac3.config_boxes, b"dac3")?)?;
            Ok(CodecConfig::Ac3 {
                config,
                channel_count: ac3.channelcount,
                sample_rate: ac3.samplerate >> 16,
                sample_size: ac3.samplesize,
            })
        }
        SampleEntryVariant::Ec3(ec3) => {
            let config = Ec3SpecificBox::parse(config_box_body(&ec3.config_boxes, b"dec3")?)?;
            Ok(CodecConfig::Eac3 {
                config,
                channel_count: ec3.channelcount,
                sample_rate: ec3.samplerate >> 16,
                sample_size: ec3.samplesize,
            })
        }
        SampleEntryVariant::Opus(opus) => {
            let config = OpusSpecificBox::parse(config_box_body(&opus.config_boxes, b"dOps")?)?;
            Ok(CodecConfig::Opus {
                config,
                channel_count: opus.channelcount,
                sample_rate: opus.samplerate >> 16,
                sample_size: opus.samplesize,
            })
        }
        SampleEntryVariant::Flac(flac) => {
            let config = FlacSpecificBox::parse(config_box_body(&flac.config_boxes, b"dfLa")?)?;
            Ok(CodecConfig::Flac {
                config,
                channel_count: flac.channelcount,
                sample_rate: flac.samplerate >> 16,
                sample_size: flac.samplesize,
            })
        }
        SampleEntryVariant::Dts(dts) => {
            let config = DtsSpecificBox::parse(config_box_body(&dts.config_boxes, b"ddts")?)?;
            Ok(CodecConfig::Dts {
                config,
                codec_fourcc: dts.codec_type,
                channel_count: dts.channelcount,
                sample_rate: dts.samplerate >> 16,
                sample_size: dts.samplesize,
            })
        }
        SampleEntryVariant::Mha(mha) => {
            let config = MHADecoderConfigurationRecord::parse(config_box_body(
                &mha.config_boxes,
                &MHAC_FOURCC,
            )?)?;
            Ok(CodecConfig::MpegH {
                config,
                channel_count: mha.channelcount,
                sample_rate: mha.samplerate >> 16,
                sample_size: mha.samplesize,
            })
        }
        SampleEntryVariant::Ac4(ac4) => {
            let config = Ac4SpecificBox::parse(config_box_body(
                &ac4.config_boxes,
                &crate::ac4::DAC4_FOURCC,
            )?)?;
            Ok(CodecConfig::Ac4 {
                config,
                channel_count: ac4.channelcount,
                sample_rate: ac4.samplerate >> 16,
                sample_size: ac4.samplesize,
            })
        }
        SampleEntryVariant::Stpp(_) => Ok(CodecConfig::Subtitle {
            format: SubtitleFormat::Ttml,
        }),
        SampleEntryVariant::Wvtt(_) => Ok(CodecConfig::Subtitle {
            format: SubtitleFormat::WebVtt,
        }),
        SampleEntryVariant::C608(_) => Ok(CodecConfig::Subtitle {
            format: SubtitleFormat::Cea608,
        }),
        SampleEntryVariant::Unknown(entry) => Err(Error::UnsupportedSampleEntry {
            fourcc: String::from_utf8_lossy(&entry.box_type).into_owned(),
        }),
    }
}

pub(crate) fn refine_legacy_config(config: &mut CodecConfig, samples: &[Sample]) {
    let Some(first) = samples.first() else {
        return;
    };
    match config {
        CodecConfig::Mpeg2Video { width, height, .. } => {
            if let Ok(sh) = Mpeg2SeqHeader::find(&first.data) {
                *width = sh.width;
                *height = sh.height;
            }
        }
        CodecConfig::MpegAudio { layer, .. } => {
            if let Ok(hdr) = MpegAudioFrameHeader::parse(&first.data) {
                *layer = hdr.layer;
            }
        }
        _ => {}
    }
}

fn esds_from_config_boxes(boxes: &[OpaqueBox]) -> Result<EsdsBox> {
    EsdsBox::parse_body(config_box_body(boxes, b"esds")?)
}

pub(crate) fn config_box_body<'b>(boxes: &'b [OpaqueBox], fourcc: &[u8; 4]) -> Result<&'b [u8]> {
    boxes
        .iter()
        .find(|b| &b.box_type == fourcc)
        .map(|b| b.data.as_slice())
        .ok_or(Error::UnexpectedBox {
            expected: "config box in audio sample entry",
        })
}