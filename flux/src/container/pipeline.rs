//! TS → CMAF/fMP4 remux pipeline — the muxer above the box builders.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use bitforge::Serialize;

use crate::ac4::DAC4_FOURCC;
use crate::av1::Av1SampleEntry;
use crate::dts::DDTS_FOURCC;
use crate::error::Result;
use crate::flac::DFLA_FOURCC;
use crate::init_segment::{
    Ac3SampleEntry, Ac4SampleEntry, ChunkOffsetBox, DataEntryUrlBox, DataInformationBox,
    DataReferenceBox, DtsSampleEntry, Ec3SampleEntry, FlacSampleEntry, HandlerBox, MediaBox,
    MediaHeaderBox, MediaInformationBox, MhaSampleEntry, MovieBox, MovieExtendsBox, MovieHeaderBox,
    Mp4aSampleEntry, OpaqueBox, OpusSampleEntry, SampleDescriptionBox, SampleEntryVariant,
    SampleSizeBox, SampleTableBox, SampleToChunkBox, SoundMediaHeaderBox, StblChild, TrackBox,
    TrackExtendsBox, TrackHeaderBox, VideoMediaHeaderBox,
};
use crate::mpegh::MHAC_FOURCC;
use crate::opus::DOPS_FOURCC;
use crate::sample_entries::{
    AVCSampleEntry, HEVCSampleEntry, Mp4vSampleEntry, VVCSampleEntry, VisualSampleEntryFields,
};
use crate::segments::FileTypeBox;

use crate::timing::TimeToSampleBox;
use crate::vp9::Vp9SampleEntry;

const LANG_UND: u16 = 0x55C4;
const IDENTITY_MATRIX: [i32; 9] = [0x0001_0000, 0, 0, 0, 0x0001_0000, 0, 0, 0, 0x4000_0000];
const TKHD_ENABLED_IN_MOVIE: u32 = 0x0000_0007;

pub use crate::ir::{CodecConfig, Provenance, Sample, SampleFlags, SubtitleFormat, TrackSpec};

pub fn build_init_segment(tracks: &[TrackSpec], movie_timescale: u32) -> Result<Vec<u8>> {
    let ftyp = FileTypeBox {
        major_brand: *b"iso5",
        minor_version: 512,
        compatible_brands: vec![*b"iso5", *b"iso6", *b"mp41"],
    };

    let next_track_id = tracks.iter().map(|t| t.track_id).max().unwrap_or(0) + 1;
    let mvhd = MovieHeaderBox {
        version: 0,
        flags: 0,
        creation_time: 0,
        modification_time: 0,
        timescale: movie_timescale,
        duration: 0,
        rate: 0x0001_0000,
        volume: 0x0100,
        matrix: IDENTITY_MATRIX,
        next_track_id,
    };

    let mut trak_boxes = Vec::with_capacity(tracks.len());
    let mut trex = Vec::with_capacity(tracks.len());
    for t in tracks {
        if !t.config.is_muxable_in_bmff() {
            return Err(unmuxable_track_error(t));
        }
        trak_boxes.push(build_trak(t)?);
        trex.push(TrackExtendsBox {
            version: 0,
            flags: 0,
            track_id: t.track_id,
            default_sample_description_index: 1,
            default_sample_duration: 0,
            default_sample_size: 0,
            default_sample_flags: 0,
        });
    }

    let moov = MovieBox {
        mvhd,
        tracks: trak_boxes,
        mvex: Some(MovieExtendsBox {
            trex,
            opaque: vec![],
        }),
        opaque: vec![],
    };

    let mut out = vec![0u8; ftyp.serialized_len() + moov.serialized_len()];
    let n1 = ftyp.serialize_into(&mut out)?;
    let n2 = moov.serialize_into(&mut out[n1..])?;
    out.truncate(n1 + n2);
    Ok(out)
}

fn unmuxable_track_error(t: &TrackSpec) -> crate::error::Error {
    match &t.config {
        CodecConfig::Subtitle { format } => crate::error::Error::UnmuxableSubtitleTrack {
            track_id: t.track_id,
            format: *format,
        },
        _ => unreachable!("is_muxable_in_bmff() is only false for Subtitle"),
    }
}

fn config_box<C: Serialize<Error = crate::error::Error>>(
    fourcc: &[u8; 4],
    config: &C,
) -> Result<OpaqueBox> {
    let mut body = vec![0u8; config.serialized_len()];
    let n = config.serialize_into(&mut body)?;
    body.truncate(n);
    Ok(OpaqueBox::new(*fourcc, body))
}

fn build_trak(t: &TrackSpec) -> Result<TrackBox> {
    let audio = t.config.is_audio();

    let (stsd_entry, vmhd, smhd, handler_type, handler_name, tkhd_w, tkhd_h) = match &t.config {
        CodecConfig::Avc {
            config,
            width,
            height,
        } => {
            let visual = VisualSampleEntryFields {
                data_reference_index: 1,
                width: *width,
                height: *height,
                ..VisualSampleEntryFields::default()
            };
            let entry = SampleEntryVariant::Avc1(AVCSampleEntry {
                codec_type: *b"avc1",
                visual,
                config: config.clone(),
                extra_boxes: vec![],
            });
            (
                entry,
                Some(VideoMediaHeaderBox {
                    version: 0,
                    flags: 1,
                    graphicsmode: 0,
                    opcolor: [0, 0, 0],
                }),
                None,
                *b"vide",
                b"VideoHandler\0".to_vec(),
                (*width as u32) << 16,
                (*height as u32) << 16,
            )
        }
        CodecConfig::Hevc {
            config,
            width,
            height,
        } => {
            let visual = VisualSampleEntryFields {
                data_reference_index: 1,
                width: *width,
                height: *height,
                ..VisualSampleEntryFields::default()
            };
            let entry = SampleEntryVariant::Hevc1(HEVCSampleEntry {
                codec_type: *b"hvc1",
                visual,
                config: config.clone(),
                extra_boxes: vec![],
            });
            (
                entry,
                Some(VideoMediaHeaderBox {
                    version: 0,
                    flags: 1,
                    graphicsmode: 0,
                    opcolor: [0, 0, 0],
                }),
                None,
                *b"vide",
                b"VideoHandler\0".to_vec(),
                (*width as u32) << 16,
                (*height as u32) << 16,
            )
        }
        CodecConfig::Vvc {
            config,
            width,
            height,
        } => {
            let visual = VisualSampleEntryFields {
                data_reference_index: 1,
                width: *width,
                height: *height,
                ..VisualSampleEntryFields::default()
            };
            let entry = SampleEntryVariant::Vvc(Box::new(VVCSampleEntry {
                codec_type: *b"vvc1",
                visual,
                config: config.clone(),
                extra_boxes: vec![],
            }));
            (
                entry,
                Some(VideoMediaHeaderBox {
                    version: 0,
                    flags: 1,
                    graphicsmode: 0,
                    opcolor: [0, 0, 0],
                }),
                None,
                *b"vide",
                b"VideoHandler\0".to_vec(),
                (*width as u32) << 16,
                (*height as u32) << 16,
            )
        }
        CodecConfig::Aac {
            esds,
            channel_count,
            sample_rate,
            sample_size,
        } => {
            let mut esds_full = vec![0u8; esds.serialized_len()];
            let n = esds.serialize_into(&mut esds_full)?;
            let esds_opaque = OpaqueBox::new(*b"esds", esds_full[8..n].to_vec());
            let entry = SampleEntryVariant::Mp4a(Box::new(Mp4aSampleEntry {
                data_reference_index: 1,
                channelcount: *channel_count,
                samplesize: *sample_size,
                samplerate: sample_rate << 16,
                config_boxes: vec![esds_opaque],
            }));
            (
                entry,
                None,
                Some(SoundMediaHeaderBox {
                    version: 0,
                    flags: 0,
                    balance: 0,
                }),
                *b"soun",
                b"SoundHandler\0".to_vec(),
                0,
                0,
            )
        }
        CodecConfig::Ac3 {
            config,
            channel_count,
            sample_rate,
            sample_size,
        } => {
            let mut dac3_full = vec![0u8; config.serialized_len() + 8];
            dac3_full[4..8].copy_from_slice(b"dac3");
            let n = config.serialize_into(&mut dac3_full[8..])?;
            let dac3_opaque = OpaqueBox::new(*b"dac3", dac3_full[8..8 + n].to_vec());
            let entry = SampleEntryVariant::Ac3(Box::new(Ac3SampleEntry {
                data_reference_index: 1,
                channelcount: *channel_count,
                samplesize: *sample_size,
                samplerate: (*sample_rate) << 16,
                config_boxes: vec![dac3_opaque],
            }));
            (
                entry,
                None,
                Some(SoundMediaHeaderBox {
                    version: 0,
                    flags: 0,
                    balance: 0,
                }),
                *b"soun",
                b"SoundHandler\0".to_vec(),
                0,
                0,
            )
        }
        CodecConfig::Eac3 {
            config,
            channel_count,
            sample_rate,
            sample_size,
        } => {
            let mut dec3_full = vec![0u8; config.serialized_len() + 8];
            dec3_full[4..8].copy_from_slice(b"dec3");
            let n = config.serialize_into(&mut dec3_full[8..])?;
            let dec3_opaque = OpaqueBox::new(*b"dec3", dec3_full[8..8 + n].to_vec());
            let entry = SampleEntryVariant::Ec3(Box::new(Ec3SampleEntry {
                data_reference_index: 1,
                channelcount: *channel_count,
                samplesize: *sample_size,
                samplerate: (*sample_rate) << 16,
                config_boxes: vec![dec3_opaque],
            }));
            (
                entry,
                None,
                Some(SoundMediaHeaderBox {
                    version: 0,
                    flags: 0,
                    balance: 0,
                }),
                *b"soun",
                b"SoundHandler\0".to_vec(),
                0,
                0,
            )
        }
        CodecConfig::Av1 {
            config,
            width,
            height,
        } => {
            let visual = VisualSampleEntryFields {
                data_reference_index: 1,
                width: *width,
                height: *height,
                ..VisualSampleEntryFields::default()
            };
            let entry = SampleEntryVariant::Av01(Box::new(Av1SampleEntry {
                visual,
                config: config.clone(),
            }));
            (
                entry,
                Some(VideoMediaHeaderBox {
                    version: 0,
                    flags: 1,
                    graphicsmode: 0,
                    opcolor: [0, 0, 0],
                }),
                None,
                *b"vide",
                b"VideoHandler\0".to_vec(),
                (*width as u32) << 16,
                (*height as u32) << 16,
            )
        }
        CodecConfig::Vp9 {
            config,
            width,
            height,
        } => {
            let visual = VisualSampleEntryFields {
                data_reference_index: 1,
                width: *width,
                height: *height,
                ..VisualSampleEntryFields::default()
            };
            let entry = SampleEntryVariant::Vp09(Box::new(Vp9SampleEntry {
                visual,
                config: config.clone(),
            }));
            (
                entry,
                Some(VideoMediaHeaderBox {
                    version: 0,
                    flags: 1,
                    graphicsmode: 0,
                    opcolor: [0, 0, 0],
                }),
                None,
                *b"vide",
                b"VideoHandler\0".to_vec(),
                (*width as u32) << 16,
                (*height as u32) << 16,
            )
        }
        CodecConfig::Opus {
            config,
            channel_count,
            sample_rate,
            sample_size,
        } => {
            let dops_opaque = config_box(&DOPS_FOURCC, config)?;
            let entry = SampleEntryVariant::Opus(Box::new(OpusSampleEntry {
                data_reference_index: 1,
                channelcount: *channel_count,
                samplesize: *sample_size,
                samplerate: (*sample_rate) << 16,
                config_boxes: vec![dops_opaque],
            }));
            (
                entry,
                None,
                Some(SoundMediaHeaderBox {
                    version: 0,
                    flags: 0,
                    balance: 0,
                }),
                *b"soun",
                b"SoundHandler\0".to_vec(),
                0,
                0,
            )
        }
        CodecConfig::Flac {
            config,
            channel_count,
            sample_rate,
            sample_size,
        } => {
            let dfla_opaque = config_box(&DFLA_FOURCC, config)?;
            let entry = SampleEntryVariant::Flac(Box::new(FlacSampleEntry {
                data_reference_index: 1,
                channelcount: *channel_count,
                samplesize: *sample_size,
                samplerate: (*sample_rate) << 16,
                config_boxes: vec![dfla_opaque],
            }));
            (
                entry,
                None,
                Some(SoundMediaHeaderBox {
                    version: 0,
                    flags: 0,
                    balance: 0,
                }),
                *b"soun",
                b"SoundHandler\0".to_vec(),
                0,
                0,
            )
        }
        CodecConfig::Ac4 {
            config,
            channel_count,
            sample_rate,
            sample_size,
        } => {
            let dac4_opaque = config_box(&DAC4_FOURCC, config)?;
            let entry = SampleEntryVariant::Ac4(Box::new(Ac4SampleEntry {
                data_reference_index: 1,
                channelcount: *channel_count,
                samplesize: *sample_size,
                samplerate: (*sample_rate) << 16,
                config_boxes: vec![dac4_opaque],
            }));
            (
                entry,
                None,
                Some(SoundMediaHeaderBox {
                    version: 0,
                    flags: 0,
                    balance: 0,
                }),
                *b"soun",
                b"SoundHandler\0".to_vec(),
                0,
                0,
            )
        }
        CodecConfig::MpegH {
            config,
            channel_count,
            sample_rate,
            sample_size,
        } => {
            let mhac_opaque = config_box(&MHAC_FOURCC, config)?;
            let entry = SampleEntryVariant::Mha(Box::new(MhaSampleEntry {
                codec_type: crate::mpegh::MHA1_FOURCC,
                data_reference_index: 1,
                channelcount: *channel_count,
                samplesize: *sample_size,
                samplerate: (*sample_rate) << 16,
                config_boxes: vec![mhac_opaque],
            }));
            (
                entry,
                None,
                Some(SoundMediaHeaderBox {
                    version: 0,
                    flags: 0,
                    balance: 0,
                }),
                *b"soun",
                b"SoundHandler\0".to_vec(),
                0,
                0,
            )
        }
        CodecConfig::Mpeg2Video {
            esds,
            width,
            height,
        } => {
            let visual = VisualSampleEntryFields {
                data_reference_index: 1,
                width: *width,
                height: *height,
                ..VisualSampleEntryFields::default()
            };
            let mut esds_full = vec![0u8; esds.serialized_len()];
            let n = esds.serialize_into(&mut esds_full)?;
            let esds_opaque = OpaqueBox::new(*b"esds", esds_full[8..n].to_vec());
            let entry = SampleEntryVariant::Mp4v(Box::new(Mp4vSampleEntry {
                visual,
                config_boxes: vec![esds_opaque],
            }));
            (
                entry,
                Some(VideoMediaHeaderBox {
                    version: 0,
                    flags: 1,
                    graphicsmode: 0,
                    opcolor: [0, 0, 0],
                }),
                None,
                *b"vide",
                b"VideoHandler\0".to_vec(),
                (*width as u32) << 16,
                (*height as u32) << 16,
            )
        }
        CodecConfig::MpegAudio {
            esds,
            layer: _,
            channel_count,
            sample_rate,
            sample_size,
        } => {
            let mut esds_full = vec![0u8; esds.serialized_len()];
            let n = esds.serialize_into(&mut esds_full)?;
            let esds_opaque = OpaqueBox::new(*b"esds", esds_full[8..n].to_vec());
            let entry = SampleEntryVariant::Mp4a(Box::new(Mp4aSampleEntry {
                data_reference_index: 1,
                channelcount: *channel_count,
                samplesize: *sample_size,
                samplerate: sample_rate << 16,
                config_boxes: vec![esds_opaque],
            }));
            (
                entry,
                None,
                Some(SoundMediaHeaderBox {
                    version: 0,
                    flags: 0,
                    balance: 0,
                }),
                *b"soun",
                b"SoundHandler\0".to_vec(),
                0,
                0,
            )
        }
        CodecConfig::Dts {
            config,
            codec_fourcc,
            channel_count,
            sample_rate,
            sample_size,
        } => {
            let ddts_opaque = config_box(&DDTS_FOURCC, config)?;
            let entry = SampleEntryVariant::Dts(Box::new(DtsSampleEntry {
                codec_type: *codec_fourcc,
                data_reference_index: 1,
                channelcount: *channel_count,
                samplesize: *sample_size,
                samplerate: (*sample_rate) << 16,
                config_boxes: vec![ddts_opaque],
            }));
            (
                entry,
                None,
                Some(SoundMediaHeaderBox {
                    version: 0,
                    flags: 0,
                    balance: 0,
                }),
                *b"soun",
                b"SoundHandler\0".to_vec(),
                0,
                0,
            )
        }
        CodecConfig::Vp8 {
            config,
            width,
            height,
        } => {
            let visual = VisualSampleEntryFields {
                data_reference_index: 1,
                width: *width,
                height: *height,
                ..VisualSampleEntryFields::default()
            };
            let entry = SampleEntryVariant::Vp08(Box::new(crate::vp9::Vp8SampleEntry {
                visual,
                config: config.clone(),
            }));
            (
                entry,
                Some(VideoMediaHeaderBox {
                    version: 0,
                    flags: 1,
                    graphicsmode: 0,
                    opcolor: [0, 0, 0],
                }),
                None,
                *b"vide",
                b"VideoHandler\0".to_vec(),
                (*width as u32) << 16,
                (*height as u32) << 16,
            )
        }
        CodecConfig::Vorbis { .. } => {
            return Err(crate::error::Error::UnsupportedCodec { codec: "Vorbis" });
        }
        CodecConfig::Subtitle { .. } => {
            return Err(crate::error::Error::UnsupportedCodec { codec: "Subtitle" });
        }
    };

    let stbl = SampleTableBox {
        children: vec![
            StblChild::Stsd(SampleDescriptionBox {
                version: 0,
                flags: 0,
                entries: vec![stsd_entry],
            }),
            StblChild::Stts(TimeToSampleBox {
                version: 0,
                flags: 0,
                entries: vec![],
            }),
            StblChild::Stsc(SampleToChunkBox {
                version: 0,
                flags: 0,
                entries: vec![],
            }),
            StblChild::Stsz(SampleSizeBox {
                version: 0,
                flags: 0,
                sample_size: 0,
                entries: vec![],
            }),
            StblChild::Stco(ChunkOffsetBox {
                version: 0,
                flags: 0,
                entries: vec![],
            }),
        ],
    };

    let dinf = DataInformationBox {
        dref: Some(DataReferenceBox {
            version: 0,
            flags: 0,
            entries: vec![DataEntryUrlBox {
                version: 0,
                flags: 1,
                location: vec![],
            }],
        }),
        opaque: vec![],
    };

    let minf = MediaInformationBox {
        vmhd,
        smhd,
        dinf: Some(dinf),
        stbl: Some(stbl),
        opaque: vec![],
    };

    let mdhd = MediaHeaderBox {
        version: 0,
        flags: 0,
        creation_time: 0,
        modification_time: 0,
        timescale: t.timescale,
        duration: 0,
        language: LANG_UND,
    };

    let hdlr = HandlerBox {
        version: 0,
        flags: 0,
        handler_type,
        name: handler_name,
    };

    let mdia = MediaBox {
        mdhd: Some(mdhd),
        hdlr: Some(hdlr),
        minf: Some(minf),
        opaque: vec![],
    };

    let tkhd = TrackHeaderBox {
        version: 0,
        flags: TKHD_ENABLED_IN_MOVIE,
        creation_time: 0,
        modification_time: 0,
        track_id: t.track_id,
        duration: 0,
        layer: 0,
        alternate_group: 0,
        volume: if audio { 0x0100 } else { 0 },
        matrix: IDENTITY_MATRIX,
        width: tkhd_w,
        height: tkhd_h,
    };

    let edts = t.edit_list.as_ref().map(|elst| crate::init_segment::EditBox {
        elst: Some(elst.clone()),
        opaque: vec![],
    });

    Ok(TrackBox {
        tkhd,
        edts,
        mdia: Some(mdia),
        opaque: vec![],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AVCConfigurationBox, AVCDecoderConfigurationRecord};
    use crate::timing::{EditListBox, EditListEntry};

    fn minimal_avc_config() -> AVCConfigurationBox {
        AVCConfigurationBox::new(AVCDecoderConfigurationRecord {
            configuration_version: 1,
            profile_indication: 0x64,
            profile_compatibility: 0,
            level_indication: 0x1f,
            length_size_minus_one: 3,
            sps: vec![],
            pps: vec![],
            chroma_format: None,
            bit_depth_luma_minus8: None,
            bit_depth_chroma_minus8: None,
            sps_ext: vec![],
        })
    }

    fn edit_list_with_leading_trim() -> EditListBox {
        EditListBox {
            version: 0,
            flags: 0,
            entries: vec![EditListEntry {
                segment_duration: 1000,
                media_time: 512,
                media_rate_integer: 1,
                media_rate_fraction: 0,
            }],
        }
    }

    #[test]
    fn build_trak_carries_the_source_edit_list_onto_a_video_track() {
        let mut spec = TrackSpec::new(
            1,
            30000,
            CodecConfig::Avc {
                config: minimal_avc_config(),
                width: 640,
                height: 360,
            },
        );
        let source_elst = edit_list_with_leading_trim();
        spec.edit_list = Some(source_elst.clone());

        let trak = build_trak(&spec).expect("build_trak must succeed on a minimal AVC spec");

        let got = trak
            .edts
            .as_ref()
            .and_then(|e| e.elst.as_ref())
            .expect("video track must carry the source edit list into edts/elst");
        assert_eq!(got, &source_elst, "carried edit list must match the source verbatim");
    }

    #[test]
    fn build_trak_omits_edts_when_the_source_has_no_edit_list() {
        let spec = TrackSpec::new(
            1,
            30000,
            CodecConfig::Avc {
                config: minimal_avc_config(),
                width: 640,
                height: 360,
            },
        );
        let trak = build_trak(&spec).expect("build_trak must succeed on a minimal AVC spec");
        assert!(trak.edts.is_none(), "no source edit list means no edts in the output");
    }
}
