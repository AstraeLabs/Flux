//! Per-track codec configuration — [`CodecConfig`].

use alloc::vec::Vec;

use crate::ac3::{Ac3SpecificBox, Ec3SpecificBox};
use crate::ac4::Ac4SpecificBox;
use crate::av1::Av1ConfigurationBox;
use crate::avc_config::AVCConfigurationBox;
use crate::dts::DtsSpecificBox;
use crate::flac::FlacSpecificBox;
use crate::hevc_config::HEVCConfigurationBox;
use crate::mp4esds::EsdsBox;
use crate::opus::OpusSpecificBox;
use crate::vp9::Vp9ConfigurationBox;
use crate::vvc_config::VvcConfigurationBox;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SubtitleFormat {
    Ttml,
    WebVtt,
    Cea608,
}

impl SubtitleFormat {
    pub fn name(&self) -> &'static str {
        match self {
            SubtitleFormat::Ttml => "TTML (stpp)",
            SubtitleFormat::WebVtt => "WebVTT (wvtt)",
            SubtitleFormat::Cea608 => "CEA-608 (c608)",
        }
    }
}

bitforge::impl_spec_display!(SubtitleFormat);

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum CodecConfig {
    Avc {
        config: AVCConfigurationBox,
        width: u16,
        height: u16,
    },
    Hevc {
        config: HEVCConfigurationBox,
        width: u16,
        height: u16,
    },
    Vvc {
        config: VvcConfigurationBox,
        width: u16,
        height: u16,
    },
    Aac {
        esds: EsdsBox,
        channel_count: u16,
        sample_rate: u32,
        sample_size: u16,
    },
    Ac3 {
        config: Ac3SpecificBox,
        channel_count: u16,
        sample_rate: u32,
        sample_size: u16,
    },
    Eac3 {
        config: Ec3SpecificBox,
        channel_count: u16,
        sample_rate: u32,
        sample_size: u16,
    },
    Av1 {
        config: Av1ConfigurationBox,
        width: u16,
        height: u16,
    },
    Vp9 {
        config: Vp9ConfigurationBox,
        width: u16,
        height: u16,
    },
    Opus {
        config: OpusSpecificBox,
        channel_count: u16,
        sample_rate: u32,
        sample_size: u16,
    },
    Flac {
        config: FlacSpecificBox,
        channel_count: u16,
        sample_rate: u32,
        sample_size: u16,
    },
    Ac4 {
        config: Ac4SpecificBox,
        channel_count: u16,
        sample_rate: u32,
        sample_size: u16,
    },
    MpegH {
        config: crate::mpegh::MHADecoderConfigurationRecord,
        channel_count: u16,
        sample_rate: u32,
        sample_size: u16,
    },
    Mpeg2Video {
        esds: EsdsBox,
        width: u16,
        height: u16,
    },
    MpegAudio {
        esds: EsdsBox,
        layer: crate::mpeg_legacy::MpegAudioLayer,
        channel_count: u16,
        sample_rate: u32,
        sample_size: u16,
    },
    Dts {
        config: DtsSpecificBox,
        codec_fourcc: [u8; 4],
        channel_count: u16,
        sample_rate: u32,
        sample_size: u16,
    },
    Vp8 {
        config: crate::vp9::Vp9ConfigurationBox,
        width: u16,
        height: u16,
    },
    Vorbis {
        codec_private: Vec<u8>,
        channels: u16,
        sample_rate: u32,
    },
    Subtitle {
        format: SubtitleFormat,
    },
}

impl CodecConfig {
    pub(crate) fn is_audio(&self) -> bool {
        matches!(
            self,
            CodecConfig::Aac { .. }
                | CodecConfig::Ac3 { .. }
                | CodecConfig::Eac3 { .. }
                | CodecConfig::Opus { .. }
                | CodecConfig::Flac { .. }
                | CodecConfig::Ac4 { .. }
                | CodecConfig::MpegH { .. }
                | CodecConfig::Dts { .. }
                | CodecConfig::MpegAudio { .. }
                | CodecConfig::Vorbis { .. }
        )
    }

    pub(crate) fn is_subtitle(&self) -> bool {
        matches!(self, CodecConfig::Subtitle { .. })
    }

    pub fn is_muxable_in_bmff(&self) -> bool {
        !self.is_subtitle()
    }
}
