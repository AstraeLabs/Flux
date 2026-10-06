//! Legacy-codec elementary-stream headers: MPEG-2 video (H.262) sequence header
//! and MPEG-1/2 audio (MP1/2/3) frame header.

use crate::error::{Error, Result};

pub const SEQUENCE_HEADER_CODE: [u8; 4] = [0x00, 0x00, 0x01, 0xB3];

const START_CODE_PREFIX: [u8; 3] = [0x00, 0x00, 0x01];

const SEQ_SIZE_FIELD_BYTES: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mpeg2SeqHeader {
    pub width: u16,
    pub height: u16,
}

impl Mpeg2SeqHeader {
    pub fn find(es: &[u8]) -> Result<Self> {
        let start = find_start_code(es, SEQUENCE_HEADER_CODE[3]).ok_or(Error::InvalidInput(
            "no MPEG-2 sequence_header (start code 0x000001B3) in elementary stream",
        ))?;
        let fields_at = start + SEQUENCE_HEADER_CODE.len();
        if fields_at + SEQ_SIZE_FIELD_BYTES > es.len() {
            return Err(Error::BufferTooShort {
                need: fields_at + SEQ_SIZE_FIELD_BYTES,
                have: es.len(),
                what: "MPEG-2 sequence_header size fields",
            });
        }
        let b = &es[fields_at..fields_at + SEQ_SIZE_FIELD_BYTES];
        let width = ((b[0] as u16) << 4) | ((b[1] as u16) >> 4);
        let height = (((b[1] & 0x0F) as u16) << 8) | b[2] as u16;
        Ok(Self { width, height })
    }
}

fn find_start_code(data: &[u8], code: u8) -> Option<usize> {
    let mut i = 0usize;
    while i + 4 <= data.len() {
        if data[i..i + 3] == START_CODE_PREFIX && data[i + 3] == code {
            return Some(i);
        }
        i += 1;
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub enum MpegAudioLayer {
    LayerI,
    LayerII,
    LayerIII,
}

impl MpegAudioLayer {
    pub fn number(self) -> u8 {
        match self {
            MpegAudioLayer::LayerI => 1,
            MpegAudioLayer::LayerII => 2,
            MpegAudioLayer::LayerIII => 3,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            MpegAudioLayer::LayerI => "Layer I",
            MpegAudioLayer::LayerII => "Layer II",
            MpegAudioLayer::LayerIII => "Layer III",
        }
    }
}

bitforge::impl_spec_display!(MpegAudioLayer);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MpegAudioVersion {
    Mpeg1,
    Mpeg2,
    Mpeg25,
}

pub const MPEG_AUDIO_SYNCWORD: u16 = 0x07FF;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MpegAudioFrameHeader {
    pub layer: MpegAudioLayer,
    pub sample_rate: u32,
    pub channels: u16,
    pub frame_length: usize,
    pub samples_per_frame: u32,
}

#[rustfmt::skip]
const BITRATE_KBPS: [[[u16; 16]; 3]; 2] = [
    [
        [0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448, 0],
        [0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 0],
        [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0],
    ],
    [
        [0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256, 0],
        [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0],
        [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0],
    ],
];

const SAMPLE_RATE_MPEG1: [u32; 3] = [44100, 48000, 32000];

const LAYER_III: u8 = 0b01;
const LAYER_II: u8 = 0b10;
const LAYER_I: u8 = 0b11;

const MODE_SINGLE_CHANNEL: u8 = 0b11;

impl MpegAudioFrameHeader {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(Error::BufferTooShort {
                need: 4,
                have: data.len(),
                what: "MPEG audio frame header",
            });
        }
        let h = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);

        let syncword = ((h >> 21) & 0x07FF) as u16;
        if syncword != MPEG_AUDIO_SYNCWORD {
            return Err(Error::InvalidInput(
                "MPEG audio frame header: bad syncword (expected 11-bit 0x7FF)",
            ));
        }
        let id = ((h >> 19) & 0x3) as u8;
        let version = match id {
            0b11 => MpegAudioVersion::Mpeg1,
            0b10 => MpegAudioVersion::Mpeg2,
            0b00 => MpegAudioVersion::Mpeg25,
            _ => {
                return Err(Error::InvalidInput(
                    "MPEG audio frame header: reserved version ID",
                ));
            }
        };
        let layer = match ((h >> 17) & 0x3) as u8 {
            LAYER_I => MpegAudioLayer::LayerI,
            LAYER_II => MpegAudioLayer::LayerII,
            LAYER_III => MpegAudioLayer::LayerIII,
            _ => {
                return Err(Error::InvalidInput(
                    "MPEG audio frame header: reserved layer",
                ));
            }
        };
        let bitrate_index = ((h >> 12) & 0xF) as usize;
        let sample_rate_index = ((h >> 10) & 0x3) as usize;
        let padding = ((h >> 9) & 0x1) as usize;
        let mode = ((h >> 6) & 0x3) as u8;

        if sample_rate_index >= SAMPLE_RATE_MPEG1.len() {
            return Err(Error::InvalidInput(
                "MPEG audio frame header: reserved sampling_frequency",
            ));
        }
        let base_rate = SAMPLE_RATE_MPEG1[sample_rate_index];
        let sample_rate = match version {
            MpegAudioVersion::Mpeg1 => base_rate,
            MpegAudioVersion::Mpeg2 => base_rate / 2,
            MpegAudioVersion::Mpeg25 => base_rate / 4,
        };

        let version_group = matches!(version, MpegAudioVersion::Mpeg1) as usize ^ 1;
        let layer_group = match layer {
            MpegAudioLayer::LayerI => 0,
            MpegAudioLayer::LayerII => 1,
            MpegAudioLayer::LayerIII => 2,
        };
        let bitrate_kbps = BITRATE_KBPS[version_group][layer_group][bitrate_index];
        if bitrate_kbps == 0 {
            return Err(Error::InvalidInput(
                "MPEG audio frame header: free-format or forbidden bitrate_index",
            ));
        }
        let bitrate = bitrate_kbps as usize * 1000;

        let channels: u16 = if mode == MODE_SINGLE_CHANNEL { 1 } else { 2 };

        let samples_per_frame = match (layer, version) {
            (MpegAudioLayer::LayerI, _) => 384,
            (MpegAudioLayer::LayerII, _) => 1152,
            (MpegAudioLayer::LayerIII, MpegAudioVersion::Mpeg1) => 1152,
            (MpegAudioLayer::LayerIII, _) => 576,
        };
        let frame_length = match layer {
            MpegAudioLayer::LayerI => (12 * bitrate / sample_rate as usize + padding) * 4,
            _ => (samples_per_frame as usize / 8) * bitrate / sample_rate as usize + padding,
        };
        if frame_length < 4 {
            return Err(Error::InvalidInput(
                "MPEG audio frame header: computed frame length shorter than header",
            ));
        }

        Ok(Self {
            layer,
            sample_rate,
            channels,
            frame_length,
            samples_per_frame,
        })
    }
}
