//! RFC 6381 codec-string generation (`avc1.4d401f`, `mp4a.40.2`, ...) for `--dump`.
use crate::pipeline::CodecConfig;
use alloc::format;
use alloc::string::String;

pub(crate) fn rfc6381_codec_string(cfg: &CodecConfig) -> String {
    match cfg {
        CodecConfig::Avc { config, .. } => {
            let c = &config.config;
            format!(
                "avc1.{:02x}{:02x}{:02x}",
                c.profile_indication, c.profile_compatibility, c.level_indication
            )
        }
        CodecConfig::Hevc { config, .. } => hevc_codec_string(&config.config),
        CodecConfig::Vvc { config, .. } => vvc_codec_string(&config.config),
        CodecConfig::Av1 { config, .. } => {
            let tier = if config.seq_tier_0 { "H" } else { "M" };
            let depth = if config.twelve_bit {
                12
            } else if config.high_bitdepth {
                10
            } else {
                8
            };
            format!(
                "av01.{}.{:02}{}.{:02}",
                config.seq_profile, config.seq_level_idx_0, tier, depth
            )
        }
        CodecConfig::Vp9 { config, .. } => {
            format!("vp09.{:02}.{:02}.{:02}", config.profile, config.level, config.bit_depth)
        }
        CodecConfig::Vp8 { config, .. } => {
            format!("vp08.{:02}.{:02}.{:02}", config.profile, config.level, config.bit_depth)
        }
        CodecConfig::Aac { esds, .. } => aac_codec_string(esds),
        CodecConfig::Ac3 { .. } => String::from("ac-3"),
        CodecConfig::Eac3 { .. } => String::from("ec-3"),
        CodecConfig::Ac4 { .. } => String::from("ac-4"),
        CodecConfig::Opus { .. } => String::from("opus"),
        CodecConfig::Flac { .. } => String::from("fLaC"),
        CodecConfig::Dts { codec_fourcc, .. } => {
            String::from_utf8_lossy(codec_fourcc).into_owned()
        }
        CodecConfig::MpegH { .. } => String::from("mhm1"),
        CodecConfig::Mpeg2Video { esds, .. } => {
            let oti = esds
                .es_descriptor
                .decoder_config
                .as_ref()
                .map(|dc| dc.object_type_indication.0)
                .unwrap_or(0x60);
            format!("mp4v.{oti:02x}")
        }
        CodecConfig::MpegAudio { esds, .. } => {
            let oti = esds
                .es_descriptor
                .decoder_config
                .as_ref()
                .map(|dc| dc.object_type_indication.0)
                .unwrap_or(0x6B);
            format!("mp4a.{oti:02x}")
        }
        CodecConfig::Vorbis { .. } => String::from("vorbis"),
        CodecConfig::Subtitle { format } => String::from(match format {
            crate::pipeline::SubtitleFormat::Ttml => "stpp",
            crate::pipeline::SubtitleFormat::WebVtt => "wvtt",
            crate::pipeline::SubtitleFormat::Cea608 => "c608",
        }),
    }
}

fn hevc_codec_string(c: &crate::hevc_config::HEVCDecoderConfigurationRecord) -> String {
    let space = match c.general_profile_space {
        1 => "A",
        2 => "B",
        3 => "C",
        _ => "",
    };
    let compat = c.general_profile_compatibility_flags.reverse_bits();
    let tier = if c.general_tier_flag { "H" } else { "L" };

    let flags = c.general_constraint_indicator_flags;
    let mut bytes: alloc::vec::Vec<u8> = (0..6)
        .map(|i| ((flags >> ((5 - i) * 8)) & 0xFF) as u8)
        .collect();
    while bytes.last() == Some(&0) {
        bytes.pop();
    }
    let constraint = bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<alloc::vec::Vec<_>>()
        .join(".");

    let mut s = format!(
        "hev1.{}{}.{:X}.{}{}",
        space, c.general_profile_idc, compat, tier, c.general_level_idc
    );
    if !constraint.is_empty() {
        s.push('.');
        s.push_str(&constraint);
    }
    s
}

fn vvc_codec_string(c: &crate::vvc_config::VvcDecoderConfigurationRecord) -> String {
    match &c.ptl {
        Some(ptl) => {
            let tier = if ptl.general_tier_flag { "H" } else { "L" };
            format!("vvc1.{}.{}{}", ptl.general_profile_idc, tier, ptl.general_level_idc)
        }
        None => String::from("vvc1"),
    }
}

fn aac_codec_string(esds: &crate::mp4esds::EsdsBox) -> String {
    let oti = esds
        .es_descriptor
        .decoder_config
        .as_ref()
        .map(|dc| dc.object_type_indication.0)
        .unwrap_or(0x40);

    let aot = esds
        .es_descriptor
        .decoder_config
        .as_ref()
        .and_then(|dc| dc.decoder_specific_info.as_ref())
        .and_then(|dsi| audio_object_type(&dsi.data));

    match aot {
        Some(aot) => format!("mp4a.{oti:02x}.{aot}"),
        None => format!("mp4a.{oti:02x}"),
    }
}

fn audio_object_type(data: &[u8]) -> Option<u32> {
    let read_bits = |bit_off: usize, bit_count: u32| -> Option<u32> {
        if bit_off + bit_count as usize > data.len() * 8 {
            return None;
        }
        let mut value: u32 = 0;
        for i in 0..bit_count as usize {
            let bit_idx = bit_off + i;
            let byte = data[bit_idx / 8];
            let bit = (byte >> (7 - (bit_idx % 8))) & 1;
            value = (value << 1) | bit as u32;
        }
        Some(value)
    };
    let aot = read_bits(0, 5)?;
    if aot == 31 {
        let extra = read_bits(5, 6)?;
        Some(32 + extra)
    } else {
        Some(aot)
    }
}
