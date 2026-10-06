//! `--dump`: read-only per-stream/track metadata report to stdout.

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use serde::Serialize;

use super::{CliError, CliResult, codec_label, hex_kid, open_sequential, scan_top_level_boxes};
use crate::cenc_decrypt;
use crate::cli::codec_string::rfc6381_codec_string;
use crate::webm_decrypt::{WebmTrackMeta, harvest_webm_track_meta};
use crate::crypto::drm_label::harvest_pssh_boxes;
use crate::pipeline::CodecConfig;

#[derive(Default)]
struct FragmentTotals {
    sample_count: u64,
    duration: u64,
    bytes: u64,
}

#[derive(Serialize)]
struct CryptoReport {
    default_kid: String,
    scheme: String,
    iv_size: u8,
    pattern: String,
}

#[derive(Serialize)]
struct PsshJson {
    system: String,
    system_id: String,
    version: u8,
    pssh_base64: String,
}

#[derive(Serialize)]
struct StreamReport {
    index: usize,
    stream_type: String,
    codec_string: String,
    time_scale: u32,
    duration: u64,
    duration_seconds: f64,
    sample_count: Option<u64>,
    avg_bitrate: Option<u64>,
    is_encrypted: bool,
    encrypted_fragments: Option<u64>,
    clear_fragments: Option<u64>,
    residual_protection_boxes: bool,
    codec: String,
    width: Option<u16>,
    height: Option<u16>,
    pixel_aspect_ratio: Option<String>,
    nalu_length_size: Option<u8>,
    sample_bits: Option<u16>,
    num_channels: Option<u16>,
    sampling_frequency: Option<u32>,
    trick_play_factor: Option<u8>,
    language: String,
    crypto: Option<CryptoReport>,
}

#[derive(Serialize)]
struct DumpReport {
    stream_count: usize,
    fragments: Option<usize>,
    pssh_systems: Vec<String>,
    pssh: Vec<PsshJson>,
    streams: Vec<StreamReport>,
}

pub(super) fn dump_streams(
    in_path: &Path,
    tracks_filter: &[u32],
    json: bool,
) -> CliResult<()> {
    let mut file = open_sequential(in_path)?;
    let mut magic = [0u8; 4];
    if file.read_exact(&mut magic).is_ok() {
        if magic == [0x1A, 0x45, 0xDF, 0xA3] {
            return dump_webm(in_path, tracks_filter, json);
        }
        let _ = file.seek(SeekFrom::Start(0));
    }
    let top_level = scan_top_level_boxes(&mut file)?;
    let Some(moov_box) = top_level.iter().find(|b| &b.box_type == b"moov") else {
        return Err(CliError::Flux(crate::Error::UnexpectedBox { expected: "moov" }));
    };

    let file_len = file.metadata()?.len();
    let available = file_len.saturating_sub(moov_box.offset);
    let read_len = moov_box.size.min(available) as usize;
    if (read_len as u64) < moov_box.size {
        eprintln!(
            "flux: warning: moov box appears truncated (input has {available} byte(s) of it, \
             moov declares {}) -- --dump output below may be incomplete",
            moov_box.size
        );
    }
    let mut moov_bytes = vec![0u8; read_len];
    file.seek(SeekFrom::Start(moov_box.offset))?;
    file.read_exact(&mut moov_bytes)?;

    let (_movie_timescale, specs) = cenc_decrypt::harvest_moov_track_specs(&moov_bytes)?;
    let crypto_tracks = cenc_decrypt::harvest_moov_crypto(&moov_bytes)?;
    let extras = cenc_decrypt::harvest_moov_dump_extras(&moov_bytes)?;
    let trex_defaults = cenc_decrypt::harvest_trex_defaults(&moov_bytes);
    let residual_protection = cenc_decrypt::harvest_moov_residual_protection(&moov_bytes);

    let specs: Vec<_> = specs
        .into_iter()
        .filter(|s| tracks_filter.is_empty() || tracks_filter.contains(&s.track_id))
        .collect();

    let pssh_boxes = harvest_pssh_boxes(&moov_bytes);
    let pssh_systems: Vec<String> = pssh_boxes
        .iter()
        .map(|p| p.name.clone().unwrap_or_else(|| hex_kid(&p.system_id)))
        .collect();

    if specs.is_empty() && pssh_systems.is_empty() {
        return Err(CliError::NoTracksSelected);
    }

    let track_ids: Vec<u32> = specs.iter().map(|s| s.track_id).collect();
    let mut next_dts: std::collections::BTreeMap<u32, i64> = std::collections::BTreeMap::new();
    let mut fragment_totals: std::collections::BTreeMap<u32, FragmentTotals> =
        std::collections::BTreeMap::new();
    let mut senc_totals: std::collections::BTreeMap<u32, (u64, u64)> =
        std::collections::BTreeMap::new();
    let mut fragment_count = 0usize;
    for moof_box in top_level.iter().filter(|b| &b.box_type == b"moof") {
        let file_len = file.metadata()?.len();
        let available = file_len.saturating_sub(moof_box.offset);
        if available < moof_box.size {
            eprintln!(
                "flux: warning: moof at offset {} appears truncated ({available} byte(s) \
                 available, declares {}) -- skipping it and any fragments after it; \
                 sample_count/duration/avg_bitrate above may be incomplete",
                moof_box.offset, moof_box.size
            );
            break;
        }
        fragment_count += 1;
        let mut moof_bytes = vec![0u8; moof_box.size as usize];
        file.seek(SeekFrom::Start(moof_box.offset))?;
        file.read_exact(&mut moof_bytes)?;
        let Ok((bx, _)) = crate::box_types::parse_box(&moof_bytes) else {
            eprintln!("flux: warning: moof at offset {} is malformed -- skipping it", moof_box.offset);
            continue;
        };
        let Ok(moof) = crate::movie_fragment::MovieFragmentBox::parse_body(bx.body) else {
            eprintln!("flux: warning: moof at offset {} is malformed -- skipping it", moof_box.offset);
            continue;
        };
        let Ok(layouts) = cenc_decrypt::fragment_sample_layout(
            moof_box.offset,
            &moof,
            &track_ids,
            &mut next_dts,
            &trex_defaults,
        ) else {
            eprintln!("flux: warning: moof at offset {} has malformed sample layout -- skipping it", moof_box.offset);
            continue;
        };
        for (track_id, samples) in layouts {
            let totals = fragment_totals.entry(track_id).or_default();
            totals.sample_count += samples.len() as u64;
            totals.duration += samples.iter().map(|s| s.duration as u64).sum::<u64>();
            totals.bytes += samples.iter().map(|s| s.size as u64).sum::<u64>();
        }
        for (track_id, has_senc) in cenc_decrypt::moof_sample_encryption_by_track(&moof_bytes) {
            let entry = senc_totals.entry(track_id).or_insert((0, 0));
            if has_senc {
                entry.0 += 1;
            } else {
                entry.1 += 1;
            }
        }
    }

    let pssh_json: Vec<PsshJson> = pssh_boxes
        .into_iter()
        .map(|p| PsshJson {
            system: p
                .name
                .unwrap_or_else(|| hex_kid(&p.system_id)),
            system_id: hex_kid(&p.system_id),
            version: p.version,
            pssh_base64: base64_encode(&p.data),
        })
        .collect();

    let mut streams = Vec::with_capacity(specs.len());    for (idx, spec) in specs.iter().enumerate() {
        let extra = extras.iter().find(|e| e.track_id == spec.track_id);
        let crypto = crypto_tracks.iter().find(|t| t.track_id == spec.track_id);
        let is_encrypted = crypto.is_some_and(|t| t.tenc.default_is_protected != 0);

        let stream_type = if spec.codec_config.is_subtitle() {
            "Subtitle"
        } else if spec.codec_config.is_audio() {
            "Audio"
        } else {
            "Video"
        };

        let totals = fragment_totals.get(&spec.track_id);
        let duration = totals
            .map(|t| t.duration)
            .filter(|&d| d > 0)
            .or_else(|| extra.map(|e| e.duration))
            .unwrap_or(0);
        let seconds = if spec.timescale != 0 {
            duration as f64 / spec.timescale as f64
        } else {
            0.0
        };

        let mut s = StreamReport {
            index: idx,
            stream_type: stream_type.to_string(),
            codec_string: rfc6381_codec_string(&spec.codec_config),
            time_scale: spec.timescale,
            duration,
            duration_seconds: seconds,
            sample_count: totals.filter(|t| t.sample_count > 0).map(|t| t.sample_count),
            avg_bitrate: if seconds > 0.0 {
                totals
                    .filter(|t| t.sample_count > 0)
                    .map(|t| (t.bytes as f64 * 8.0 / seconds).round() as u64)
            } else {
                None
            },
            is_encrypted,
            encrypted_fragments: if fragment_count > 0 {
                Some(senc_totals.get(&spec.track_id).map(|e| e.0).unwrap_or(0))
            } else {
                None
            },
            clear_fragments: if fragment_count > 0 {
                Some(senc_totals.get(&spec.track_id).map(|e| e.1).unwrap_or(0))
            } else {
                None
            },
            residual_protection_boxes: residual_protection
                .get(&spec.track_id)
                .copied()
                .unwrap_or(false),
            codec: codec_label(&spec.codec_config).to_string(),
            width: None,
            height: None,
            pixel_aspect_ratio: None,
            nalu_length_size: None,
            sample_bits: None,
            num_channels: None,
            sampling_frequency: None,
            trick_play_factor: None,
            language: extra
                .map(|e| String::from_utf8_lossy(&e.language).into_owned())
                .unwrap_or_else(|| "und".to_string()),
            crypto: None,
        };

        match &spec.codec_config {
            CodecConfig::Avc { width, height, config } => {
                s.width = Some(*width);
                s.height = Some(*height);
                s.pixel_aspect_ratio = Some(par_aspect_string(extra.and_then(|e| e.pixel_aspect)));
                s.nalu_length_size = Some(config.config.length_size_minus_one + 1);
            }
            CodecConfig::Hevc { width, height, config } => {
                s.width = Some(*width);
                s.height = Some(*height);
                s.pixel_aspect_ratio = Some(par_aspect_string(extra.and_then(|e| e.pixel_aspect)));
                s.nalu_length_size = Some(config.config.length_size_minus_one + 1);
            }
            CodecConfig::Vvc { width, height, config } => {
                s.width = Some(*width);
                s.height = Some(*height);
                s.pixel_aspect_ratio = Some(par_aspect_string(extra.and_then(|e| e.pixel_aspect)));
                s.nalu_length_size = Some(config.config.length_size_minus_one + 1);
            }
            CodecConfig::Av1 { width, height, .. }
            | CodecConfig::Vp9 { width, height, .. }
            | CodecConfig::Vp8 { width, height, .. }
            | CodecConfig::Mpeg2Video { width, height, .. } => {
                s.width = Some(*width);
                s.height = Some(*height);
                s.pixel_aspect_ratio = Some(par_aspect_string(extra.and_then(|e| e.pixel_aspect)));
            }
            CodecConfig::Aac {
                channel_count,
                sample_rate,
                sample_size,
                ..
            }
            | CodecConfig::Ac3 {
                channel_count,
                sample_rate,
                sample_size,
                ..
            }
            | CodecConfig::Eac3 {
                channel_count,
                sample_rate,
                sample_size,
                ..
            }
            | CodecConfig::Opus {
                channel_count,
                sample_rate,
                sample_size,
                ..
            }
            | CodecConfig::Flac {
                channel_count,
                sample_rate,
                sample_size,
                ..
            }
            | CodecConfig::Ac4 {
                channel_count,
                sample_rate,
                sample_size,
                ..
            }
            | CodecConfig::MpegH {
                channel_count,
                sample_rate,
                sample_size,
                ..
            }
            | CodecConfig::MpegAudio {
                channel_count,
                sample_rate,
                sample_size,
                ..
            }
            | CodecConfig::Dts {
                channel_count,
                sample_rate,
                sample_size,
                ..
            } => {
                s.sample_bits = Some(*sample_size);
                s.num_channels = Some(*channel_count);
                s.sampling_frequency = Some(*sample_rate);
            }
            CodecConfig::Vorbis {
                channels,
                sample_rate,
                ..
            } => {
                s.num_channels = Some(*channels);
                s.sampling_frequency = Some(*sample_rate);
            }
            CodecConfig::Subtitle { .. } => {}
        }

        if !spec.codec_config.is_audio() && !spec.codec_config.is_subtitle() {
            s.trick_play_factor = Some(0);
        }

        if is_encrypted {
            if let Some(t) = crypto {
                s.crypto = Some(CryptoReport {
                    default_kid: hex_kid(&t.tenc.default_kid),
                    scheme: format!("{:?}", t.scheme),
                    iv_size: t.tenc.default_per_sample_iv_size,
                    pattern: format!(
                        "{}:{}",
                        t.tenc.default_crypt_byte_block, t.tenc.default_skip_byte_block
                    ),
                });
            }
        }

        streams.push(s);
    }

    let report = DumpReport {
        stream_count: specs.len(),
        fragments: if fragment_count > 0 {
            Some(fragment_count)
        } else {
            None
        },
        pssh_systems,
        pssh: pssh_json,
        streams,
    };

    if json {
        render_json(&report)?;
    } else {
        render_human(&report);
    }
    Ok(())
}

fn dump_webm(in_path: &Path, tracks_filter: &[u32], json: bool) -> CliResult<()> {
    let bytes = std::fs::read(in_path).map_err(CliError::Io)?;
    let metas = harvest_webm_track_meta(&bytes)?;
    if metas.is_empty() {
        return Err(CliError::NoTracksSelected);
    }

    let filtered: Vec<&WebmTrackMeta> = metas
        .iter()
        .filter(|m| tracks_filter.is_empty() || tracks_filter.contains(&(m.track_number as u32)))
        .collect();

    let mut streams = Vec::with_capacity(filtered.len());
    for (idx, m) in filtered.into_iter().enumerate() {
        let is_enc = m.encrypted;
        let mut s = StreamReport {
            index: idx,
            stream_type: m.stream_type.to_string(),
            codec_string: m.codec_id.clone(),
            time_scale: 0,
            duration: 0,
            duration_seconds: 0.0,
            sample_count: None,
            avg_bitrate: None,
            is_encrypted: is_enc,
            encrypted_fragments: None,
            clear_fragments: None,
            residual_protection_boxes: false,
            codec: m.codec_id.clone(),
            width: m.width.map(|v| v as u16),
            height: m.height.map(|v| v as u16),
            pixel_aspect_ratio: None,
            nalu_length_size: None,
            sample_bits: m.bit_depth.map(|v| v as u16),
            num_channels: m.num_channels.map(|v| v as u16),
            sampling_frequency: m.sampling_frequency.map(|v| v as u32),
            trick_play_factor: if m.stream_type != "Audio" && m.stream_type != "Subtitle" {
                Some(0)
            } else {
                None
            },
            language: m
                .language
                .clone()
                .unwrap_or_else(|| "und".to_string()),
            crypto: None,
        };
        if is_enc {
            s.crypto = Some(CryptoReport {
                default_kid: match &m.kid {
                    Some(k) => hex_kid(k),
                    None => String::new(),
                },
                scheme: m.scheme.clone().unwrap_or_else(|| "cenc".to_string()),
                iv_size: m.iv_size.unwrap_or(8),
                pattern: m.pattern.clone().unwrap_or_else(|| "0:0".to_string()),
            });
        }
        streams.push(s);
    }

    let report = DumpReport {
        stream_count: streams.len(),
        fragments: None,
        pssh_systems: Vec::new(),
        pssh: Vec::new(),
        streams,
    };

    if json {
        render_json(&report)?;
    } else {
        render_human(&report);
    }
    Ok(())
}

#[cfg(feature = "cli")]
fn render_json(report: &DumpReport) -> CliResult<()> {
    let json = serde_json::to_string_pretty(report)
        .map_err(|_| {
            CliError::Flux(crate::Error::InvalidInput("failed to serialize --dump JSON output"))
        })?;
    println!("{json}");
    Ok(())
}

#[cfg(not(feature = "cli"))]
fn render_json(_report: &DumpReport) -> CliResult<()> {
    Err(CliError::Flux(crate::Error::InvalidInput(
        "--json requires the cli feature",
    )))
}

fn render_human(report: &DumpReport) {
    println!("Found {} stream(s).", report.stream_count);
    if let Some(fragments) = report.fragments {
        println!("Fragments: {fragments}");
    }
    if !report.pssh_systems.is_empty() {
        println!("PSSH systems: {}", report.pssh_systems.join(", "));
    }
    println!();

    for s in &report.streams {
        println!("Stream [{}] type: {}", s.index, s.stream_type);
        println!(" codec_string: {}", s.codec_string);
        println!(" time_scale: {}", s.time_scale);
        println!(
            " duration: {} ({:.1} seconds)",
            s.duration, s.duration_seconds
        );
        if let Some(sample_count) = s.sample_count {
            println!(" sample_count: {sample_count}");
            if let Some(bitrate) = s.avg_bitrate {
                println!(" avg_bitrate: {bitrate} bps");
            }
        }
        println!(" is_encrypted: {}", s.is_encrypted);
        if let Some(n) = s.encrypted_fragments {
            println!(" encrypted_fragments: {n}");
        }
        if let Some(n) = s.clear_fragments {
            println!(" clear_fragments: {n}");
        }
        if s.residual_protection_boxes {
            println!(" residual_protection_boxes: true");
        }
        println!(" codec: {}", s.codec);

        if let (Some(w), Some(h)) = (s.width, s.height) {
            println!(" width: {w}");
            println!(" height: {h}");
            println!(
                " pixel_aspect_ratio: {}",
                s.pixel_aspect_ratio.as_deref().unwrap_or("1:1")
            );
            if let Some(nalu) = s.nalu_length_size {
                println!(" nalu_length_size: {nalu}");
            }
        }
        if let (Some(bits), Some(ch), Some(freq)) =
            (s.sample_bits, s.num_channels, s.sampling_frequency)
        {
            println!(" sample_bits: {bits}");
            println!(" num_channels: {ch}");
            println!(" sampling_frequency: {freq}");
        }

        if s.trick_play_factor.is_some() {
            println!(" trick_play_factor: 0");
        }
        println!(" language: {}", s.language);

        if let Some(c) = &s.crypto {
            println!(" default_kid: {}", c.default_kid);
            println!(" scheme: {}", c.scheme);
            println!(" iv_size: {}", c.iv_size);
            println!(" pattern: {}", c.pattern);
            if !report.pssh.is_empty() {
                println!(" pssh:");
                for p in &report.pssh {
                    println!("   name: {}", p.system);
                    println!("   pssh: {}", p.pssh_base64);
                }
            }
        }

        println!();
    }
}

fn par_aspect_string(par: Option<(u32, u32)>) -> String {
    let (h, v) = par.unwrap_or((1, 1));
    format!("{h}:{v}")
}

fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18) & 63] as char);
        out.push(ALPHABET[(n >> 12) & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n & 63] as char
        } else {
            '='
        });
    }
    out
}
