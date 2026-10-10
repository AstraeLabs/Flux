//! `--extract-text`: extract a WebVTT-in-fMP4 (`wvtt`)

use core::fmt::Write as _;
use std::path::Path;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::{CliError, CliResult, open_sequential, read_region, scan_top_level_boxes};
use crate::cenc_decrypt;
use crate::pipeline::{CodecConfig, SubtitleFormat};
use crate::VttCueBox;

struct Cue {
    start: i64,
    end: i64,
    settings: Option<String>,
    cue_id: Option<String>,
    text: String,
}

pub(super) fn extract_text(in_path: &Path, tracks_filter: &[u32], output: &Path) -> CliResult<()> {
    let mut file = open_sequential(in_path)?;
    let top_level = scan_top_level_boxes(&mut file)?;
    let Some(moov_box) = top_level.iter().find(|b| &b.box_type == b"moov") else {
        return Err(CliError::Flux(crate::Error::UnexpectedBox { expected: "moov" }));
    };

    let moov_bytes = read_region(&mut file, moov_box.offset, moov_box.size)?;

    let (_movie_timescale, specs) = cenc_decrypt::harvest_moov_track_specs(&moov_bytes)?;
    let trex_defaults = cenc_decrypt::harvest_trex_defaults(&moov_bytes);

    let candidates: Vec<_> = specs
        .iter()
        .filter(|s| matches!(&s.codec_config, CodecConfig::Subtitle { format: SubtitleFormat::WebVtt }))
        .filter(|s| tracks_filter.is_empty() || tracks_filter.contains(&s.track_id))
        .collect();

    let spec = match candidates.as_slice() {
        [] => return Err(CliError::NoTracksSelected),
        [only] => *only,
        _ => {
            return Err(CliError::Flux(crate::Error::InvalidInput(
                "more than one WebVTT subtitle track matched -- narrow to one with --tracks <ID>",
            )));
        }
    };

    let track_ids = [spec.track_id];
    let mut next_dts: std::collections::BTreeMap<u32, i64> = std::collections::BTreeMap::new();
    let mut cues: Vec<Cue> = Vec::new();

    for moof_box in top_level.iter().filter(|b| &b.box_type == b"moof") {
        let moof_bytes = read_region(&mut file, moof_box.offset, moof_box.size)?;
        let Ok((bx, _)) = crate::box_types::parse_box(&moof_bytes) else {
            continue;
        };
        let Ok(moof) = crate::movie_fragment::MovieFragmentBox::parse_body(bx.body) else {
            continue;
        };
        let Ok(layouts) = cenc_decrypt::fragment_sample_layout(
            moof_box.offset,
            &moof,
            &track_ids,
            &mut next_dts,
            &trex_defaults,
        ) else {
            continue;
        };

        let Some(samples) = layouts.get(&spec.track_id) else {
            continue;
        };
        for sample in samples {
            if sample.size < 8 {
                continue;
            }
            let buf = read_region(&mut file, sample.file_offset, sample.size as u64)?;

            if let Some((text, settings, cue_id)) = decode_cue_sample(&buf) {
                cues.push(Cue {
                    start: sample.dts,
                    end: sample.dts + sample.duration as i64,
                    settings,
                    cue_id,
                    text,
                });
            }
        }
    }

    if cues.is_empty() {
        return Err(CliError::Flux(crate::Error::InvalidInput(
            "no subtitle cues with text were found in this track",
        )));
    }

    let mut out = String::from("WEBVTT\n\n");
    for cue in &cues {
        if let Some(cue_id) = &cue.cue_id {
            let _ = writeln!(out, "{}", sanitize_single_line(cue_id));
        }
        let _ = write!(
            out,
            "{} --> {}",
            format_timestamp(cue.start, spec.timescale),
            format_timestamp(cue.end, spec.timescale)
        );
        if let Some(settings) = &cue.settings {
            let _ = write!(out, " {}", sanitize_single_line(settings));
        }
        let _ = writeln!(out);
        let _ = writeln!(out, "{}", sanitize_cue_text(&cue.text));
        let _ = writeln!(out);
    }

    std::fs::write(output, out).map_err(CliError::Io)?;
    Ok(())
}

/// Collapse a field that must stay on one line (cue id / settings): any line break or
/// `-->` would otherwise let the cue forge extra cues or timing lines.
fn sanitize_single_line(s: &str) -> String {
    sanitize_cue_text(s).replace('\n', " ")
}

/// Make cue payload text safe to embed in a WebVTT file: normalize line endings, drop
/// blank lines (they terminate a cue) and neutralize `-->` (it starts a timing line).
fn sanitize_cue_text(s: &str) -> String {
    let normalized = s.replace("\r\n", "\n").replace('\r', "\n");
    let mut out = String::with_capacity(normalized.len());
    for line in normalized.split('\n') {
        if line.trim().is_empty() {
            continue;
        }
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&line.replace("-->", "--&gt;"));
    }
    out
}

fn decode_cue_sample(buf: &[u8]) -> Option<(String, Option<String>, Option<String>)> {
    if buf.len() < 8 || &buf[4..8] != b"vttc" {
        return None;
    }
    let cue = VttCueBox::bare_parse(buf).ok()?;
    if cue.payload.cue_text.is_empty() {
        return None;
    }
    Some((
        cue.payload.cue_text,
        cue.settings.map(|s| s.settings),
        cue.cue_id.map(|c| c.cue_id),
    ))
}

fn format_timestamp(ticks: i64, timescale: u32) -> String {
    let ticks = ticks.max(0) as u64;
    let timescale = timescale.max(1) as u64;
    let total_ms = ticks.saturating_mul(1000) / timescale;
    let ms = total_ms % 1000;
    let total_s = total_ms / 1000;
    let s = total_s % 60;
    let total_m = total_s / 60;
    let m = total_m % 60;
    let h = total_m / 60;
    format!("{h:02}:{m:02}:{s:02}.{ms:03}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boxes::subtitle_entries::{CueIdBox, CueSettingsBox, VttEmptyCueBox};
    use bitforge::Serialize;

    fn to_bytes(b: &impl Serialize) -> Vec<u8> {
        let mut buf = vec![0u8; b.serialized_len()];
        let n = b.serialize_into(&mut buf).unwrap_or_else(|_| panic!("serialize failed"));
        buf.truncate(n);
        buf
    }

    #[test]
    fn decode_cue_sample_reads_text_only_cue() {
        let cue = VttCueBox::new("Hello world");
        let bytes = to_bytes(&cue);
        let (text, settings, cue_id) = decode_cue_sample(&bytes).expect("must decode");
        assert_eq!(text, "Hello world");
        assert_eq!(settings, None);
        assert_eq!(cue_id, None);
    }

    #[test]
    fn decode_cue_sample_reads_settings_and_cue_id_regardless_of_child_order() {
        let cue = VttCueBox {
            payload: crate::boxes::subtitle_entries::CuePayloadBox::new("Second cue"),
            settings: Some(CueSettingsBox::new("line:85% position:50% size:53% align:center")),
            cue_id: Some(CueIdBox::new("cue-42")),
        };
        let bytes = to_bytes(&cue);
        let (text, settings, cue_id) = decode_cue_sample(&bytes).expect("must decode");
        assert_eq!(text, "Second cue");
        assert_eq!(settings.as_deref(), Some("line:85% position:50% size:53% align:center"));
        assert_eq!(cue_id.as_deref(), Some("cue-42"));
    }

    #[test]
    fn sanitize_cue_text_blocks_cue_forgery() {
        let evil = "hi\n\n00:00:09.000 --> 00:00:10.000\nforged";
        let clean = sanitize_cue_text(evil);
        assert!(!clean.contains("\n\n"));
        assert!(!clean.contains("-->"));
        assert_eq!(sanitize_cue_text("a\r\n\r\nb"), "a\nb");
        assert_eq!(sanitize_single_line("x\ny"), "x y");
    }

    #[test]
    fn decode_cue_sample_ignores_an_empty_cue_gap() {
        let gap = VttEmptyCueBox;
        let bytes = to_bytes(&gap);
        assert_eq!(decode_cue_sample(&bytes), None);
    }

    #[test]
    fn decode_cue_sample_ignores_a_cue_with_empty_text() {
        let cue = VttCueBox::new("");
        let bytes = to_bytes(&cue);
        assert_eq!(decode_cue_sample(&bytes), None);
    }

    #[test]
    fn decode_cue_sample_rejects_a_buffer_too_short_to_be_a_box() {
        assert_eq!(decode_cue_sample(&[0, 0, 0]), None);
    }

    #[test]
    fn decode_cue_sample_rejects_an_unrecognized_fourcc() {
        let mut bytes = to_bytes(&VttCueBox::new("text"));
        bytes[4..8].copy_from_slice(b"xxxx");
        assert_eq!(decode_cue_sample(&bytes), None);
    }

    #[test]
    fn format_timestamp_renders_hours_minutes_seconds_milliseconds() {
        assert_eq!(format_timestamp(0, 1000), "00:00:00.000");
        assert_eq!(format_timestamp(2_085, 1000), "00:00:02.085");
        assert_eq!(format_timestamp(3_661_444, 1000), "01:01:01.444");
    }

    #[test]
    fn format_timestamp_handles_a_non_millisecond_timescale() {
        assert_eq!(format_timestamp(90_000, 90_000), "00:00:01.000");
        assert_eq!(format_timestamp(45_000, 90_000), "00:00:00.500");
    }

    #[test]
    fn format_timestamp_clamps_a_negative_tick_to_zero() {
        assert_eq!(format_timestamp(-500, 1000), "00:00:00.000");
    }
}
