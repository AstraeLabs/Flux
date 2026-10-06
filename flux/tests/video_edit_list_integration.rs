//! Regression test for carrying a video track's `edts/elst` (edit list) through progressive remux

use std::path::{Path, PathBuf};
use std::process::Command;

use flux::cli::{self, Args};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}

fn unique_temp_path(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let (stem, ext) = name.rsplit_once('.').expect("fixture output name must have an extension");
    std::env::temp_dir().join(format!("flux-test-{}-{stem}-{nanos}.{ext}", std::process::id()))
}

fn base_args(input: PathBuf, output: PathBuf) -> Args {
    Args {
        help: None,
        version: None,
        in_positional: None,
        input: Some(input),
        output: Some(output),
        dump: false,
        json: false,
        extract_text: false,
        format: None,
        tracks: Vec::new(),
        keys: Vec::new(),
        fragments_info: None,
        ffmpeg_path: None,
        key_sanity_check: false,
        skip_key_sanity_check: false,
        writer_buf_kb: None,
        parallel_decrypt_min_kb: None,
        io_depth: None,
        no_profile: false,
        daemon: false,
        #[cfg(feature = "sample-aes")]
        aes128: false,
        #[cfg(feature = "sample-aes")]
        sample_aes_ts: false,
    }
}

#[derive(Debug, PartialEq, Eq)]
struct RawEditListEntry {
    segment_duration: u32,
    media_time: i32,
    media_rate_integer: i16,
    media_rate_fraction: i16,
}

fn find_elst_entries(data: &[u8]) -> Vec<RawEditListEntry> {
    let pos = data
        .windows(4)
        .position(|w| w == b"elst")
        .expect("expected an elst box in this MP4");

    let body = &data[pos + 4..];
    let version = body[0];
    assert_eq!(version, 0, "test fixture must use elst version 0");
    let entry_count = u32::from_be_bytes(body[4..8].try_into().unwrap());
    let mut entries = Vec::with_capacity(entry_count as usize);
    let mut off = 8usize;
    for _ in 0..entry_count {
        let e = &body[off..off + 12];
        entries.push(RawEditListEntry {
            segment_duration: u32::from_be_bytes(e[0..4].try_into().unwrap()),
            media_time: i32::from_be_bytes(e[4..8].try_into().unwrap()),
            media_rate_integer: i16::from_be_bytes(e[8..10].try_into().unwrap()),
            media_rate_fraction: i16::from_be_bytes(e[10..12].try_into().unwrap()),
        });
        off += 12;
    }
    entries
}

fn ffprobe_video_summary(path: &Path) -> Option<(f64, f64, usize)> {
    let out = Command::new("ffprobe")
        .args([
            "-v", "error", "-select_streams", "v:0", "-count_frames",
            "-show_entries", "stream=start_time,duration,nb_read_frames",
            "-of", "csv=p=0",
        ])
        .arg(path)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut parts = text.trim().split(',');
    let start_time: f64 = parts.next()?.parse().ok()?;
    let duration: f64 = parts.next()?.parse().ok()?;
    let frames: usize = parts.next()?.parse().ok()?;
    Some((start_time, duration, frames))
}

#[test]
fn progressive_remux_carries_a_video_edit_list_verbatim() {
    let src = fixture("video_edit_list.mp4");
    let src_bytes = std::fs::read(&src).unwrap();
    let src_entries = find_elst_entries(&src_bytes);
    assert_eq!(src_entries.len(), 1, "fixture must carry exactly one edit-list entry");
    assert!(src_entries[0].media_time > 0, "fixture must encode a leading (media_time > 0) trim");
    assert_ne!(src_entries[0].segment_duration, 0, "fixture must encode a bounded segment_duration");

    let out = unique_temp_path("video-edit-list-out.mp4");
    let args = base_args(src.clone(), out.clone());
    cli::run(args).expect("progressive remux must succeed on this unprotected fixture");

    let out_bytes = std::fs::read(&out).unwrap();
    let out_entries = find_elst_entries(&out_bytes);
    assert_eq!(
        out_entries, src_entries,
        "the video track's edit list must be carried into the output verbatim -- \
         segment_duration is non-zero in the source, so `set_track_durations`'s \
         zero-placeholder patch must not touch it either"
    );

    if let Some((start_time, duration, frames)) = ffprobe_video_summary(&out) {
        assert_eq!(frames, 40, "edit list must trim exactly the leading 10 samples, not the trailing ones");
        assert!((duration - 1.6).abs() < 0.01, "reported duration must match segment_duration ({duration})");
        assert!(start_time.abs() < 0.01, "reported start_time must be 0 (edit list already accounts for the trim)");
    } else {
        eprintln!("ffprobe not found on PATH -- skipping decoded-frame-count verification");
    }

    let _ = std::fs::remove_file(&out);
}
