//! Edit-list `media_time` must follow a media-timescale change made while remuxing to progressive

use std::path::{Path, PathBuf};

use flux::cli::{self, Args};

const KEY: &str = "f8c80c25690f47368132430e5c6994ce:7bc99cb1dd0623cd0b5065056a57a1dd";
const SAFE_MAX_TRACK_TICKS: u64 = 1 << 31;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}

fn unique_temp_path(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let (stem, ext) = name.rsplit_once('.').expect("output name must have an extension");
    std::env::temp_dir().join(format!("flux-test-{}-{stem}-{nanos}.{ext}", std::process::id()))
}

fn base_args(input: PathBuf, output: PathBuf, keys: Vec<String>) -> Args {
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
        keys,
        fragments_info: None,
        ffmpeg_path: None,
        key_sanity_check: false,
        skip_key_sanity_check: true,
        writer_buf_kb: None,
        parallel_decrypt_min_kb: None,
        io_depth: None,
        no_profile: true,
        daemon: false,
        #[cfg(feature = "sample-aes")]
        aes128: false,
        #[cfg(feature = "sample-aes")]
        sample_aes_ts: false,
    }
}

fn dump_json(input: &Path) -> serde_json::Value {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_flux"))
        .args(["--dump", "-j", "-i"])
        .arg(input)
        .output()
        .expect("failed to run flux binary");
    assert!(output.status.success(), "--dump must succeed: {}", String::from_utf8_lossy(&output.stderr));
    serde_json::from_slice(&output.stdout).expect("--dump -j must print valid JSON")
}

fn positions(data: &[u8], fourcc: &[u8; 4]) -> Vec<usize> {
    data.windows(4).enumerate().filter(|(_, w)| *w == fourcc).map(|(i, _)| i).collect()
}

fn be32(data: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(data[at..at + 4].try_into().unwrap())
}

fn put32(data: &mut [u8], at: usize, v: u32) {
    data[at..at + 4].copy_from_slice(&v.to_be_bytes());
}

/// Offset of the `mdhd` timescale field (version 0), `idx`-th track
fn mdhd_timescale_at(data: &[u8], idx: usize) -> usize {
    assert_eq!(data[positions(data, b"mdhd")[idx] + 4], 0, "tests use mdhd version 0");
    positions(data, b"mdhd")[idx] + 4 + 4 + 8
}

/// Offset of the first elst entry's `media_time` field (version 0)
fn elst_media_time_at(data: &[u8]) -> usize {
    let pos = positions(data, b"elst")[0];
    assert_eq!(data[pos + 4], 0, "tests use elst version 0");
    pos + 4 + 4 + 4 + 4
}

fn elst_segment_duration(data: &[u8]) -> u32 {
    be32(data, elst_media_time_at(data) - 4)
}

fn rescaled(media_time: u32, old_ts: u32, new_ts: u32) -> u32 {
    ((u64::from(media_time) * u64::from(new_ts) + u64::from(old_ts) / 2) / u64::from(old_ts)) as u32
}

/// Progressive input: stts deltas inflated so the track overflows a 32-bit tick budget
fn inflated_video() -> (PathBuf, u32, u32, u32) {
    let mut data = std::fs::read(fixture("video_edit_list.mp4")).unwrap();
    let stts = positions(&data, b"stts")[0];
    assert_eq!(be32(&data, stts + 8), 1, "fixture must have a single stts entry");
    let count = be32(&data, stts + 12);
    put32(&mut data, stts + 16, (SAFE_MAX_TRACK_TICKS * 2 / u64::from(count)) as u32);

    let old_ts = be32(&data, mdhd_timescale_at(&data, 0));
    let old_media_time = be32(&data, elst_media_time_at(&data));
    assert!(old_media_time > 0, "fixture must carry a leading trim");
    let seg = elst_segment_duration(&data);

    let path = unique_temp_path("video-inflated-in.mp4");
    std::fs::write(&path, &data).unwrap();
    (path, old_ts, old_media_time, seg)
}

#[test]
fn progressive_video_edit_list_follows_a_rescaled_timescale() {
    let (src, old_ts, old_media_time, old_seg) = inflated_video();
    let out = unique_temp_path("video-inflated-out.mp4");
    cli::run(base_args(src.clone(), out.clone(), Vec::new())).expect("remux must succeed");

    let bytes = std::fs::read(&out).unwrap();
    let new_ts = be32(&bytes, mdhd_timescale_at(&bytes, 0));
    assert!(new_ts < old_ts, "the overflowing track must have been rescaled ({old_ts} -> {new_ts})");
    assert_eq!(
        be32(&bytes, elst_media_time_at(&bytes)),
        rescaled(old_media_time, old_ts, new_ts),
        "media_time must be re-expressed in the new media timescale"
    );
    assert_eq!(elst_segment_duration(&bytes), old_seg, "segment_duration is in the movie timescale and must not change");

    std::fs::remove_file(&src).ok();
    std::fs::remove_file(&out).ok();
}

/// Fragmented audio input claiming a 10 MHz timescale with very long samples and a 10 MHz priming trim (Rakuten/Smooth style)
fn inflated_audio() -> PathBuf {
    let mut data = std::fs::read(fixture("cenc_audio.mp4")).unwrap();
    assert_eq!(be32(&data, mdhd_timescale_at(&data, 0)), 48_000);
    let mdhd_at = mdhd_timescale_at(&data, 0);
    put32(&mut data, mdhd_at, 10_000_000);
    let elst_at = elst_media_time_at(&data);
    put32(&mut data, elst_at, 426_667);
    for tfhd in positions(&data, b"tfhd") {
        // flags 0x20028 -> default_sample_duration sits right after the track_id
        put32(&mut data, tfhd + 4 + 4 + 4, 20_000_000);
    }
    let path = unique_temp_path("audio-inflated-in.mp4");
    std::fs::write(&path, &data).unwrap();
    path
}

#[test]
fn audio_keeps_its_sample_rate_as_timescale_and_a_matching_priming() {
    let src = inflated_audio();
    let out = unique_temp_path("audio-inflated-out.mp4");
    cli::run(base_args(src.clone(), out.clone(), vec![KEY.to_string()])).expect("decrypt must succeed");

    let bytes = std::fs::read(&out).unwrap();
    assert_eq!(be32(&bytes, mdhd_timescale_at(&bytes, 0)), 48_000, "audio must fall back to its sampling rate, not an arbitrary timescale");
    // 426667 / 10 MHz = 42.67 ms = the 2048-sample AAC priming
    assert_eq!(be32(&bytes, elst_media_time_at(&bytes)), 2048);

    let report = dump_json(&out);
    let stream = &report["streams"][0];
    assert_eq!(stream["time_scale"], 48_000);
    assert!(stream.get("edit_list_timescale_mismatch").is_none(), "{report}");

    std::fs::remove_file(&src).ok();
    std::fs::remove_file(&out).ok();
}

#[test]
fn untouched_timescale_leaves_the_edit_list_byte_identical() {
    let src = fixture("cenc_audio.mp4");
    let out = unique_temp_path("audio-plain-out.mp4");
    cli::run(base_args(src.clone(), out.clone(), vec![KEY.to_string()])).expect("decrypt must succeed");

    let src_bytes = std::fs::read(&src).unwrap();
    let bytes = std::fs::read(&out).unwrap();
    assert_eq!(be32(&bytes, mdhd_timescale_at(&bytes, 0)), 48_000);
    assert_eq!(be32(&bytes, elst_media_time_at(&bytes)), be32(&src_bytes, elst_media_time_at(&src_bytes)));
    std::fs::remove_file(&out).ok();
}

#[test]
fn dump_reports_the_edit_list_and_the_audio_timescale_mismatch() {
    let src = inflated_audio();
    let report = dump_json(&src);
    std::fs::remove_file(&src).ok();

    assert_eq!(report["movie_timescale"].as_u64().is_some(), true, "{report}");
    let stream = &report["streams"][0];
    assert_eq!(stream["time_scale"], 10_000_000);
    let edits = stream["edit_list"].as_array().expect("edit_list must be reported");
    assert_eq!(edits.len(), 1);
    assert_eq!(edits[0]["media_time"], 426_667);
    assert!((edits[0]["media_time_seconds"].as_f64().unwrap() - 0.0426667).abs() < 1e-6);
    assert_eq!(edits[0]["media_rate"], 1.0);
    assert_eq!(stream["edit_list_timescale_mismatch"], true, "{report}");
}

#[test]
fn dump_does_not_flag_a_consistent_audio_track_or_a_video_track() {
    let audio = dump_json(&fixture("cenc_audio.mp4"));
    let a = &audio["streams"][0];
    assert!(a.get("edit_list_timescale_mismatch").is_none(), "{audio}");
    assert_eq!(a["edit_list"][0]["media_time"], 5058);

    let video = dump_json(&fixture("video_edit_list.mp4"));
    let v = &video["streams"][0];
    assert_eq!(v["stream_type"], "Video");
    assert!(v["edit_list"][0]["media_time"].as_i64().unwrap() > 0);
    assert!(v.get("edit_list_timescale_mismatch").is_none(), "{video}");
}
