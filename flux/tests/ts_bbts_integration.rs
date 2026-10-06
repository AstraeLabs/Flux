//! End-to-end regression test for the **experimental** BBTS variant 
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
const KID: &str = "00000000000000000000000000000001";
const KEY: &str = "0123456789abcdeffedcba9876543210";

fn ffmpeg_stream_md5(path: &Path, map: &str) -> Option<String> {
    let output = Command::new("ffmpeg")
        .args(["-v", "error", "-i"])
        .arg(path)
        .args(["-map", map, "-f", "md5", "-"])
        .output()
        .ok()?;
    if !output.status.success() {
        panic!("ffmpeg failed decoding {path:?} ({map}): {}", String::from_utf8_lossy(&output.stderr));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Some(stdout.trim().trim_start_matches("MD5=").to_string())
}

fn run_sample_aes_ts(input: PathBuf, output: PathBuf) {
    let args = Args {
        help: None,
        version: None,
        in_positional: None,
        input: Some(input),
        output: Some(output),
        dump: false,
        json: false,
        extract_text: false,
        format: Some(cli::FormatArg::Progressive),
        tracks: Vec::new(),
        keys: vec![format!("{KID}:{KEY}")],
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
        sample_aes_ts: true,
    };
    cli::run(args).expect("--sample-aes-ts BBTS decrypt must succeed on the synthetic fixture");
}

#[test]
fn ts_bbts_decrypt_matches_the_original_clear_source_checksums() {
    const EXPECTED_VIDEO_MD5: &str = "9fd4d2df5086889ba95c9c33a15ea49b";
    const EXPECTED_AUDIO_MD5: &str = "d126103e6db02b50f8d2c76beb8e45db";

    let out = unique_temp_path("ts-bbts-out.ts");
    run_sample_aes_ts(fixture("synthetic_bbts.ts"), out.clone());
    assert!(std::fs::metadata(&out).unwrap().len() > 0);

    if let Some(got) = ffmpeg_stream_md5(&out, "0:v") {
        assert_eq!(got, EXPECTED_VIDEO_MD5, "decrypted video must match the original clear source");
    }
    if let Some(got) = ffmpeg_stream_md5(&out, "0:a") {
        assert_eq!(got, EXPECTED_AUDIO_MD5, "decrypted audio must match the original clear source");
    }
    let _ = std::fs::remove_file(&out);
}

#[test]
fn ts_bbts_encrypt_then_decrypt_round_trips_byte_identical() {
    let encrypted = unique_temp_path("ts-bbts-roundtrip-enc.ts");
    let decrypted = unique_temp_path("ts-bbts-roundtrip-dec.ts");
    run_sample_aes_ts(fixture("synthetic_bbts.ts"), encrypted.clone());
    run_sample_aes_ts(encrypted.clone(), decrypted.clone());

    let original = std::fs::read(fixture("synthetic_bbts.ts")).unwrap();
    let twice_decrypted = std::fs::read(&decrypted).unwrap();
    assert_eq!(original, twice_decrypted, "double-decrypt must reproduce the original fixture byte-for-byte");

    let _ = std::fs::remove_file(&encrypted);
    let _ = std::fs::remove_file(&decrypted);
}
