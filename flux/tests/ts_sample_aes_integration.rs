//! End-to-end regression test for the **experimental** `--sample-aes-ts`

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

const KEY: &str = "000102030405060708090a0b0c0d0e0f";
const IV: &str = "101112131415161718191a1b1c1d1e1f";

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

#[test]
fn ts_sample_aes_decrypt_matches_the_independently_encrypted_source_checksums() {
    const EXPECTED_VIDEO_MD5: &str = "fcd4992d4964dec2c36dbafc663176cb";
    const EXPECTED_AUDIO_MD5: &str = "59babbc7d973b888c1775f141aa655b2";

    let out = unique_temp_path("ts-sample-aes-out.ts");
    let args = Args {
        help: None,
        version: None,
        in_positional: None,
        input: Some(fixture("synthetic_sample_aes.ts")),
        output: Some(out.clone()),
        dump: false,
        json: false,
        extract_text: false,
        format: Some(cli::FormatArg::Progressive),
        tracks: Vec::new(),
        keys: vec![format!("{IV}:{KEY}")],
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
    cli::run(args).expect("--sample-aes-ts decrypt must succeed on the synthetic fixture");
    assert!(std::fs::metadata(&out).unwrap().len() > 0);

    if let Some(got) = ffmpeg_stream_md5(&out, "0:v") {
        assert_eq!(got, EXPECTED_VIDEO_MD5, "decrypted video must match the independently-encrypted source");
    }
    if let Some(got) = ffmpeg_stream_md5(&out, "0:a") {
        assert_eq!(got, EXPECTED_AUDIO_MD5, "decrypted audio must match the independently-encrypted source");
    }
    let _ = std::fs::remove_file(&out);
}
