//! `--dump -j`'s `residual_protection_boxes` field

use std::path::{Path, PathBuf};

use flux::cli::{self, Args};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}

fn unique_temp_path(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let (stem, ext) = name.rsplit_once('.').expect("output name must have an extension");
    std::env::temp_dir().join(format!("flux-test-{}-{stem}-{nanos}.{ext}", std::process::id()))
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

#[test]
fn flags_residual_protection_on_a_still_encrypted_asset() {
    let report = dump_json(&fixture("cenc_audio.mp4"));
    let streams = report["streams"].as_array().expect("streams array");
    assert_eq!(streams.len(), 1);
    assert_eq!(streams[0]["is_encrypted"], true);
    assert_eq!(
        streams[0]["residual_protection_boxes"], true,
        "a still-encrypted track's stsd (enca + sinf) must be flagged: {report}"
    );
}

#[test]
fn clears_residual_protection_after_flux_decrypts_it() {
    let out = unique_temp_path("cenc-audio-clean-out.mp4");
    let args = Args {
        help: None,
        version: None,
        in_positional: None,
        input: Some(fixture("cenc_audio.mp4")),
        output: Some(out.clone()),
        dump: false,
        json: false,
        extract_text: false,
        format: None,
        tracks: Vec::new(),
        keys: vec!["f8c80c25690f47368132430e5c6994ce:7bc99cb1dd0623cd0b5065056a57a1dd".to_string()],
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
    };
    cli::run(args).expect("cenc decrypt must succeed");

    let report = dump_json(&out);
    std::fs::remove_file(&out).ok();
    let streams = report["streams"].as_array().expect("streams array");
    assert_eq!(streams.len(), 1);
    assert_eq!(streams[0]["is_encrypted"], false);
    assert_eq!(
        streams[0]["residual_protection_boxes"], false,
        "a cleanly decrypted track must have no residual protection markers: {report}"
    );
}
