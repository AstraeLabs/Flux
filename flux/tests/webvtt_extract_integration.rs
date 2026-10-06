//! End-to-end `--extract-text` regression test against a real fMP4/wvtt asset

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

fn extract_text_args(input: PathBuf, output: PathBuf) -> Args {
    Args {
        help: None,
        version: None,
        in_positional: None,
        input: Some(input),
        output: Some(output),
        dump: false,
        json: false,
        extract_text: true,
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
        no_profile: true,
        daemon: false,
        #[cfg(feature = "sample-aes")]
        aes128: false,
        #[cfg(feature = "sample-aes")]
        sample_aes_ts: false,
    }
}

#[test]
fn extracts_a_real_wvtt_track_byte_for_byte_matching_the_gpac_reference() {
    let out = unique_temp_path("elephants-dream-out.vtt");
    let args = extract_text_args(fixture("webvtt_elephants_dream.mp4"), out.clone());
    cli::run(args).expect("--extract-text must succeed on a well-formed wvtt fixture");

    let vtt = std::fs::read_to_string(&out).expect("output .vtt must be readable UTF-8 text");
    std::fs::remove_file(&out).ok();

    assert!(vtt.starts_with("WEBVTT\n\n"), "must start with a bare WEBVTT header");

    assert_eq!(vtt.matches(" --> ").count(), 89, "cue count must match the MP4Box reference");

    assert!(
        vtt.contains("00:00:15.000 --> 00:00:18.000 align:start\n<v Proog>At the left we can see...</v>\n"),
        "first cue (text + timing + settings) must match the MP4Box reference verbatim:\n{vtt}"
    );

    assert!(
        vtt.contains("00:00:20.083 --> 00:00:22.000\n<v Proog>...the <c.highlight>head-snarlers</c></v>\n"),
        "a cue with no settings must render with no trailing settings text:\n{vtt}"
    );

    assert!(
        vtt.contains("00:09:05.000 --> 00:09:07.500\n(howling wind)\n"),
        "the final cue in the source track must be present -- fragment walking may have stopped early:\n{vtt}"
    );
}

#[test]
fn dump_recognizes_the_wvtt_track_and_reports_correct_sample_count() {
    let out = unique_temp_path("elephants-dream-dump-out.mp4");
    let mut args = extract_text_args(fixture("webvtt_elephants_dream.mp4"), out);
    args.extract_text = false;
    args.dump = true;
    args.json = true;

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_flux"))
        .args(["--dump", "-j", "-i"])
        .arg(fixture("webvtt_elephants_dream.mp4"))
        .output()
        .expect("failed to run flux binary");
    assert!(output.status.success(), "--dump must succeed: {}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"stream_type\": \"Subtitle\""), "must report the wvtt track as Subtitle:\n{stdout}");
    assert!(stdout.contains("\"codec_string\": \"wvtt\""), "must report the wvtt codec string:\n{stdout}");
    assert!(stdout.contains("\"sample_count\": 166"), "must report the real fragmented sample count:\n{stdout}");
}
