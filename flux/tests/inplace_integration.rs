use std::path::{Path, PathBuf};
use std::process::Command;

use flux::cli::{self, Args};

const KEY: &str = "f8c80c25690f47368132430e5c6994ce:7bc99cb1dd0623cd0b5065056a57a1dd";
const EXPECTED_AUDIO_PACKETS_MD5: &str = "283ab05f361c3ed6ea5f2ec55b2247f4";

fn unique_temp_dir(stem: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("flux-inplace-{}-{stem}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}

fn args() -> Args {
    Args {
        help: None,
        version: None,
        in_positional: None,
        input: None,
        output: None,
        chunks: None,
        in_place: false,
        tfdt_rebase: false,
        tfdt_base: None,
        dump: false,
        json: false,
        extract_text: false,
        format: None,
        tracks: Vec::new(),
        keys: vec![KEY.to_string()],
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

/// Split `data` into `seg_<n>.mp4` files of uneven sizes, so that box headers and samples
/// straddle the chunk boundaries.
fn write_chunks(dir: &Path, data: &[u8]) {
    let sizes = [1usize, 7, 4093, 100_003, 9, 65_536];
    let mut pos = 0;
    let mut n = 0;
    while pos < data.len() {
        let len = sizes[n % sizes.len()].min(data.len() - pos);
        std::fs::write(dir.join(format!("seg_{n:05}.mp4")), &data[pos..pos + len]).unwrap();
        pos += len;
        n += 1;
    }
}

fn concat_chunks(dir: &Path) -> Vec<u8> {
    let mut names: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names.iter().flat_map(|n| std::fs::read(dir.join(n)).unwrap()).collect()
}

fn ffmpeg_audio_packets_md5(path: &Path) -> Option<String> {
    let out = Command::new("ffmpeg")
        .args(["-v", "error", "-i"])
        .arg(path)
        .args(["-map", "0:a:0", "-c", "copy", "-f", "md5", "-"])
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().trim_start_matches("MD5=").to_string())
}

#[test]
fn in_place_single_file_keeps_size_and_decrypts() {
    let dir = unique_temp_dir("single");
    let target = dir.join("cenc_audio.mp4");
    std::fs::copy(fixture("cenc_audio.mp4"), &target).unwrap();
    let before = std::fs::metadata(&target).unwrap().len();

    cli::run(Args { input: Some(target.clone()), in_place: true, ..args() }).expect("in-place decrypt");

    assert_eq!(std::fs::metadata(&target).unwrap().len(), before, "in-place must keep the size");
    assert_ne!(std::fs::read(&target).unwrap(), std::fs::read(fixture("cenc_audio.mp4")).unwrap());
    if let Some(got) = ffmpeg_audio_packets_md5(&target) {
        assert_eq!(got, EXPECTED_AUDIO_PACKETS_MD5);
    }

    let again = cli::run(Args { input: Some(target.clone()), in_place: true, ..args() });
    assert!(again.is_err(), "a second pass over decrypted data must be refused");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn chunks_match_the_single_file_result_in_both_modes() {
    let original = std::fs::read(fixture("cenc_audio.mp4")).unwrap();

    let single = unique_temp_dir("ref");
    let single_file = single.join("a.mp4");
    std::fs::write(&single_file, &original).unwrap();
    cli::run(Args { input: Some(single_file.clone()), in_place: true, ..args() }).unwrap();
    let expected = std::fs::read(&single_file).unwrap();

    // --chunks -o
    let chunks = unique_temp_dir("chunks-out");
    write_chunks(&chunks, &original);
    let out = single.join("merged.mp4");
    cli::run(Args { chunks: Some(chunks.clone()), output: Some(out.clone()), ..args() }).unwrap();
    assert_eq!(std::fs::read(&out).unwrap(), expected, "--chunks -o");
    assert_eq!(concat_chunks(&chunks), original, "--chunks -o must not touch the chunks");

    // --chunks --in-place
    let chunks2 = unique_temp_dir("chunks-ip");
    write_chunks(&chunks2, &original);
    cli::run(Args { chunks: Some(chunks2.clone()), in_place: true, ..args() }).unwrap();
    assert_eq!(concat_chunks(&chunks2), expected, "--chunks --in-place");

    for d in [single, chunks, chunks2] {
        let _ = std::fs::remove_dir_all(d);
    }
}

#[test]
fn truncated_or_gapped_chunks_are_refused_without_writing() {
    let original = std::fs::read(fixture("cenc_audio.mp4")).unwrap();

    let truncated = unique_temp_dir("trunc");
    write_chunks(&truncated, &original[..original.len() - 100]);
    let before = concat_chunks(&truncated);
    let res = cli::run(Args { chunks: Some(truncated.clone()), in_place: true, ..args() });
    assert!(res.is_err(), "a truncated download must be refused");
    assert_eq!(concat_chunks(&truncated), before, "a refused run must not modify the chunks");

    let gapped = unique_temp_dir("gap");
    write_chunks(&gapped, &original);
    std::fs::remove_file(gapped.join("seg_00001.mp4")).unwrap();
    let res = cli::run(Args { chunks: Some(gapped.clone()), in_place: true, ..args() });
    assert!(res.is_err(), "a gap in the numbering must be refused");

    for d in [truncated, gapped] {
        let _ = std::fs::remove_dir_all(d);
    }
}

fn ffmpeg_available() -> bool {
    Command::new("ffmpeg").arg("-version").output().is_ok_and(|o| o.status.success())
}

#[test]
fn wrong_key_on_aac_audio_is_refused_before_anything_is_written() {
    if !ffmpeg_available() {
        eprintln!("ffmpeg not found on PATH -- skipping the AAC wrong-key check");
        return;
    }
    let dir = unique_temp_dir("aac-key");
    let target = dir.join("cenc_audio.mp4");
    std::fs::copy(fixture("cenc_audio.mp4"), &target).unwrap();
    let before = std::fs::read(&target).unwrap();

    let wrong = Args {
        input: Some(target.clone()),
        in_place: true,
        keys: vec!["f8c80c25690f47368132430e5c6994ce:00112233445566778899aabbccddeeff".to_string()],
        ..args()
    };
    match cli::run(wrong) {
        Err(cli::CliError::KeySanityCheckFailed { .. }) => {}
        other => panic!("expected KeySanityCheckFailed, got {other:?}"),
    }
    assert_eq!(std::fs::read(&target).unwrap(), before, "a refused run must not modify the file");

    cli::run(Args { input: Some(target.clone()), in_place: true, ..args() })
        .expect("the right key must pass the AAC check");
    let _ = std::fs::remove_dir_all(&dir);
}
#[test]
fn iv_in_mdat_fragments_are_refused_with_the_file_untouched() {
    let dir = unique_temp_dir("aux-mdat");
    let target = dir.join("aux_in_mdat.mp4");
    let mut bytes = std::fs::read(fixture("cenc_audio.mp4")).unwrap();
    let mut hidden = 0;
    for i in 0..bytes.len().saturating_sub(4) {
        if &bytes[i..i + 4] == b"senc" {
            bytes[i..i + 4].copy_from_slice(b"free");
            hidden += 1;
        }
    }
    assert!(hidden > 0, "fixture no longer contains senc boxes");
    std::fs::write(&target, &bytes).unwrap();
    let before = bytes;

    let res = cli::run(Args { input: Some(target.clone()), in_place: true, ..args() });
    let err = res.expect_err("IV-in-mdat must be refused").to_string();
    assert!(err.contains("IVs in mdat"), "unexpected error: {err}");
    assert_eq!(std::fs::read(&target).unwrap(), before);
    let _ = std::fs::remove_dir_all(&dir);
}

/// `(value_offset, width)` of every tfdt in the file, in document order.
fn tfdt_all(data: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut off = 0;
    while off + 8 <= data.len() {
        let size = u32::from_be_bytes(data[off..off + 4].try_into().unwrap()) as usize;
        let ty = &data[off + 4..off + 8];
        if size < 8 || off + size > data.len() {
            break;
        }
        if ty == b"moof" {
            let mut pos = off + 8;
            while pos + 8 <= off + size {
                let tty = &data[pos + 4..pos + 8];
                let tsize = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
                if tsize < 8 || pos + tsize > off + size {
                    break;
                }
                if tty == b"traf" {
                    let mut c = pos + 8;
                    while c + 8 <= pos + tsize {
                        let ctty = &data[c + 4..c + 8];
                        let csize = u32::from_be_bytes(data[c..c + 4].try_into().unwrap()) as usize;
                        if csize < 8 || c + csize > pos + tsize {
                            break;
                        }
                        if ctty == b"tfdt" && c + 12 <= c + csize {
                            let version = data[c + 8];
                            let width = usize::from(version == 1) + 4;
                            let value_off = c + 12;
                            if value_off + width <= c + csize {
                                out.push((value_off, width));
                            }
                        }
                        c += csize;
                    }
                }
                pos += tsize;
            }
        }
        off += size;
    }
    out
}

fn read_tfdt(data: &[u8], value_off: usize, width: usize) -> u64 {
    match width {
        8 => u64::from_be_bytes(data[value_off..value_off + 8].try_into().unwrap()),
        _ => u64::from(u32::from_be_bytes(data[value_off..value_off + 4].try_into().unwrap())),
    }
}

fn patch_tfdt(data: &mut [u8], value_off: usize, width: usize, new_value: u64) {
    if width == 8 {
        data[value_off..value_off + width].copy_from_slice(&new_value.to_be_bytes());
    } else {
        data[value_off..value_off + width]
            .copy_from_slice(&(new_value.min(u64::from(u32::MAX)) as u32).to_be_bytes());
    }
}

#[test]
fn tfdt_rebase_output_matches_the_python_semantics() {
    let mut original = std::fs::read(fixture("cenc_audio.mp4")).unwrap();
    let original_tfdt = tfdt_all(&original);
    assert!(!original_tfdt.is_empty(), "the fixture must carry tfdt boxes");
    // The fixture starts at tfdt 0, which would make the rebase an identity. Shift every tfdt by an
    // absolute, live-stream-like offset (tfdt sits in the clear moof, outside the encrypted samples).
    for &(off, width) in &original_tfdt {
        let value = read_tfdt(&original, off, width);
        patch_tfdt(&mut original, off, width, value + 3_600_000);
    }
    assert!(read_tfdt(&original, original_tfdt[0].0, original_tfdt[0].1) > 1);

    let dir = unique_temp_dir("tfdt");

    // Reference: plain decrypt, then what the Python-side rebase CPU arithmetic
    // (rebase_fragment_timestamps) would produce: new_value = max(0, value - first_tfdt).
    // (The whole file as one chunk keeps the output a fragmented MP4, which is what the rebase applies to.)
    let plain = dir.join("plain");
    std::fs::create_dir_all(&plain).unwrap();
    std::fs::write(plain.join("seg_00000.mp4"), &original).unwrap();
    let ref_file = dir.join("plain.dec");
    cli::run(Args {
        chunks: Some(plain.clone()),
        output: Some(ref_file.clone()),
        ..args()
    })
    .expect("plain --chunks -o decrypt");
    let mut reference = std::fs::read(&ref_file).unwrap();
    let all = tfdt_all(&reference);
    assert!(all.len() >= original_tfdt.len().min(1), "decrypted fMP4 must keep its tfdt boxes");
    let (first_off, first_width) = all[0];
    let base = read_tfdt(&reference, first_off, first_width);
    for (value_off, width) in all {
        let cur = read_tfdt(&reference, value_off, width);
        patch_tfdt(&mut reference, value_off, width, cur.saturating_sub(base));
    }

    // --chunks -o --tfdt-rebase must match that reference byte for byte.
    let chunks = dir.join("chunks");
    std::fs::create_dir_all(&chunks).unwrap();
    write_chunks(&chunks, &original);
    let out = dir.join("rebased.dec");
    cli::run(Args {
        chunks: Some(chunks.clone()),
        output: Some(out.clone()),
        tfdt_rebase: true,
        ..args()
    })
    .expect("--chunks --tfdt-rebase decrypt");
    assert_eq!(
        std::fs::read(&out).unwrap(),
        reference,
        "--tfdt-rebase output must equal plain decrypt + Python rebase arithmetic"
    );
    assert_eq!(concat_chunks(&chunks), original, "the chunks must never be touched");

    // --chunks --in-place --tfdt-rebase writes the same rebased bytes where they are.
    write_chunks(&chunks, &original);
    cli::run(Args {
        chunks: Some(chunks.clone()),
        in_place: true,
        tfdt_rebase: true,
        ..args()
    })
    .expect("--chunks --in-place --tfdt-rebase decrypt");
    assert_eq!(concat_chunks(&chunks), reference, "in-place rebase must rewrite tfdt where it is");

    let _ = std::fs::remove_dir_all(&dir);
}

// ---- `-o -` (stdout) ------------------------------------------------------------------------------

fn flux_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_flux"))
}

#[test]
fn stdout_is_refused_on_a_terminal() {
    assert!(flux::cli::ensure_stdout_is_not_a_terminal(false).is_ok());
    let err = flux::cli::ensure_stdout_is_not_a_terminal(true).expect_err("a terminal must be refused");
    assert!(err.to_string().contains("terminal"), "unexpected message: {err}");
}

#[test]
fn stdout_pipe_carries_exactly_the_bytes_of_the_file_output() {
    let dir = unique_temp_dir("stdout");
    let chunks = dir.join("chunks");
    std::fs::create_dir_all(&chunks).unwrap();
    write_chunks(&chunks, &std::fs::read(fixture("cenc_audio.mp4")).unwrap());

    for extra in [&[][..], &["--tfdt-rebase"][..]] {
        let file_out = dir.join("file.mp4");
        let status = flux_bin()
            .args(["--no-profile", "--chunks"])
            .arg(&chunks)
            .arg("-o")
            .arg(&file_out)
            .args(["--key", KEY])
            .args(extra)
            .output()
            .unwrap();
        assert!(status.status.success(), "file mode failed: {}", String::from_utf8_lossy(&status.stderr));

        // Output::stdout is a pipe: this is the same situation as `flux ... | ffmpeg -i -`.
        let piped = flux_bin()
            .args(["--no-profile", "--chunks"])
            .arg(&chunks)
            .args(["-o", "-", "--key", KEY])
            .args(extra)
            .output()
            .unwrap();
        assert!(piped.status.success(), "stdout mode failed: {}", String::from_utf8_lossy(&piped.stderr));
        assert_eq!(piped.stdout, std::fs::read(&file_out).unwrap(), "-o - must equal -o FILE ({extra:?})");
    }
    assert_eq!(concat_chunks(&chunks), std::fs::read(fixture("cenc_audio.mp4")).unwrap());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn stdout_mode_prints_nothing_but_media_on_stdout_when_it_fails() {
    let dir = unique_temp_dir("stdout-fail");
    let chunks = dir.join("chunks");
    std::fs::create_dir_all(&chunks).unwrap();
    let original = std::fs::read(fixture("cenc_audio.mp4")).unwrap();
    write_chunks(&chunks, &original[..original.len() - 100]);

    let piped = flux_bin().args(["--no-profile", "--chunks"]).arg(&chunks).args(["-o", "-", "--key", KEY]).output().unwrap();
    assert!(!piped.status.success(), "a truncated input must fail");
    assert!(piped.stdout.is_empty(), "a refused run must not emit partial media on stdout");
    assert!(!piped.stderr.is_empty(), "the reason must be on stderr");
    let _ = std::fs::remove_dir_all(&dir);
}
