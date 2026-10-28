
use std::path::{Path, PathBuf};
use std::process::Command;

use flux::cli::{self, Args};

fn corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/corpus")
}

fn unique_temp_dir(stem: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let dir = std::env::temp_dir().join(format!("flux-corpus-{}-{stem}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
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
        no_profile: true,
        daemon: false,
        #[cfg(feature = "sample-aes")]
        aes128: false,
        #[cfg(feature = "sample-aes")]
        sample_aes_ts: false,
    }
}

struct Entry {
    file: String,
    video: bool,
    keys: Vec<String>,
    packet_md5: String,
    also: Vec<(bool, String)>,
    first_tfdt: u64,
    wrong_key_refused: bool,
}

fn manifest() -> Vec<Entry> {
    let text = std::fs::read_to_string(corpus().join("manifest.json")).unwrap();
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    json.as_array()
        .unwrap()
        .iter()
        .map(|m| Entry {
            file: m["file"].as_str().unwrap().to_string(),
            video: m["kind"] == "video",
            keys: std::iter::once(format!("{}:{}", m["kid"].as_str().unwrap(), m["key"].as_str().unwrap()))
                .chain(m["extra_keys"].as_array().into_iter().flatten().map(|k| k.as_str().unwrap().to_string()))
                .collect(),
            packet_md5: m["packet_md5"].as_str().unwrap().trim_start_matches("MD5=").to_string(),
            also: m["also"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|a| (a["kind"] == "video", a["packet_md5"].as_str().unwrap().trim_start_matches("MD5=").to_string()))
                .collect(),
            first_tfdt: m["first_tfdt"].as_u64().unwrap_or(0),
            wrong_key_refused: m["wrong_key_refused"].as_bool().unwrap(),
        })
        .collect()
}

/// Odd chunk sizes: the first one holds the init and cuts the first moof in half, the rest straddle box headers.
fn write_chunks(dir: &Path, data: &[u8]) {
    let sizes = [1500usize, 7, 4093, 20_011, 9, 65_536];
    let (mut pos, mut n) = (0, 0);
    while pos < data.len() {
        let len = sizes[n % sizes.len()].min(data.len() - pos);
        std::fs::write(dir.join(format!("seg_{n:05}.mp4")), &data[pos..pos + len]).unwrap();
        pos += len;
        n += 1;
    }
}

fn concat_chunks(dir: &Path) -> Vec<u8> {
    let mut names: Vec<_> = std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
    names.sort();
    names.iter().flat_map(|n| std::fs::read(dir.join(n)).unwrap()).collect()
}

/// md5 of the clear packets of the first video/audio stream; `None` when ffmpeg is not installed.
fn packet_md5(path: &Path, video: bool) -> Option<String> {
    let out = Command::new("ffmpeg")
        .args(["-v", "error", "-i"])
        .arg(path)
        .args(["-map", if video { "0:v:0" } else { "0:a:0" }, "-c", "copy", "-f", "md5", "-"])
        .output()
        .ok()?;
    assert!(out.status.success(), "ffmpeg could not read {path:?}: {}", String::from_utf8_lossy(&out.stderr));
    Some(String::from_utf8_lossy(&out.stdout).trim().trim_start_matches("MD5=").to_string())
}

/// `tfdt` of the first fragment (box walk: moof > traf > tfdt).
fn first_tfdt(data: &[u8]) -> Option<u64> {
    let mut pos = 0usize;
    while pos + 8 <= data.len() {
        let size = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        if size < 8 {
            return None;
        }
        if &data[pos + 4..pos + 8] == b"moof" {
            let moof_end = pos + size;
            let mut traf = pos + 8;
            while traf + 8 <= moof_end {
                let tsize = u32::from_be_bytes(data[traf..traf + 4].try_into().unwrap()) as usize;
                if tsize < 8 {
                    return None;
                }
                if &data[traf + 4..traf + 8] == b"traf" {
                    let mut c = traf + 8;
                    while c + 8 <= traf + tsize {
                        let csize = u32::from_be_bytes(data[c..c + 4].try_into().unwrap()) as usize;
                        if csize < 8 {
                            return None;
                        }
                        if &data[c + 4..c + 8] == b"tfdt" {
                            let v1 = data[c + 8] == 1;
                            return Some(if v1 {
                                u64::from_be_bytes(data[c + 12..c + 20].try_into().unwrap())
                            } else {
                                u32::from_be_bytes(data[c + 12..c + 16].try_into().unwrap()) as u64
                            });
                        }
                        c += csize;
                    }
                }
                traf += tsize;
            }
            return None;
        }
        pos += size;
    }
    None
}

fn ffmpeg_available() -> bool {
    Command::new("ffmpeg").arg("-version").output().is_ok_and(|o| o.status.success())
}

fn check(entry: &Entry, mode: &str, out: &Path) {
    assert!(std::fs::metadata(out).unwrap().len() > 0, "{} [{mode}]: empty output", entry.file);
    let streams = std::iter::once((entry.video, &entry.packet_md5)).chain(entry.also.iter().map(|(v, m)| (*v, m)));
    for (video, want) in streams {
        if let Some(got) = packet_md5(out, video) {
            assert_eq!(&got, want, "{} [{mode}]: {} packets differ from the independent decrypt", entry.file, if video { "video" } else { "audio" });
        }
    }
}

#[test]
fn every_mode_matches_the_independent_decrypt() {
    if !ffmpeg_available() {
        eprintln!("ffmpeg not found on PATH -- the packet comparison against mp4decrypt is skipped");
    }
    let work = unique_temp_dir("modes");
    for entry in manifest() {
        let src = corpus().join(&entry.file);
        let data = std::fs::read(&src).unwrap();
        let keys = entry.keys.clone();

        // progressive, straight from the file
        let out = work.join(format!("{}.prog.mp4", entry.file));
        cli::run(Args { input: Some(src.clone()), output: Some(out.clone()), keys: keys.clone(), ..args() })
            .unwrap_or_else(|e| panic!("{} [progressive]: {e}", entry.file));
        check(&entry, "progressive", &out);

        // --chunks -o
        let chunks = work.join(format!("{}.chunks", entry.file));
        std::fs::create_dir_all(&chunks).unwrap();
        write_chunks(&chunks, &data);
        let out = work.join(format!("{}.chunks.mp4", entry.file));
        cli::run(Args { chunks: Some(chunks.clone()), output: Some(out.clone()), keys: keys.clone(), ..args() })
            .unwrap_or_else(|e| panic!("{} [--chunks -o]: {e}", entry.file));
        check(&entry, "--chunks -o", &out);
        assert_eq!(concat_chunks(&chunks), data, "{}: --chunks -o must not touch the chunks", entry.file);

        // --chunks -o --tfdt-rebase: same packets, timeline starts at 0 (also for 64-bit tfdt)
        let out = work.join(format!("{}.rebase.mp4", entry.file));
        cli::run(Args { chunks: Some(chunks.clone()), output: Some(out.clone()), keys: keys.clone(), tfdt_rebase: true, ..args() })
            .unwrap_or_else(|e| panic!("{} [--tfdt-rebase]: {e}", entry.file));
        check(&entry, "--tfdt-rebase", &out);
        // A file without any tfdt (GPAC omits it) must stay that way: the rebase moves timestamps, it adds none.
        let expected = first_tfdt(&data).map(|_| 0);
        assert_eq!(first_tfdt(&std::fs::read(&out).unwrap()), expected, "{}: rebase must start at 0 (was {})", entry.file, entry.first_tfdt);

        // --chunks --in-place
        cli::run(Args { chunks: Some(chunks.clone()), in_place: true, keys, ..args() })
            .unwrap_or_else(|e| panic!("{} [--in-place]: {e}", entry.file));
        let out = work.join(format!("{}.inplace.mp4", entry.file));
        std::fs::write(&out, concat_chunks(&chunks)).unwrap();
        check(&entry, "--in-place", &out);
    }
    let _ = std::fs::remove_dir_all(&work);
}

/// The 64-bit case must really be one: a tfdt that does not fit 32 bits.
#[test]
fn the_corpus_covers_a_64_bit_tfdt() {
    assert!(manifest().iter().any(|e| e.first_tfdt > u32::MAX as u64), "no fixture starts beyond 2^32");
}

/// Files whose wrong key is caught up front: audio (sync word / test decode) and H.264 (test decode of the sync
/// sample). HEVC is deliberately absent, see the README of the corpus: libavcodec often decodes garbage HEVC
/// slices without a message, so there the check is only probabilistic.
#[test]
fn a_wrong_key_is_refused_for_the_codecs_that_can_prove_it() {
    // Only (E-)AC-3 is judged without ffmpeg (sync word); AAC and H.264 are test-decoded by it.
    let ffmpeg = ffmpeg_available();
    if !ffmpeg {
        eprintln!("ffmpeg not found on PATH -- only the (E-)AC-3 files can be checked");
    }
    let work = unique_temp_dir("wrongkey");
    let mut checked = 0;
    for entry in manifest().into_iter().filter(|e| e.wrong_key_refused && (ffmpeg || e.file.contains("ac3"))) {
        let kid = entry.keys[0].split(':').next().unwrap();
        let data = std::fs::read(corpus().join(&entry.file)).unwrap();
        for seed in 1u8..=6 {
            let wrong = format!("{kid}:{}", format!("{:02x}", seed.wrapping_mul(37)).repeat(16));
            let chunks = work.join(format!("{}.{seed}", entry.file));
            std::fs::create_dir_all(&chunks).unwrap();
            write_chunks(&chunks, &data);
            let res = cli::run(Args { chunks: Some(chunks.clone()), in_place: true, keys: vec![wrong.clone()], ..args() });
            assert!(res.is_err(), "{}: wrong key {wrong} was accepted", entry.file);
            assert_eq!(concat_chunks(&chunks), data, "{}: a refused run must leave the chunks untouched", entry.file);
            checked += 1;
        }
    }
    assert!(checked >= if ffmpeg { 60 } else { 12 }, "expected to check many files, checked {checked}");
    let _ = std::fs::remove_dir_all(&work);
}

/// A file that rotates keys (`seig` sample groups naming a second KID) must never be decrypted with the
/// track's key alone: that yields wrong packets the sanity check cannot see. Without the second key the run
/// has to fail, with it every packet must match the clear source.
#[test]
fn a_rotating_file_without_its_second_key_is_refused() {
    let entry = manifest().into_iter().find(|e| e.file == "gpac_keyroll10_avc.mp4").expect("fixture in the manifest");
    assert_eq!(entry.keys.len(), 2, "the fixture needs two keys");
    let data = std::fs::read(corpus().join(&entry.file)).unwrap();
    let work = unique_temp_dir("rotation");

    let out = work.join("one-key.mp4");
    let res = cli::run(Args { input: Some(corpus().join(&entry.file)), output: Some(out), keys: entry.keys[..1].to_vec(), ..args() });
    assert!(res.is_err(), "progressive: decrypting a rotating file with one key must fail");

    let chunks = work.join("chunks");
    std::fs::create_dir_all(&chunks).unwrap();
    write_chunks(&chunks, &data);
    let res = cli::run(Args { chunks: Some(chunks.clone()), output: Some(work.join("one-key.chunks.mp4")), keys: entry.keys[..1].to_vec(), ..args() });
    assert!(res.is_err(), "--chunks: decrypting a rotating file with one key must fail");
    let res = cli::run(Args { chunks: Some(chunks.clone()), in_place: true, keys: entry.keys[..1].to_vec(), ..args() });
    assert!(res.is_err(), "--in-place: decrypting a rotating file with one key must fail");
    assert_eq!(concat_chunks(&chunks), data, "a refused --in-place run must leave the chunks untouched");
    let _ = std::fs::remove_dir_all(&work);
}
