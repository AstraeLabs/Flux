
use std::path::{Path, PathBuf};
use std::process::Command;

use flux::cli::{self, Args};

fn unique_temp_path(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let (stem, ext) = name.rsplit_once('.').expect("fixture output name must have an extension");
    std::env::temp_dir().join(format!("flux-test-{}-{stem}-{nanos}.{ext}", std::process::id()))
}

fn base_args(input: PathBuf, output: PathBuf, keys: Vec<&str>) -> Args {
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
        keys: keys.into_iter().map(String::from).collect(),
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

fn ffmpeg_md5(path: &Path, extra_args: &[&str]) -> Option<String> {
    let mut cmd = Command::new("ffmpeg");
    cmd.args(["-v", "error", "-i"])
        .arg(path)
        .args(extra_args)
        .args(["-f", "md5", "-"]);
    let output = match cmd.output() {
        Ok(o) => o,
        Err(_) => {
            eprintln!("ffmpeg not found on PATH -- skipping checksum verification");
            return None;
        }
    };
    if !output.status.success() {
        panic!(
            "ffmpeg failed decoding {path:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Some(stdout.trim().trim_start_matches("MD5=").to_string())
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}


#[test]
fn cenc_audio_decrypts_and_matches_independently_decrypted_pcm() {
    const EXPECTED_PCM_MD5: &str = "1b7117f565f59cabebfe43a9c020db40";
    let out = unique_temp_path("cenc-audio-out.mp4");
    let args = base_args(
        fixture("cenc_audio.mp4"),
        out.clone(),
        vec!["f8c80c25690f47368132430e5c6994ce:7bc99cb1dd0623cd0b5065056a57a1dd"],
    );
    cli::run(args).expect("cenc decrypt must succeed");
    assert!(std::fs::metadata(&out).unwrap().len() > 0);

    if let Some(got) = ffmpeg_md5(&out, &["-f", "s16le"]) {
        assert_eq!(got, EXPECTED_PCM_MD5, "decrypted cenc audio PCM must match the independent reference decrypt");
    }
    let _ = std::fs::remove_file(&out);
}

#[test]
fn cbcs_audio_decrypts_and_matches_independently_decrypted_pcm() {
    const EXPECTED_PCM_MD5: &str = "1b7117f565f59cabebfe43a9c020db40";
    let out = unique_temp_path("cbcs-audio-out.mp4");
    let args = base_args(
        fixture("cbcs_audio.mp4"),
        out.clone(),
        vec!["f8c80c25690f47368132430e5c6994ce:7bc99cb1dd0623cd0b5065056a57a1dd"],
    );
    cli::run(args).expect("cbcs decrypt must succeed");
    assert!(std::fs::metadata(&out).unwrap().len() > 0);

    if let Some(got) = ffmpeg_md5(&out, &["-f", "s16le"]) {
        assert_eq!(got, EXPECTED_PCM_MD5, "decrypted cbcs audio PCM must match the independent reference decrypt");
    }
    let _ = std::fs::remove_file(&out);
}

#[test]
fn piff_uuid_box_decrypts_and_matches_independently_decrypted_video() {
    const EXPECTED_VIDEO_MD5: &str = "db66b93f4cdd08f3a0f3b80ed7c67f8c";
    let out = unique_temp_path("piff-uuid-out.mp4");
    let args = base_args(
        fixture("piff_uuid_senc.mp4"),
        out.clone(),
        vec!["09e367028f33436ca5dd60ffe6671e70:b42ca3172ee4e69bf51848a59db9cd13"],
    );
    cli::run(args).expect("PIFF uuid-box decrypt must succeed");
    assert!(std::fs::metadata(&out).unwrap().len() > 0);

    if let Some(got) = ffmpeg_md5(&out, &["-map", "0:v", "-f", "rawvideo"]) {
        assert_eq!(got, EXPECTED_VIDEO_MD5, "decrypted PIFF video must match the independent reference decrypt");
    }
    let _ = std::fs::remove_file(&out);
}

#[test]
fn fragments_info_bare_fragment_decrypts_and_stitches_into_playable_video() {
    const EXPECTED_VIDEO_MD5: &str = "b5839014b60774c45ffafb1b9ec5559b";

    let frag_out = unique_temp_path("piff-fragment-out.mp4");
    let args = Args {
        fragments_info: Some(fixture("piff_uuid_senc.mp4")),
        ..base_args(
            fixture("piff_raw_fragment.ismv"),
            frag_out.clone(),
            vec!["09e367028f33436ca5dd60ffe6671e70:b42ca3172ee4e69bf51848a59db9cd13"],
        )
    };
    cli::run(args).expect("--fragments-info bare-fragment decrypt must succeed");
    let decrypted_fragment = std::fs::read(&frag_out).unwrap();
    assert!(!decrypted_fragment.is_empty());
    let _ = std::fs::remove_file(&frag_out);

    let init_bytes = std::fs::read(fixture("piff_uuid_senc.mp4")).unwrap();
    let first_moof = find_first_moof_offset(&init_bytes).expect("init fixture must contain a moof");
    let mut stitched = init_bytes[..first_moof].to_vec();
    stitched.extend_from_slice(&decrypted_fragment);

    let stitched_path = unique_temp_path("piff-stitched.mp4");
    std::fs::write(&stitched_path, &stitched).unwrap();

    if let Some(got) = ffmpeg_md5(&stitched_path, &["-map", "0:v", "-f", "rawvideo"]) {
        assert_eq!(got, EXPECTED_VIDEO_MD5, "stitched fragments-info output must match the previously-verified reference");
    }
    let _ = std::fs::remove_file(&stitched_path);
}

fn find_first_moof_offset(data: &[u8]) -> Option<usize> {
    let mut off = 0usize;
    while off + 8 <= data.len() {
        let size = u32::from_be_bytes(data[off..off + 4].try_into().unwrap()) as usize;
        if &data[off + 4..off + 8] == b"moof" {
            return Some(off);
        }
        if size == 0 {
            break;
        }
        off += size;
    }
    None
}

fn top_level_box_offsets(data: &[u8]) -> Vec<([u8; 4], usize, usize)> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 8 <= data.len() {
        let size = u32::from_be_bytes(data[off..off + 4].try_into().unwrap()) as usize;
        if size < 8 {
            break;
        }
        let fourcc: [u8; 4] = data[off + 4..off + 8].try_into().unwrap();
        out.push((fourcc, off, size));
        off += size;
    }
    out
}

fn contains_box_type(data: &[u8], fourcc: &[u8; 4]) -> bool {
    data.windows(4).any(|w| w == fourcc)
}

fn first_traf_children(data: &[u8]) -> Vec<[u8; 4]> {
    let moof_off = find_first_moof_offset(data).expect("expected a moof in this output");
    let moof_size = u32::from_be_bytes(data[moof_off..moof_off + 4].try_into().unwrap()) as usize;
    let moof_body = &data[moof_off + 8..moof_off + moof_size];
    let mut fourccs = Vec::new();
    for (fourcc, off, size) in top_level_box_offsets(moof_body) {
        if &fourcc != b"traf" {
            continue;
        }
        let traf_body = &moof_body[off + 8..off + size];
        fourccs.extend(top_level_box_offsets(traf_body).into_iter().map(|(f, _, _)| f));
    }
    fourccs
}

#[test]
fn fragments_info_strips_senc_saiz_saio_but_keeps_sample_group_boxes() {
    let whole = std::fs::read(fixture("cenc_audio.mp4")).unwrap();
    let boxes = top_level_box_offsets(&whole);
    let styp_offsets: Vec<usize> =
        boxes.iter().filter(|(t, _, _)| t == b"styp").map(|(_, o, _)| *o).collect();
    assert!(styp_offsets.len() >= 2, "fixture must have at least 2 fragments to isolate the first one");
    let init_bytes = &whole[..styp_offsets[0]];
    let frag1_bytes = &whole[styp_offsets[0]..styp_offsets[1]];
    assert!(
        first_traf_children(frag1_bytes).contains(b"senc"),
        "fixture's first fragment must carry a real senc box (not just PIFF uuid) for this test to mean anything"
    );

    let init_path = unique_temp_path("cenc-audio-frag-init.mp4");
    let frag_path = unique_temp_path("cenc-audio-frag1.mp4");
    std::fs::write(&init_path, init_bytes).unwrap();
    std::fs::write(&frag_path, frag1_bytes).unwrap();

    let out = unique_temp_path("cenc-audio-frag1-out.mp4");
    let args = Args {
        fragments_info: Some(init_path.clone()),
        ..base_args(
            frag_path.clone(),
            out.clone(),
            vec!["f8c80c25690f47368132430e5c6994ce:7bc99cb1dd0623cd0b5065056a57a1dd"],
        )
    };
    cli::run(args).expect("--fragments-info decrypt of a standard-box CENC fragment must succeed");

    let decrypted_fragment = std::fs::read(&out).unwrap();
    let out_children = first_traf_children(&decrypted_fragment);
    for stripped in [b"senc", b"saiz", b"saio"] {
        assert!(
            !out_children.contains(stripped),
            "{:?} must be stripped from the decrypted fragment's traf",
            std::str::from_utf8(stripped).unwrap()
        );
    }
    for kept in [b"sgpd", b"sbgp", b"tfhd", b"tfdt", b"trun"] {
        assert!(
            out_children.contains(kept),
            "{:?} must survive stripping untouched",
            std::str::from_utf8(kept).unwrap()
        );
    }

    let stitched_path = unique_temp_path("cenc-audio-frag1-stitched.mp4");
    let mut stitched = init_bytes.to_vec();
    stitched.extend_from_slice(&decrypted_fragment);
    std::fs::write(&stitched_path, &stitched).unwrap();
    if let Some(_md5) = ffmpeg_md5(&stitched_path, &["-map", "0:a", "-f", "s16le"]) {
    } else {
        eprintln!("ffmpeg not found on PATH -- skipping decode verification");
    }

    for p in [&init_path, &frag_path, &out, &stitched_path] {
        let _ = std::fs::remove_file(p);
    }
}

#[test]
fn fragments_info_init_only_rewrites_encv_stsd_to_clear() {
    let init_bytes = std::fs::read(fixture("piff_uuid_senc.mp4")).unwrap();
    let first_moof = find_first_moof_offset(&init_bytes).expect("fixture must contain a moof");
    assert!(
        contains_box_type(&init_bytes[..first_moof], b"encv"),
        "fixture's own init segment must carry a protected (encv) stsd entry for this test to mean anything"
    );

    let init_only_path = unique_temp_path("piff-init-only.mp4");
    std::fs::write(&init_only_path, &init_bytes[..first_moof]).unwrap();

    let out = unique_temp_path("piff-init-only-out.mp4");
    let args = Args {
        fragments_info: Some(init_only_path.clone()),
        ..base_args(init_only_path.clone(), out.clone(), vec![])
    };
    cli::run(args).expect("--fragments-info init-only rewrite must succeed");

    let out_bytes = std::fs::read(&out).unwrap();
    assert!(!contains_box_type(&out_bytes, b"encv"), "output stsd must no longer carry encv");
    assert!(contains_box_type(&out_bytes, b"avc1"), "output stsd must carry a clear avc1 entry instead");

    let _ = std::fs::remove_file(&init_only_path);
    let _ = std::fs::remove_file(&out);
}
