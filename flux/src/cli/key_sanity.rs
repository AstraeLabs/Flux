//! Best-effort "did we decrypt with the right key" check.

use std::io::Write;
use std::process::{Command, Stdio};

fn ffmpeg_raw_format(cfg: &crate::CodecConfig) -> Option<(&'static str, u8)> {
    match cfg {
        crate::CodecConfig::Avc { config, .. } => Some(("h264", config.config.length_size_minus_one + 1)),
        crate::CodecConfig::Hevc { config, .. } => Some(("hevc", config.config.length_size_minus_one + 1)),
        _ => None,
    }
}

fn append_sample_as_annexb(out: &mut Vec<u8>, sample: &[u8], length_size: u8) {
    let length_size = length_size as usize;
    let mut p = 0usize;
    while p + length_size <= sample.len() {
        let mut nal_len = 0usize;
        for b in &sample[p..p + length_size] {
            nal_len = (nal_len << 8) | *b as usize;
        }
        p += length_size;
        if nal_len == 0 || p + nal_len > sample.len() {
            break;
        }
        out.extend_from_slice(&[0, 0, 0, 1]);
        out.extend_from_slice(&sample[p..p + nal_len]);
        p += nal_len;
    }
}

fn parameter_sets_annexb(cfg: &crate::CodecConfig) -> Vec<u8> {
    let mut out = Vec::new();
    match cfg {
        crate::CodecConfig::Avc { config, .. } => {
            for sps in &config.config.sps {
                out.extend_from_slice(&[0, 0, 0, 1]);
                out.extend_from_slice(&sps.0);
            }
            for pps in &config.config.pps {
                out.extend_from_slice(&[0, 0, 0, 1]);
                out.extend_from_slice(&pps.0);
            }
        }
        crate::CodecConfig::Hevc { config, .. } => {
            for array in &config.config.arrays {
                for nalu in &array.nalus {
                    out.extend_from_slice(&[0, 0, 0, 1]);
                    out.extend_from_slice(&nalu.0);
                }
            }
        }
        _ => {}
    }
    out
}

pub(crate) fn check_first_sample(
    cfg: &crate::CodecConfig,
    first_sample: &[u8],
    ffmpeg_path: Option<&std::path::Path>,
) -> Result<Option<()>, String> {
    let Some((ffmpeg_fmt, length_size)) = ffmpeg_raw_format(cfg) else {
        return Ok(None);
    };
    let mut annexb = parameter_sets_annexb(cfg);
    let params_len = annexb.len();
    append_sample_as_annexb(&mut annexb, first_sample, length_size);
    if annexb.len() == params_len {
        return Ok(None);
    }

    let ffmpeg_bin: std::path::PathBuf = match ffmpeg_path {
        Some(p) => p.to_path_buf(),
        None => std::path::PathBuf::from("ffmpeg"),
    };

    let mut child = match Command::new(&ffmpeg_bin)
        .args(["-v", "error", "-f", ffmpeg_fmt, "-i", "-", "-f", "null", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return Ok(None),
    };

    let mut stdin = match child.stdin.take() {
        Some(s) => s,
        None => return Ok(None),
    };
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&annexb);
    });

    let output = match child.wait_with_output() {
        Ok(o) => o,
        Err(_) => {
            let _ = writer.join();
            return Ok(None);
        }
    };
    let _ = writer.join();

    let stderr = String::from_utf8_lossy(&output.stderr);
    match stderr.lines().find(|l| !l.trim().is_empty()) {
        Some(line) => Err(line.to_string()),
        None => Ok(Some(())),
    }
}
