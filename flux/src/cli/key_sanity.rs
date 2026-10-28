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

/// Run `ffmpeg -v error <args>` over `input` piped on stdin; any stderr line is a failure.
/// `Ok(None)` when ffmpeg cannot be run at all (the check is best-effort).
fn run_ffmpeg_on_stdin(
    args: &[&str],
    input: Vec<u8>,
    ffmpeg_path: Option<&std::path::Path>,
) -> Result<Option<()>, String> {
    let ffmpeg_bin: std::path::PathBuf = match ffmpeg_path {
        Some(p) => p.to_path_buf(),
        None => std::path::PathBuf::from("ffmpeg"),
    };

    let mut child = match Command::new(&ffmpeg_bin)
        .args(["-v", "error"])
        .args(args)
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
        let _ = stdin.write_all(&input);
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

/// Every (E-)AC-3 sample is one or more syncframes, so it starts with 0x0B77. Decrypting with a
/// wrong key yields random bytes, which pass this with probability 2^-16 per sample.
fn check_ac3_syncword(samples: &[&[u8]]) -> Result<Option<()>, String> {
    let mut checked = false;
    for s in samples.iter().filter(|s| !s.is_empty()) {
        checked = true;
        if s.len() < 2 || s[0] != 0x0B || s[1] != 0x77 {
            let b1 = s.get(1).copied().unwrap_or(0);
            return Err(format!(
                "(E-)AC-3 sample does not start with the 0x0B77 syncword (starts {:02x}{:02x})",
                s[0], b1
            ));
        }
    }
    Ok(checked.then_some(()))
}

/// `(profile - 1, sampling_frequency_index, channel_configuration)` for an ADTS header, from the
/// AudioSpecificConfig. `None` for layouts that cannot be expressed (explicit rates, PS, ...).
fn adts_params(esds: &crate::mp4esds::EsdsBox) -> Option<(u8, u8, u8)> {
    let dsi = esds
        .es_descriptor
        .decoder_config
        .as_ref()?
        .decoder_specific_info
        .as_ref()?;
    let data = &dsi.data;
    let mut pos = 0usize;
    let mut next = |bits: u32| {
        let v = super::read_bits(data, pos, bits);
        pos += bits as usize;
        v
    };
    let aot = next(5)?;
    let sfi = next(4)?;
    let chan = next(4)?;
    if aot == 31 || sfi == 15 || chan == 0 || chan > 7 {
        return None;
    }
    // Explicit SBR signalling (AOT 5): the first rate is the core's, the core AOT follows.
    let core_aot = if aot == 5 {
        next(4)?; // extension sampling frequency index
        next(5)?
    } else {
        aot
    };
    if !(1..=4).contains(&core_aot) {
        return None;
    }
    Some(((core_aot - 1) as u8, sfi as u8, chan as u8))
}

fn adts_wrap(out: &mut Vec<u8>, sample: &[u8], (profile, sfi, chan): (u8, u8, u8)) -> bool {
    let frame_len = sample.len() + 7;
    if sample.is_empty() || frame_len > 0x1FFF {
        return false;
    }
    out.extend_from_slice(&[
        0xFF,
        0xF1,
        (profile << 6) | (sfi << 2) | (chan >> 2),
        ((chan & 3) << 6) | (frame_len >> 11) as u8,
        (frame_len >> 3) as u8,
        (((frame_len & 7) as u8) << 5) | 0x1F,
        0xFC,
    ]);
    out.extend_from_slice(sample);
    true
}

fn check_aac(
    esds: &crate::mp4esds::EsdsBox,
    samples: &[&[u8]],
    ffmpeg_path: Option<&std::path::Path>,
) -> Result<Option<()>, String> {
    let Some(params) = adts_params(esds) else {
        return Ok(None);
    };
    let mut adts = Vec::new();
    let mut wrapped = 0usize;
    for s in samples {
        if adts_wrap(&mut adts, s, params) {
            wrapped += 1;
        }
    }
    if wrapped == 0 {
        return Ok(None);
    }
    run_ffmpeg_on_stdin(&["-f", "aac", "-i", "-", "-f", "null", "-"], adts, ffmpeg_path)
}

/// How many consecutive samples `check_samples` wants for this codec.
pub(crate) fn wanted_samples(cfg: &crate::CodecConfig) -> usize {
    match cfg {
        crate::CodecConfig::Ac3 { .. } | crate::CodecConfig::Eac3 { .. } => 4,
        crate::CodecConfig::Aac { .. } => 8,
        crate::CodecConfig::Hevc { .. } => 25,
        _ => 1,
    }
}

pub(crate) fn check_first_sample(
    cfg: &crate::CodecConfig,
    first_sample: &[u8],
    ffmpeg_path: Option<&std::path::Path>,
) -> Result<Option<()>, String> {
    check_samples(cfg, &[first_sample], ffmpeg_path)
}

/// Best-effort wrong-key check on freshly decrypted samples: H.264/HEVC are test-decoded with
/// ffmpeg, (E-)AC-3 must start with its syncword, AAC is ADTS-wrapped and test-decoded.
pub(crate) fn check_samples(
    cfg: &crate::CodecConfig,
    samples: &[&[u8]],
    ffmpeg_path: Option<&std::path::Path>,
) -> Result<Option<()>, String> {
    match cfg {
        crate::CodecConfig::Ac3 { .. } | crate::CodecConfig::Eac3 { .. } => {
            return check_ac3_syncword(samples);
        }
        crate::CodecConfig::Aac { esds, .. } => return check_aac(esds, samples, ffmpeg_path),
        _ => {}
    }
    let Some((ffmpeg_fmt, length_size)) = ffmpeg_raw_format(cfg) else {
        return Ok(None);
    };
    if samples.is_empty() {
        return Ok(None);
    }
    let mut annexb = parameter_sets_annexb(cfg);
    let params_len = annexb.len();
    for sample in samples {
        append_sample_as_annexb(&mut annexb, sample, length_size);
    }
    if annexb.len() == params_len {
        return Ok(None);
    }
    run_ffmpeg_on_stdin(&["-f", ffmpeg_fmt, "-i", "-", "-f", "null", "-"], annexb, ffmpeg_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ac3_syncword_accepts_clear_and_rejects_noise() {
        let good = [0x0Bu8, 0x77, 1, 2, 3];
        let bad = [0x13u8, 0x77, 1, 2, 3];
        assert_eq!(check_ac3_syncword(&[&good, &good]), Ok(Some(())));
        assert!(check_ac3_syncword(&[&good, &bad]).is_err());
        assert_eq!(check_ac3_syncword(&[]), Ok(None));
    }

    #[test]
    fn adts_header_encodes_profile_rate_channels_and_length() {
        let mut out = Vec::new();
        // AAC-LC (profile 1), 48 kHz (index 3), stereo, 100-byte payload -> frame length 107.
        assert!(adts_wrap(&mut out, &[0u8; 100], (1, 3, 2)));
        assert_eq!(out.len(), 107);
        assert_eq!(&out[..2], &[0xFF, 0xF1]);
        assert_eq!(out[2], (1 << 6) | (3 << 2));
        let len = ((out[3] as usize & 3) << 11) | ((out[4] as usize) << 3) | (out[5] as usize >> 5);
        assert_eq!(len, 107);
        assert_eq!(out[3] >> 6, 2, "channel configuration low bits");
    }

    #[test]
    fn adts_wrap_rejects_empty_and_oversized_samples() {
        let mut out = Vec::new();
        assert!(!adts_wrap(&mut out, &[], (1, 3, 2)));
        assert!(!adts_wrap(&mut out, &vec![0u8; 0x2000], (1, 3, 2)));
        assert!(out.is_empty());
    }
}
