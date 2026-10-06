//! **EXPERIMENTAL** in-place MPEG-2 Transport Stream `SAMPLE-AES` decrypt.

use alloc::vec::Vec;

use crate::crypto::sample_aes::{aac_decrypt_frame, adts_header_len, h264_decrypt_nal};
use crate::error::{Error, Result};

const PACKET_LEN: usize = 188;
const SYNC_BYTE: u8 = 0x47;

const STREAM_TYPE_H264_PROTECTED: u8 = 0xDB;
const STREAM_TYPE_H264_CLEAR: u8 = 0x1B;
const STREAM_TYPE_AAC_PROTECTED: u8 = 0xCF;
const STREAM_TYPE_AAC_CLEAR: u8 = 0x0F;

struct TsPacket<'a> {
    pid: u16,
    payload_unit_start: bool,
    payload_offset: usize,
    payload: &'a [u8],
}

fn parse_packet(buf: &[u8], pkt_offset: usize) -> Result<TsPacket<'_>> {
    let pkt = &buf[pkt_offset..pkt_offset + PACKET_LEN];
    if pkt[0] != SYNC_BYTE {
        return Err(Error::InvalidInput(
            "ts sample-aes: packet does not start with the 0x47 sync byte -- input is not a \
             clean 188-byte-aligned MPEG-TS stream (no resync attempted)",
        ));
    }
    let pid = (((pkt[1] & 0x1F) as u16) << 8) | pkt[2] as u16;
    let payload_unit_start = pkt[1] & 0x40 != 0;
    let afc = (pkt[3] >> 4) & 0x3;
    let has_payload = afc == 0x1 || afc == 0x3;
    let mut off = 4usize;
    if afc == 0x2 || afc == 0x3 {
        let af_len = pkt[4] as usize;
        off = 5 + af_len;
        if off > PACKET_LEN {
            return Err(Error::InvalidInput(
                "ts sample-aes: adaptation_field_length runs past the end of its own packet",
            ));
        }
    }
    let payload: &[u8] = if has_payload && off < PACKET_LEN { &pkt[off..] } else { &[] };
    Ok(TsPacket {
        pid,
        payload_unit_start,
        payload_offset: pkt_offset + off,
        payload,
    })
}

fn iter_packets(buf: &[u8]) -> impl Iterator<Item = Result<TsPacket<'_>>> {
    let n = buf.len() / PACKET_LEN;
    (0..n).map(move |i| parse_packet(buf, i * PACKET_LEN))
}

fn crc32_mpeg2(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= (b as u32) << 24;
        for _ in 0..8 {
            crc = if crc & 0x8000_0000 != 0 { (crc << 1) ^ 0x04C1_1DB7 } else { crc << 1 };
        }
    }
    crc
}

fn find_pmt_pid(buf: &[u8]) -> Result<u16> {
    for pkt in iter_packets(buf) {
        let pkt = pkt?;
        if pkt.pid != 0 || !pkt.payload_unit_start || pkt.payload.is_empty() {
            continue;
        }
        let pointer = pkt.payload[0] as usize;
        let section = &pkt.payload[1 + pointer..];
        if section.len() < 8 || section[0] != 0x00 {
            return Err(Error::InvalidInput("ts sample-aes: PAT section malformed or not table_id 0x00"));
        }
        let section_len = (((section[1] & 0x0F) as usize) << 8) | section[2] as usize;
        let entries_start = 3 + 5;
        let entries_end = (3 + section_len).saturating_sub(4);
        if entries_end <= entries_start || entries_end > section.len() {
            return Err(Error::InvalidInput("ts sample-aes: PAT has no program entries"));
        }
        let e = &section[entries_start..entries_start + 4];
        let program_number = ((e[0] as u16) << 8) | e[1] as u16;
        if program_number == 0 {
            continue;
        }
        let pmt_pid = (((e[2] & 0x1F) as u16) << 8) | e[3] as u16;
        return Ok(pmt_pid);
    }
    Err(Error::InvalidInput("ts sample-aes: no PAT found (PID 0)"))
}

struct StreamEntry {
    stream_type: u8,
    pid: u16,
    stream_type_offset: usize,
}

struct PmtLocation {
    streams: Vec<StreamEntry>,
    crc_offset: usize,
    section_start: usize,
}

fn find_and_parse_pmt(buf: &[u8], pmt_pid: u16) -> Result<PmtLocation> {
    for pkt in iter_packets(buf) {
        let pkt = pkt?;
        if pkt.pid != pmt_pid || !pkt.payload_unit_start || pkt.payload.is_empty() {
            continue;
        }
        let pointer = pkt.payload[0] as usize;
        let section_start = pkt.payload_offset + 1 + pointer;
        let section = &buf[section_start..];
        if section.len() < 12 || section[0] != 0x02 {
            return Err(Error::InvalidInput("ts sample-aes: PMT section malformed or not table_id 0x02"));
        }
        let section_len = (((section[1] & 0x0F) as usize) << 8) | section[2] as usize;
        let prog_info_len = (((section[10] & 0x0F) as usize) << 8) | section[11] as usize;
        let mut off = 12 + prog_info_len;
        let end = (3 + section_len).saturating_sub(4);
        let mut streams = Vec::new();
        while off + 5 <= end && off + 5 <= section.len() {
            let stream_type = section[off];
            let pid = (((section[off + 1] & 0x1F) as u16) << 8) | section[off + 2] as u16;
            let es_info_len = (((section[off + 3] & 0x0F) as usize) << 8) | section[off + 4] as usize;
            streams.push(StreamEntry {
                stream_type,
                pid,
                stream_type_offset: section_start + off,
            });
            off += 5 + es_info_len;
        }
        if off != end {
            return Err(Error::InvalidInput(
                "ts sample-aes: PMT stream loop does not exactly cover the section (malformed \
                 ES_info_length chain)",
            ));
        }
        return Ok(PmtLocation { streams, crc_offset: section_start + end, section_start });
    }
    Err(Error::InvalidInput("ts sample-aes: no PMT found for the PID named by the PAT"))
}

fn pes_header_len(payload: &[u8]) -> Result<usize> {
    if payload.len() < 9 || payload[0] != 0x00 || payload[1] != 0x00 || payload[2] != 0x01 {
        return Err(Error::InvalidInput("ts sample-aes: PES packet missing 00 00 01 start code prefix"));
    }
    let header_data_len = payload[8] as usize;
    let total = 9 + header_data_len;
    if total > payload.len() {
        return Err(Error::InvalidInput(
            "ts sample-aes: PES header_data_length runs past the first TS packet's payload -- \
             this module only handles a PES header fully contained in its first packet",
        ));
    }
    Ok(total)
}

struct GatheredEs {
    data: Vec<u8>,
    spans: Vec<(usize, usize)>,
}

fn gather_es(buf: &[u8], target_pid: u16) -> Result<GatheredEs> {
    let mut data = Vec::new();
    let mut spans = Vec::new();
    let mut in_pes = false;
    for pkt in iter_packets(buf) {
        let pkt = pkt?;
        if pkt.pid != target_pid {
            continue;
        }
        if pkt.payload.is_empty() {
            continue;
        }
        let (bytes, file_off) = if pkt.payload_unit_start {
            let hlen = pes_header_len(pkt.payload)?;
            in_pes = true;
            (&pkt.payload[hlen..], pkt.payload_offset + hlen)
        } else {
            if !in_pes {
                return Err(Error::InvalidInput(
                    "ts sample-aes: PID has a continuation packet before any PES start -- \
                     truncated/non-standard input",
                ));
            }
            (pkt.payload, pkt.payload_offset)
        };
        if !bytes.is_empty() {
            data.extend_from_slice(bytes);
            spans.push((file_off, bytes.len()));
        }
    }
    Ok(GatheredEs { data, spans })
}

fn scatter_es(out: &mut [u8], spans: &[(usize, usize)], decrypted: &[u8]) {
    let mut pos = 0usize;
    for &(file_off, len) in spans {
        out[file_off..file_off + len].copy_from_slice(&decrypted[pos..pos + len]);
        pos += len;
    }
}

fn split_annexb_exact(es: &[u8]) -> Vec<(core::ops::Range<usize>, core::ops::Range<usize>)> {
    let mut starts = Vec::new();
    let mut i = 0usize;
    while i + 2 < es.len() {
        if es[i] == 0 && es[i + 1] == 0 && es[i + 2] == 1 {
            let (sc_start, sc_len) = if i > 0 && es[i - 1] == 0 { (i - 1, 4) } else { (i, 3) };
            starts.push((sc_start, sc_len));
            i += 3;
        } else {
            i += 1;
        }
    }
    let mut out = Vec::with_capacity(starts.len());
    for (idx, &(sc_start, sc_len)) in starts.iter().enumerate() {
        let nal_start = sc_start + sc_len;
        let nal_end = starts.get(idx + 1).map(|&(s, _)| s).unwrap_or(es.len());
        out.push((sc_start..nal_start, nal_start..nal_end));
    }
    out
}

fn decrypt_h264_es(es: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(es.len());
    for (sc_range, nal_range) in split_annexb_exact(es) {
        out.extend_from_slice(&es[sc_range]);
        let nal = &es[nal_range.clone()];
        let decrypted = h264_decrypt_nal(key, iv, nal);
        if decrypted.len() != nal.len() {
            return Err(Error::InvalidInput(
                "ts sample-aes: decrypted H.264 NAL length differs from its on-disk length \
                 (start-code emulation-prevention byte count changed) -- this experimental \
                 in-place decrypt path has no TS/PES re-packetizer to handle that; refusing \
                 rather than writing a misaligned/corrupt output file",
            ));
        }
        out.extend_from_slice(&decrypted);
    }
    if out.len() != es.len() {
        return Err(Error::InvalidInput(
            "ts sample-aes: H.264 elementary stream length changed after NAL-by-NAL decrypt \
             (unreachable if every NAL-length check above passed -- indicates a gap between \
             this NAL scan and the byte range it actually covers)",
        ));
    }
    Ok(out)
}

fn decrypt_aac_es(es: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(es.len());
    let mut i = 0usize;
    while i < es.len() {
        let frame = &es[i..];
        if frame.len() < 7 || frame[0] != 0xFF || frame[1] & 0xF0 != 0xF0 {
            return Err(Error::InvalidInput("ts sample-aes: ADTS sync word not found at expected frame boundary"));
        }
        let frame_len = (((frame[3] & 0x03) as usize) << 11) | ((frame[4] as usize) << 3) | ((frame[5] >> 5) as usize);
        if frame_len < adts_header_len(frame)? || i + frame_len > es.len() {
            return Err(Error::InvalidInput("ts sample-aes: ADTS frame_length runs past the elementary stream"));
        }
        let decrypted = aac_decrypt_frame(key, iv, &frame[..frame_len])?;
        if decrypted.len() != frame_len {
            return Err(Error::InvalidInput(
                "ts sample-aes: decrypted AAC frame length differs from its ADTS frame_length \
                 (should be impossible -- AAC sample-aes never changes byte count)",
            ));
        }
        out.extend_from_slice(&decrypted);
        i += frame_len;
    }
    Ok(out)
}

pub(crate) fn decrypt_ts_sample_aes(input: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Result<Vec<u8>> {
    if input.len() < PACKET_LEN || input[0] != SYNC_BYTE || input.len() % PACKET_LEN != 0 {
        return Err(Error::InvalidInput(
            "ts sample-aes: input is not a clean 188-byte-packet-aligned MPEG-TS stream",
        ));
    }

    let pmt_pid = find_pmt_pid(input)?;
    let pmt = find_and_parse_pmt(input, pmt_pid)?;

    let video = pmt.streams.iter().find(|s| s.stream_type == STREAM_TYPE_H264_PROTECTED);
    let audio = pmt.streams.iter().find(|s| s.stream_type == STREAM_TYPE_AAC_PROTECTED);
    if video.is_none() && audio.is_none() {
        let unsupported_protected = pmt.streams.iter().any(|s| matches!(s.stream_type, 0xC1 | 0xC2));
        if unsupported_protected {
            return Err(Error::InvalidInput(
                "ts sample-aes: stream is SAMPLE-AES-protected but only carries AC-3/Enhanced \
                 AC-3 (0xC1/0xC2) protected streams -- not yet supported by this experimental \
                 path (only H.264 video and AAC audio are)",
            ));
        }
        return Err(Error::InvalidInput(
            "ts sample-aes: PMT carries no SAMPLE-AES-protected stream_type (0xDB/0xCF) -- \
             not a SAMPLE-AES-protected TS stream",
        ));
    }

    let mut out = input.to_vec();

    for s in &pmt.streams {
        let clear_type = match s.stream_type {
            STREAM_TYPE_H264_PROTECTED => Some(STREAM_TYPE_H264_CLEAR),
            STREAM_TYPE_AAC_PROTECTED => Some(STREAM_TYPE_AAC_CLEAR),
            _ => None,
        };
        if let Some(ct) = clear_type {
            out[s.stream_type_offset] = ct;
        }
    }
    let crc_input_start = pmt.section_start;
    let new_crc = crc32_mpeg2(&out[crc_input_start..pmt.crc_offset]);
    out[pmt.crc_offset..pmt.crc_offset + 4].copy_from_slice(&new_crc.to_be_bytes());

    if let Some(v) = video {
        let gathered = gather_es(input, v.pid)?;
        let decrypted = decrypt_h264_es(&gathered.data, key, iv)?;
        scatter_es(&mut out, &gathered.spans, &decrypted);
    }
    if let Some(a) = audio {
        let gathered = gather_es(input, a.pid)?;
        let decrypted = decrypt_aac_es(&gathered.data, key, iv)?;
        scatter_es(&mut out, &gathered.spans, &decrypted);
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn crc32_mpeg2_matches_a_known_reference_value() {
        assert_eq!(crc32_mpeg2(b"123456789"), 0x0376_E6E7);
    }

    fn ts_packet(pid: u16, pusi: bool, cc: u8, payload: &[u8]) -> Vec<u8> {
        let mut pkt = vec![0xFFu8; PACKET_LEN];
        pkt[0] = SYNC_BYTE;
        pkt[1] = ((pusi as u8) << 6) | ((pid >> 8) as u8 & 0x1F);
        pkt[2] = (pid & 0xFF) as u8;
        pkt[3] = 0x10 | (cc & 0xF);
        let n = payload.len().min(PACKET_LEN - 4);
        pkt[4..4 + n].copy_from_slice(&payload[..n]);
        pkt
    }

    #[test]
    fn parse_packet_reads_pid_and_pusi() {
        let mut buf = ts_packet(0x100, true, 3, b"hello");
        buf.resize(PACKET_LEN, 0xFF);
        let pkt = parse_packet(&buf, 0).unwrap();
        assert_eq!(pkt.pid, 0x100);
        assert!(pkt.payload_unit_start);
        assert_eq!(&pkt.payload[..5], b"hello");
    }

    #[test]
    fn split_annexb_exact_covers_the_whole_input_byte_for_byte() {
        let mut es = Vec::new();
        es.extend_from_slice(&[0, 0, 1, 0x67, 0xAA, 0xBB]);
        es.extend_from_slice(&[0, 0, 0, 1, 0x41, 0xCC, 0xDD]);
        let parts = split_annexb_exact(&es);
        assert_eq!(parts.len(), 2);
        let mut rebuilt = Vec::new();
        for (sc, nal) in &parts {
            rebuilt.extend_from_slice(&es[sc.clone()]);
            rebuilt.extend_from_slice(&es[nal.clone()]);
        }
        assert_eq!(rebuilt, es);
        assert_eq!(&es[parts[0].1.clone()], &[0x67, 0xAA, 0xBB]);
        assert_eq!(&es[parts[1].1.clone()], &[0x41, 0xCC, 0xDD]);
    }

    #[test]
    fn decrypt_ts_sample_aes_rejects_non_ts_input() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        assert!(decrypt_ts_sample_aes(b"not a ts file", &key, &iv).is_err());
    }
}
