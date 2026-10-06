// **EXPERIMENTAL** in-place MPEG-2 Transport Stream "BBTS" decrypt.

use alloc::vec::Vec;

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};

use crate::error::{Error, Result};

const PACKET_LEN: usize = 188;
const SYNC_BYTE: u8 = 0x47;
const PID_PAT: u16 = 0x0000;
const PID_SDT: u16 = 0x0011;

fn ctr_inc(counter: &mut [u8; 16]) {
    let mut carry: u16 = 1;
    for byte in counter.iter_mut().rev() {
        let v = *byte as u16 + carry;
        *byte = (v & 0xff) as u8;
        carry = v >> 8;
        if carry == 0 {
            break;
        }
    }
}

fn decrypt_es_sparse(es: &[u8], cipher: &Aes128, iv_start: &[u8; 16]) -> Vec<u8> {
    let mut counter_iv = *iv_start;
    let mut output = es.to_vec();
    let mut remaining = output.len();
    let mut position = 0usize;
    let mut counter = 0usize;

    while remaining > 0 {
        ctr_inc(&mut counter_iv);
        let mut block = counter_iv;
        if remaining <= 16 || counter % 10 == 0 {
            let mut ga = GenericArray::clone_from_slice(&counter_iv);
            cipher.encrypt_block(&mut ga);
            block.copy_from_slice(&ga);
        }
        let n = remaining.min(16);
        for b in 0..n {
            output[position + b] ^= block[b];
        }
        remaining -= n;
        position += 16;
        counter += 1;
    }

    output
}

struct PacketInfo {
    pid: u16,
    pusi: bool,
    payload_offset: Option<usize>,
}

fn packet_info(packet: &[u8]) -> Option<PacketInfo> {
    if packet.len() != PACKET_LEN || packet[0] != SYNC_BYTE {
        return None;
    }
    let pid = (((packet[1] & 0x1f) as u16) << 8) | packet[2] as u16;
    let pusi = (packet[1] & 0x40) != 0;
    let afc = (packet[3] >> 4) & 0x03;
    let mut off = 4usize;
    if afc == 2 || afc == 3 {
        if off >= PACKET_LEN {
            return Some(PacketInfo { pid, pusi, payload_offset: None });
        }
        off += 1 + packet[off] as usize;
        if off > PACKET_LEN {
            return Some(PacketInfo { pid, pusi, payload_offset: None });
        }
    }
    if afc != 1 && afc != 3 {
        return Some(PacketInfo { pid, pusi, payload_offset: None });
    }
    Some(PacketInfo { pid, pusi, payload_offset: Some(off) })
}

fn parse_pat_pmt_pid(packet: &[u8]) -> Option<u16> {
    let info = packet_info(packet)?;
    if info.pid != PID_PAT {
        return None;
    }
    let off = info.payload_offset?;
    let mut payload = &packet[off..];
    if info.pusi {
        if payload.is_empty() {
            return None;
        }
        let pointer = payload[0] as usize;
        payload = payload.get(1 + pointer..)?;
    }
    if payload.len() < 8 || payload[0] != 0x00 {
        return None;
    }
    let section_length = (((payload[1] & 0x0f) as usize) << 8) | payload[2] as usize;
    let section = payload.get(..3 + section_length)?;
    let end = section.len().checked_sub(4)?;
    let mut i = 8usize;
    while i + 4 <= end {
        let program_number = ((section[i] as u16) << 8) | section[i + 1] as u16;
        let pmt_pid = (((section[i + 2] & 0x1f) as u16) << 8) | section[i + 3] as u16;
        if program_number != 0 {
            return Some(pmt_pid);
        }
        i += 4;
    }
    None
}

fn has_dovi_registration(descriptors: &[u8]) -> bool {
    let mut i = 0usize;
    while i + 2 <= descriptors.len() {
        let tag = descriptors[i];
        let size = descriptors[i + 1] as usize;
        if i + 2 + size > descriptors.len() {
            break;
        }
        if tag == 0x05 && &descriptors[i + 2..i + 2 + size] == b"DOVI" {
            return true;
        }
        i += 2 + size;
    }
    false
}

fn stream_type_is_video(t: u8) -> bool {
    matches!(t, 0x01 | 0x02 | 0x1b | 0x24)
}

fn parse_pmt(packet: &[u8]) -> (Vec<u16>, Vec<(u16, u8)>) {
    let mut video_pids = Vec::new();
    let mut streams = Vec::new();
    let Some(info) = packet_info(packet) else { return (video_pids, streams) };
    let Some(off) = info.payload_offset else { return (video_pids, streams) };
    let mut payload = &packet[off..];
    if info.pusi {
        if payload.is_empty() {
            return (video_pids, streams);
        }
        let pointer = payload[0] as usize;
        let Some(rest) = payload.get(1 + pointer..) else { return (video_pids, streams) };
        payload = rest;
    }
    if payload.len() < 12 || payload[0] != 0x02 {
        return (video_pids, streams);
    }
    let section_length = (((payload[1] & 0x0f) as usize) << 8) | payload[2] as usize;
    let Some(section) = payload.get(..3 + section_length) else { return (video_pids, streams) };
    if section.len() < 16 {
        return (video_pids, streams);
    }
    let program_info_length = (((section[10] & 0x0f) as usize) << 8) | section[11] as usize;
    let mut i = 12usize + program_info_length;
    let Some(end) = section.len().checked_sub(4) else { return (video_pids, streams) };
    while i + 5 <= end {
        let stream_type = section[i];
        let elementary_pid = (((section[i + 1] & 0x1f) as u16) << 8) | section[i + 2] as u16;
        let es_info_length = (((section[i + 3] & 0x0f) as usize) << 8) | section[i + 4] as usize;
        if i + 5 + es_info_length > section.len() {
            break;
        }
        let descriptors = &section[i + 5..i + 5 + es_info_length];
        streams.push((elementary_pid, stream_type));
        if stream_type_is_video(stream_type) || (stream_type == 0x06 && has_dovi_registration(descriptors)) {
            video_pids.push(elementary_pid);
        }
        i += 5 + es_info_length;
    }
    (video_pids, streams)
}

fn decode_hex16(hex: &[u8]) -> Option<[u8; 16]> {
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = (hex[i * 2] as char).to_digit(16)?;
        let lo = (hex[i * 2 + 1] as char).to_digit(16)?;
        *byte = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

fn extract_marker_iv(packet: &[u8]) -> Option<[u8; 16]> {
    if packet.len() <= 4 {
        return None;
    }
    let text: Vec<u8> = packet[4..].iter().copied().filter(|&b| (32..=126).contains(&b)).collect();
    if text.len() < 35 {
        return None;
    }
    for i in 0..=text.len() - 35 {
        if text[i] == b'|' && text[i + 1] == b'v' && text[i + 34] == b'|' {
            if let Some(iv) = decode_hex16(&text[i + 2..i + 34]) {
                return Some(iv);
            }
        }
    }
    None
}

fn extract_sdt_service_name_iv(section: &[u8]) -> Option<[u8; 16]> {
    if section.len() < 16 || section[0] != 0x42 {
        return None;
    }
    let section_length = (((section[1] & 0x0f) as usize) << 8) | section[2] as usize;
    let end = section.len().min(3 + section_length);
    let mut pos = 3 + 8;
    while pos + 5 <= end.saturating_sub(4) {
        let desc_loop_len = (((section[pos + 3] & 0x0f) as usize) << 8) | section[pos + 4] as usize;
        let mut dpos = pos + 5;
        let dend = dpos + desc_loop_len;
        while dpos + 2 <= dend && dpos + 2 <= end.saturating_sub(4) {
            let tag = section[dpos];
            let length = section[dpos + 1] as usize;
            dpos += 2;
            if dpos + length > section.len() {
                break;
            }
            let body = &section[dpos..dpos + length];
            dpos += length;
            if tag == 0x48 && body.len() >= 3 {
                let provider_len = body[1] as usize;
                if 2 + provider_len >= body.len() {
                    continue;
                }
                let sn_len_idx = 2 + provider_len;
                let sn_len = body[sn_len_idx] as usize;
                if sn_len_idx + 1 + sn_len > body.len() {
                    continue;
                }
                let service_name = &body[sn_len_idx + 1..sn_len_idx + 1 + sn_len];
                let Ok(service_name) = core::str::from_utf8(service_name) else { continue };
                if !service_name.contains("mdcm|") {
                    continue;
                }
                let parts: Vec<&str> = service_name.split('|').collect();
                if parts.len() < 4 {
                    continue;
                }
                let mut iv_hex = parts[3].trim();
                if iv_hex.is_empty() {
                    continue;
                }
                if let Some(rest) = iv_hex.strip_prefix(['v', 'V']) {
                    iv_hex = rest;
                }
                if let Some(iv) = decode_hex16(iv_hex.as_bytes()) {
                    return Some(iv);
                }
            }
        }
        pos = dend;
    }
    None
}

struct PsiAssembler {
    buf: Vec<u8>,
    expected_total: Option<usize>,
    collecting: bool,
}

impl PsiAssembler {
    fn new() -> Self {
        Self { buf: Vec::new(), expected_total: None, collecting: false }
    }

    fn push(&mut self, packet: &[u8]) -> Option<Vec<u8>> {
        let info = packet_info(packet)?;
        let off = info.payload_offset?;
        let mut payload = &packet[off..];
        if info.pusi {
            if payload.is_empty() {
                return None;
            }
            let pointer = payload[0] as usize;
            payload = payload.get(1 + pointer..)?;
            self.buf.clear();
            self.expected_total = None;
            self.collecting = true;
        }
        if !self.collecting {
            return None;
        }
        self.buf.extend_from_slice(payload);
        if self.expected_total.is_none() && self.buf.len() >= 3 {
            let section_length = (((self.buf[1] & 0x0f) as usize) << 8) | self.buf[2] as usize;
            self.expected_total = Some(3 + section_length);
        }
        if let Some(expected) = self.expected_total {
            if self.buf.len() >= expected {
                let section = self.buf[..expected].to_vec();
                self.buf.clear();
                self.expected_total = None;
                self.collecting = false;
                return Some(section);
            }
        }
        None
    }
}

fn decrypt_pes_video(pes: &[u8], stream_type: u8, cipher: &Aes128, iv_snap: &[u8; 16]) -> Vec<u8> {
    if pes.len() < 9 {
        return pes.to_vec();
    }
    let pes_header_len = pes[8] as usize;
    let header_end = 9 + pes_header_len;
    if header_end > pes.len() {
        return pes.to_vec();
    }
    let mut out = Vec::with_capacity(pes.len());
    out.extend_from_slice(&pes[..header_end]);

    let nal_hdr_len = if stream_type == 0x1B { 1 } else { 2 };
    let mut pos_st = header_end;
    let n = pes.len();
    let mut i = pos_st;
    while i < n {
        if i == n - 1 {
            if n >= 2 && n - 2 > pos_st + 3 + nal_hdr_len {
                out.extend_from_slice(&pes[pos_st..pos_st + 3 + nal_hdr_len]);
                let es = &pes[pos_st + 3 + nal_hdr_len..n - 2];
                if !es.is_empty() {
                    out.extend_from_slice(&decrypt_es_sparse(es, cipher, iv_snap));
                }
                out.extend_from_slice(&pes[n - 2..]);
            } else {
                out.extend_from_slice(&pes[pos_st..]);
            }
        } else if i + 2 < n && pes[i] == 0 && pes[i + 1] == 0 && pes[i + 2] == 1 {
            if i != pos_st {
                if i >= 2 && i - 2 > pos_st + 3 + nal_hdr_len {
                    out.extend_from_slice(&pes[pos_st..pos_st + 3 + nal_hdr_len]);
                    let flag = i >= 1 && pes[i - 1] == 0;
                    let (es, trailer): (&[u8], &[u8]) = if flag && i >= 3 {
                        (&pes[pos_st + 3 + nal_hdr_len..i - 3], &pes[i - 3..i])
                    } else if i >= 2 {
                        (&pes[pos_st + 3 + nal_hdr_len..i - 2], &pes[i - 2..i])
                    } else {
                        (&[], &[])
                    };
                    if !es.is_empty() {
                        out.extend_from_slice(&decrypt_es_sparse(es, cipher, iv_snap));
                    }
                    out.extend_from_slice(trailer);
                } else {
                    out.extend_from_slice(&pes[pos_st..i]);
                }
                pos_st = i;
            }
        }
        i += 1;
    }
    out
}

pub(crate) fn looks_like_bbts(input: &[u8]) -> bool {
    if input.len() < PACKET_LEN || input[0] != SYNC_BYTE || input.len() % PACKET_LEN != 0 {
        return false;
    }
    let mut sdt_asm = PsiAssembler::new();
    for chunk in input.chunks_exact(PACKET_LEN) {
        let Some(info) = packet_info(chunk) else { continue };
        if info.pid != PID_SDT {
            continue;
        }
        if extract_marker_iv(chunk).is_some() {
            return true;
        }
        if let Some(section) = sdt_asm.push(chunk) {
            if extract_sdt_service_name_iv(&section).is_some() {
                return true;
            }
        }
    }
    false
}

struct PesUnit {
    bytes: Vec<u8>,
    packet_spans: Vec<(usize, usize)>,
    iv_snap: [u8; 16],
    pid: u16,
}

pub(crate) fn decrypt_ts_bbts(input: &[u8], key: &[u8; 16]) -> Result<Vec<u8>> {
    if input.len() < PACKET_LEN || input[0] != SYNC_BYTE || input.len() % PACKET_LEN != 0 {
        return Err(Error::InvalidInput("ts bbts: input is not a clean 188-byte-packet-aligned MPEG-TS stream"));
    }

    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut out = input.to_vec();

    let mut base_iv: Option<[u8; 16]> = None;
    let mut pmt_pid: Option<u16> = None;
    let mut target_pids: Vec<u16> = Vec::new();
    let mut stream_types: Vec<(u16, u8)> = Vec::new();
    let mut sdt_asm = PsiAssembler::new();

    let mut pending: Option<PesUnit> = None;
    let mut units: Vec<PesUnit> = Vec::new();

    for (pkt_idx, packet) in input.chunks_exact(PACKET_LEN).enumerate() {
        let Some(info) = packet_info(packet) else { continue };
        let pid = info.pid;

        if pid == PID_PAT {
            if let Some(p) = parse_pat_pmt_pid(packet) {
                pmt_pid = Some(p);
            }
            continue;
        }

        if pid == PID_SDT {
            if let Some(iv) = extract_marker_iv(packet) {
                base_iv = Some(iv);
            }
            if let Some(section) = sdt_asm.push(packet) {
                if let Some(iv) = extract_sdt_service_name_iv(&section) {
                    base_iv = Some(iv);
                }
            }
            continue;
        }

        if Some(pid) == pmt_pid {
            let (video_pids, streams) = parse_pmt(packet);
            for vp in &video_pids {
                if !target_pids.contains(vp) {
                    target_pids.push(*vp);
                }
            }
            for &(spid, stype) in &streams {
                if let Some(existing) = stream_types.iter_mut().find(|(p, _)| *p == spid) {
                    existing.1 = stype;
                } else {
                    stream_types.push((spid, stype));
                }
            }
            continue;
        }

        if !target_pids.contains(&pid) {
            continue;
        }
        let Some(base_iv) = base_iv else { continue };
        let Some(off) = info.payload_offset else { continue };
        if off >= PACKET_LEN {
            continue;
        }

        let mut is_new_pes = info.pusi;
        if off + 4 <= PACKET_LEN && packet[off] == 0 && packet[off + 1] == 0 && packet[off + 2] == 1 {
            let sid = packet[off + 3];
            if sid == 0xC0 || (sid & 0xF0) == 0xE0 {
                is_new_pes = true;
            }
        }

        if is_new_pes {
            if let Some(u) = pending.take() {
                units.push(u);
            }
            pending = Some(PesUnit { bytes: Vec::new(), packet_spans: Vec::new(), iv_snap: base_iv, pid });
        }

        let Some(unit) = pending.as_mut() else { continue };
        let pkt_off = pkt_idx * PACKET_LEN;
        unit.packet_spans.push((pkt_off + off, off));
        unit.bytes.extend_from_slice(&packet[off..]);
    }
    if let Some(u) = pending.take() {
        units.push(u);
    }

    for unit in &units {
        let stream_type = stream_types.iter().find(|(p, _)| *p == unit.pid).map(|(_, t)| *t).unwrap_or(0x24);
        let sid = if unit.bytes.len() > 3 { unit.bytes[3] } else { 0 };
        if sid & 0xF0 != 0xE0 || unit.bytes.len() <= 8 {
            continue;
        }
        let decrypted = decrypt_pes_video(&unit.bytes, stream_type, &cipher, &unit.iv_snap);
        if decrypted.len() != unit.bytes.len() {
            return Err(Error::InvalidInput(
                "ts bbts: decrypted PES length differs from its on-disk length -- should be \
                 unreachable (this scheme's AES-CTR decrypt is byte-count preserving); refusing \
                 rather than writing a misaligned output file",
            ));
        }
        let mut pos = 0usize;
        for &(file_off, hdr_len) in &unit.packet_spans {
            let len = PACKET_LEN - hdr_len;
            let take = len.min(decrypted.len() - pos);
            out[file_off..file_off + take].copy_from_slice(&decrypted[pos..pos + take]);
            pos += take;
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn ctr_inc_wraps_across_byte_boundaries() {
        let mut c = [0u8; 16];
        c[15] = 0xff;
        ctr_inc(&mut c);
        assert_eq!(c[15], 0);
        assert_eq!(c[14], 1);
    }

    #[test]
    fn extract_marker_iv_finds_the_pipe_v_pattern() {
        let mut packet = vec![0u8; PACKET_LEN];
        packet[0] = SYNC_BYTE;
        let marker = b"|v00112233445566778899aabbccddeeff|";
        packet[4..4 + marker.len()].copy_from_slice(marker);
        let iv = extract_marker_iv(&packet).expect("marker must be found");
        assert_eq!(iv[0], 0x00);
        assert_eq!(iv[1], 0x11);
        assert_eq!(iv[15], 0xff);
    }

    #[test]
    fn decrypt_ts_bbts_rejects_non_ts_input() {
        let key = [0u8; 16];
        assert!(decrypt_ts_bbts(b"not a ts file", &key).is_err());
    }

    #[test]
    fn looks_like_bbts_is_false_without_a_marker() {
        let mut packet = vec![0u8; PACKET_LEN];
        packet[0] = SYNC_BYTE;
        assert!(!looks_like_bbts(&packet));
    }
}
