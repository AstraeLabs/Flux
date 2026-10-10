//! `--daemon` `scan` jobs: per-`moof` sample-encryption census of one chunk
//! file, without decrypting anything and without needing its `moov`.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;

use super::{CliError, CliResult};

#[derive(Serialize)]
pub(super) struct ScanTrack {
    pub(super) track_id: u32,
    pub(super) encrypted_fragments: u64,
    pub(super) clear_fragments: u64,
}

/// Upper bound on fragments considered per chunk file.
const MAX_SCAN_MOOFS: usize = 1_000_000;

pub(super) fn scan_chunk(path: &Path) -> CliResult<(Vec<ScanTrack>, Option<u64>)> {
    let data = std::fs::read(path).map_err(CliError::Io)?;

    let mut moofs: Vec<(u64, u64)> = Vec::new();
    let mut i = 0usize;
    while moofs.len() < MAX_SCAN_MOOFS {
        let Some(j) = find_fourcc(&data[i..], b"moof").map(|k| i + k) else {
            break;
        };
        let start = j.saturating_sub(4);
        let mut next = j + 4;
        if let Some((s, e)) = valid_moof(&data, start) {
            // Candidates arrive in increasing offset order, so only the most recent
            // accepted moof can contain this one (keeps the scan linear).
            let nested = moofs.last().is_some_and(|&(ps, pe)| s >= ps && e <= pe);
            if !nested {
                moofs.push((s, e));
                // Skip the moof body: a "moof" fourcc inside it is never a new fragment.
                next = next.max(e as usize);
            }
        }
        i = next;
    }
    moofs.sort_unstable();

    let mut per_track: BTreeMap<u32, (u64, u64)> = BTreeMap::new();
    let mut first_senc_idx: Option<usize> = None;
    for (idx, &(s, e)) in moofs.iter().enumerate() {
        let moof_bytes = &data[s as usize..e as usize];
        for (track_id, has_senc) in crate::cenc_decrypt::moof_sample_encryption_by_track(moof_bytes) {
            let entry = per_track.entry(track_id).or_insert((0, 0));
            if has_senc {
                entry.0 += 1;
                first_senc_idx.get_or_insert(idx);
            } else {
                entry.1 += 1;
            }
        }
    }

    let scan_cut = first_senc_idx
        .and_then(|k| moofs.get(k + 1).map(|&(s, _)| s));

    let tracks = per_track
        .into_iter()
        .map(|(track_id, (encrypted_fragments, clear_fragments))| ScanTrack {
            track_id,
            encrypted_fragments,
            clear_fragments,
        })
        .collect();
    Ok((tracks, scan_cut))
}

fn valid_moof(data: &[u8], start: usize) -> Option<(u64, u64)> {
    use crate::box_types::parse_box;

    let (bx, _) = parse_box(&data[start..]).ok()?;
    if !bx.header.box_type.is(b"moof") {
        return None;
    }
    let size = bx.header.size;
    let end = if size == 0 {
        data.len() as u64
    } else {
        start as u64 + size
    };
    if end <= start as u64 || end > data.len() as u64 {
        return None;
    }
    if (end - start as u64) < bx.header.header_size() as u64 {
        return None;
    }
    crate::movie_fragment::MovieFragmentBox::parse_body(bx.body).ok()?;
    Some((start as u64, end))
}

fn find_fourcc(haystack: &[u8], needle: &[u8; 4]) -> Option<usize> {
    if needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}
