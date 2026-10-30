//! Size-preserving CENC decrypt of a fragmented MP4 (`--in-place` / `--chunks`).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::sync_channel;
use std::time::{Duration, Instant};

use super::{
    CliError, CliResult, MAX_SINGLE_READ, decrypt_run_maybe_parallel, invalid, key_sanity,
    key_sanity_check_enabled, parse_key, profile_enabled, split_into_contiguous_runs,
    writer_buf_capacity,
};
use crate::cenc_decrypt::{self, KeyMap};

const MAX_REGION: u64 = 512 << 20;
const PREFLIGHT_MAX_REGIONS: usize = 64;
const BOX_HDR: usize = 8;
const VISUAL_ENTRY_FIXED: usize = 78;

pub(super) enum Dest<'a> {
    /// Rewrite the input bytes where they are.
    InPlace,
    /// Write the decrypted bytes sequentially to a new file.
    File(&'a Path),
    /// Stream the decrypted bytes to stdout (`-o -`), e.g. straight into `ffmpeg -i -`.
    Stdout,
}

/// A duplicate of this process's stdout handle, as a plain file.
fn stdout_file() -> io::Result<fs::File> {
    #[cfg(unix)]
    {
        use std::os::fd::AsFd;
        Ok(fs::File::from(io::stdout().as_fd().try_clone_to_owned()?))
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsHandle;
        Ok(fs::File::from(io::stdout().as_handle().try_clone_to_owned()?))
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(io::Error::new(io::ErrorKind::Unsupported, "-o - is not supported on this platform"))
    }
}

/// Printed (and returned as an error) when a fragment keeps its per-sample IVs in `mdat`.
fn warn_aux_in_mdat(fragment: Option<usize>) -> CliError {
    let which = fragment.map_or(String::new(), |n| format!(" #{n}"));
    eprintln!(
        "flux: warning: fragment{which} keeps its per-sample IVs in mdat (saiz/saio without senc); \
         --in-place/--chunks cannot decrypt this. Nothing was written. Use the regular -o mode instead."
    );
    invalid(
        "fragment keeps its per-sample IVs in mdat (saiz/saio without senc); not supported by \
         --in-place/--chunks",
    )
}

/// Ordered files read (and, if opened writable, written) as one contiguous byte range.
pub(super) struct ChunkSet {
    files: Vec<fs::File>,
    starts: Vec<u64>,
    lens: Vec<u64>,
    total: u64,
}

#[cfg(windows)]
fn pread(f: &fs::File, buf: &mut [u8], off: u64) -> io::Result<usize> {
    std::os::windows::fs::FileExt::seek_read(f, buf, off)
}
#[cfg(unix)]
fn pread(f: &fs::File, buf: &mut [u8], off: u64) -> io::Result<usize> {
    std::os::unix::fs::FileExt::read_at(f, buf, off)
}
#[cfg(windows)]
fn pwrite(f: &fs::File, buf: &[u8], off: u64) -> io::Result<usize> {
    std::os::windows::fs::FileExt::seek_write(f, buf, off)
}
#[cfg(unix)]
fn pwrite(f: &fs::File, buf: &[u8], off: u64) -> io::Result<usize> {
    std::os::unix::fs::FileExt::write_at(f, buf, off)
}

impl ChunkSet {
    pub(super) fn open(paths: &[PathBuf], writable: bool) -> CliResult<Self> {
        let mut set = ChunkSet {
            files: Vec::with_capacity(paths.len()),
            starts: Vec::with_capacity(paths.len()),
            lens: Vec::with_capacity(paths.len()),
            total: 0,
        };
        for p in paths {
            let f = fs::OpenOptions::new().read(true).write(writable).open(p)?;
            let len = f.metadata()?.len();
            set.starts.push(set.total);
            set.lens.push(len);
            set.total += len;
            set.files.push(f);
        }
        Ok(set)
    }

    fn len(&self) -> u64 {
        self.total
    }

    /// Index of the file holding byte `off`, skipping empty files.
    fn locate(&self, off: u64) -> Option<usize> {
        let mut i = self.starts.partition_point(|&s| s <= off).saturating_sub(1);
        while i < self.files.len() && off >= self.starts[i] + self.lens[i] {
            i += 1;
        }
        (i < self.files.len()).then_some(i)
    }

    fn read_at(&self, mut off: u64, mut buf: &mut [u8]) -> io::Result<()> {
        while !buf.is_empty() {
            let i = self.locate(off).ok_or_else(eof)?;
            let local = off - self.starts[i];
            let take = buf.len().min((self.lens[i] - local) as usize);
            let (head, tail) = buf.split_at_mut(take);
            let mut done = 0;
            while done < head.len() {
                let n = pread(&self.files[i], &mut head[done..], local + done as u64)?;
                if n == 0 {
                    return Err(eof());
                }
                done += n;
            }
            off += take as u64;
            buf = tail;
        }
        Ok(())
    }

    fn write_at(&self, mut off: u64, mut buf: &[u8]) -> io::Result<()> {
        while !buf.is_empty() {
            let i = self.locate(off).ok_or_else(eof)?;
            let local = off - self.starts[i];
            let take = buf.len().min((self.lens[i] - local) as usize);
            let (head, tail) = buf.split_at(take);
            let mut done = 0;
            while done < head.len() {
                let n = pwrite(&self.files[i], &head[done..], local + done as u64)?;
                if n == 0 {
                    return Err(eof());
                }
                done += n;
            }
            off += take as u64;
            buf = tail;
        }
        Ok(())
    }
}

fn eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "read/write past the end of the chunk set")
}

/// The `seg_<n>.mp4` files of `dir` in numeric order.
pub(super) fn list_chunks(dir: &Path) -> CliResult<Vec<PathBuf>> {
    let mut found: Vec<(u64, PathBuf)> = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(num) = name
            .strip_prefix("seg_")
            .and_then(|r| r.strip_suffix(".mp4"))
            .and_then(|n| n.parse::<u64>().ok())
        else {
            continue;
        };
        found.push((num, entry.path()));
    }
    if found.is_empty() {
        return Err(invalid("--chunks: no seg_<n>.mp4 files found in the directory"));
    }
    found.sort_by_key(|(n, _)| *n);
    for w in found.windows(2) {
        if w[1].0 != w[0].0 + 1 {
            return Err(invalid("--chunks: gap in the seg_<n>.mp4 numbering"));
        }
    }
    Ok(found.into_iter().map(|(_, p)| p).collect())
}

struct Bx {
    ty: [u8; 4],
    offset: u64,
    size: u64,
}

/// Top-level boxes of the set; they must tile it exactly.
fn scan_boxes(set: &ChunkSet) -> CliResult<Vec<Bx>> {
    let total = set.len();
    let mut out = Vec::new();
    let mut off = 0u64;
    while off < total {
        let mut hdr = [0u8; 16];
        let want = (total - off).min(16) as usize;
        set.read_at(off, &mut hdr[..want])?;
        if want < BOX_HDR {
            return Err(invalid("truncated box header at the end of the input"));
        }
        let mut size = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as u64;
        if size == 1 {
            if want < 16 {
                return Err(invalid("truncated 64-bit box header at the end of the input"));
            }
            size = u64::from_be_bytes(
                hdr[8..16]
                    .try_into()
                    .map_err(|_| invalid("truncated 64-bit box size field"))?,
            );
        } else if size == 0 {
            return Err(invalid("top-level box with size 0 (to-EOF) is not supported"));
        }
        if size < BOX_HDR as u64 || off.checked_add(size).is_none_or(|e| e > total) {
            return Err(invalid(
                "box extends past the end of the input (truncated download or missing chunk)",
            ));
        }
        out.push(Bx { ty: [hdr[4], hdr[5], hdr[6], hdr[7]], offset: off, size });
        off += size;
    }
    Ok(out)
}

/// `(offset, size, type, header_len)` of the boxes found in `data[start..end]`.
fn children(data: &[u8], start: usize, end: usize) -> Vec<(usize, usize, [u8; 4], usize)> {
    let mut out = Vec::new();
    let end = end.min(data.len());
    let mut pos = start;
    while pos + BOX_HDR <= end {
        let mut size = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        let ty = [data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]];
        let mut hdr = BOX_HDR;
        if size == 1 {
            if pos + 16 > end {
                break;
            }
            size = u64::from_be_bytes(data[pos + 8..pos + 16].try_into().unwrap()) as usize;
            hdr = 16;
        } else if size == 0 {
            size = end - pos;
        }
        if size < hdr || pos + size > end {
            break;
        }
        out.push((pos, size, ty, hdr));
        pos += size;
    }
    out
}

fn retype(data: &mut [u8], box_off: usize, ty: &[u8; 4]) {
    data[box_off + 4..box_off + 8].copy_from_slice(ty);
}

/// Retype the per-sample encryption boxes of a moof to `free`.
fn neutralize_moof(moof: &mut [u8]) {
    for (off, size, ty, hdr) in children(moof, 0, moof.len()).into_iter().take(1) {
        debug_assert_eq!(&ty, b"moof");
        for (toff, tsize, tty, thdr) in children(moof, off + hdr, off + size) {
            if &tty != b"traf" {
                continue;
            }
            for (coff, _, cty, _) in children(moof, toff + thdr, toff + tsize) {
                if matches!(&cty, b"senc" | b"saiz" | b"saio") {
                    retype(moof, coff, b"free");
                }
            }
        }
    }
}

/// Clear the protection signalling of the init: `pssh` -> `free`, `encv`/`enca` -> original
/// format, `sinf` -> `free`. Returns how many sample entries were restored.
fn patch_init(head: &mut [u8]) -> usize {
    let mut restored = 0;
    for (moff, msize, mty, mhdr) in children(head, 0, head.len()) {
        if &mty != b"moov" {
            continue;
        }
        for (coff, csize, cty, chdr) in children(head, moff + mhdr, moff + msize) {
            match &cty {
                b"pssh" => retype(head, coff, b"free"),
                b"trak" => {
                    let mut path_end = (coff + chdr, coff + csize);
                    let mut found = true;
                    for want in [b"mdia", b"minf", b"stbl", b"stsd"] {
                        match children(head, path_end.0, path_end.1)
                            .into_iter()
                            .find(|(_, _, t, _)| t == want)
                        {
                            Some((o, s, _, h)) => path_end = (o + h, o + s),
                            None => {
                                found = false;
                                break;
                            }
                        }
                    }
                    if found {
                        restored += patch_stsd(head, path_end.0, path_end.1);
                    }
                }
                _ => {}
            }
        }
    }
    restored
}

/// `body_start..end` is the body of an `stsd` (after its box header).
fn patch_stsd(head: &mut [u8], body_start: usize, end: usize) -> usize {
    // FullBox header (4) + entry_count (4).
    let mut restored = 0;
    for (eoff, esize, ety, _) in children(head, body_start + 8, end) {
        let fixed = eoff + BOX_HDR;
        let child_start = match &ety {
            b"encv" => fixed + VISUAL_ENTRY_FIXED,
            b"enca" => {
                if fixed + 10 > head.len() {
                    continue;
                }
                let version = u16::from_be_bytes([head[fixed + 8], head[fixed + 9]]);
                fixed + match version {
                    0 => 28,
                    1 => 44,
                    _ => 64,
                }
            }
            _ => continue,
        };
        let eend = eoff + esize;
        let Some((soff, ssize, _, shdr)) = children(head, child_start, eend)
            .into_iter()
            .find(|(_, _, t, _)| t == b"sinf")
        else {
            continue;
        };
        let Some(format) = children(head, soff + shdr, soff + ssize)
            .into_iter()
            .find(|(_, s, t, h)| t == b"frma" && *s >= h + 4)
            .map(|(o, _, _, h)| [head[o + h], head[o + h + 1], head[o + h + 2], head[o + h + 3]])
        else {
            continue;
        };
        retype(head, eoff, &format);
        retype(head, soff, b"free");
        restored += 1;
    }
    restored
}

/// `(value_offset, width)` of every tfdt box inside `moof`, in document order.
fn tfdt_offsets(moof: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    for (moff, msize, mty, mhdr) in children(moof, 0, moof.len()) {
        if &mty != b"moof" {
            continue;
        }
        for (toff, tsize, tty, thdr) in children(moof, moff + mhdr, moff + msize) {
            if &tty != b"traf" {
                continue;
            }
            for (coff, csize, cty, chdr) in children(moof, toff + thdr, toff + tsize) {
                if &cty != b"tfdt" || coff + chdr + 4 > toff + tsize {
                    continue;
                }
                // tfdt is a FullBox: header + version(1) + flags(3) + value.
                let version = moof[coff + chdr];
                let width = if version == 1 { 8 } else { 4 }; // v0: 4 bytes, v1: 8 bytes
                let value_off = coff + chdr + 4;
                if value_off + width <= coff + csize {
                    out.push((value_off, width));
                }
            }
        }
    }
    out
}

fn read_tfdt_value(moof: &[u8], value_off: usize, width: usize) -> u64 {
    match width {
        8 => u64::from_be_bytes(moof[value_off..value_off + 8].try_into().unwrap()),
        _ => u64::from(u32::from_be_bytes(moof[value_off..value_off + 4].try_into().unwrap())),
    }
}

/// Rebase every tfdt in `moof` so its baseMediaDecodeTime sits at zero.
/// Mirrors the Python-side `rebase_fragment_timestamps()` semantics:
/// `new_value = max(0, value - base)`.
pub(super) fn rebase_moof_tfdt(moof: &mut [u8], base: u64) {
    for (value_off, width) in tfdt_offsets(moof) {
        let rebased = read_tfdt_value(moof, value_off, width).saturating_sub(base);
        if width == 8 {
            moof[value_off..value_off + width].copy_from_slice(&rebased.to_be_bytes());
        } else {
            moof[value_off..value_off + width]
                .copy_from_slice(&(rebased.min(u64::from(u32::MAX)) as u32).to_be_bytes());
        }
    }
}

struct Ctx<'a> {
    crypto_tracks: &'a [cenc_decrypt::TrackCrypto],
    target_ids: &'a [u32],
    trex: &'a BTreeMap<u32, cenc_decrypt::TrexDefaults>,
    keys: &'a BTreeMap<u32, [u8; 16]>,
    /// Every key given on the command line: a fragment that rotates keys names the KID per sample.
    all_keys: &'a KeyMap,
    codecs: &'a BTreeMap<u32, crate::CodecConfig>,
    ffmpeg: Option<&'a Path>,
}

/// Decrypt every protected sample of the fragment held in `region` (which starts at the moof)
/// and neutralize its encryption boxes. `pending` holds the tracks whose first sync sample
/// still has to pass the wrong-key check; they are removed as they pass.
fn process_region(
    ctx: &Ctx,
    region_off: u64,
    moof_size: usize,
    region: &mut [u8],
    next_dts: &mut BTreeMap<u32, i64>,
    scratch: &mut cenc_decrypt::DecryptScratch,
    pending: &mut BTreeSet<u32>,
) -> CliResult<()> {
    let moof_bytes = region[..moof_size].to_vec();
    if cenc_decrypt::fragment_aux_info_requires_mdat(&moof_bytes) {
        return Err(warn_aux_in_mdat(None));
    }
    let fragments = cenc_decrypt::harvest_fragment(
        region_off,
        &moof_bytes,
        ctx.crypto_tracks,
        ctx.target_ids,
        next_dts,
        ctx.trex,
        None,
    )?;
    for ft in fragments {
        let Some(key) = ctx.keys.get(&ft.track_id) else { continue };
        let crypto_track = ctx
            .crypto_tracks
            .iter()
            .find(|t| t.track_id == ft.track_id)
            .ok_or_else(|| invalid("no crypto metadata for a fragment's track"))?;
        if ft.layout.len() != ft.crypto.len() {
            return Err(invalid("sample count mismatch between trun and senc"));
        }
        let sizes: Vec<usize> = ft.layout.iter().map(|l| l.size as usize).collect();
        for (rs, rl) in split_into_contiguous_runs(&ft.layout) {
            let run_bytes: usize = sizes[rs..rs + rl].iter().sum();
            let start = ft.layout[rs]
                .file_offset
                .checked_sub(region_off)
                .and_then(|s| usize::try_from(s).ok())
                .ok_or_else(|| invalid("sample data lies before its moof"))?;
            let end = start.checked_add(run_bytes).filter(|&e| e <= region.len()).ok_or_else(|| {
                invalid("sample data lies outside its fragment (truncated or unsupported layout)")
            })?;
            decrypt_run_maybe_parallel(
                crypto_track,
                &ft.crypto[rs..rs + rl],
                key,
                ctx.all_keys,
                &mut region[start..end],
                &sizes[rs..rs + rl],
                scratch,
            )?;
        }
        if pending.contains(&ft.track_id)
            && let Some(idx) = ft
                .layout
                .iter()
                .zip(ft.crypto.iter())
                .position(|(l, e)| e.is_encrypted && l.is_sync)
        {
            pending.remove(&ft.track_id);
            if let Some(cfg) = ctx.codecs.get(&ft.track_id) {
                // Video is judged on one sync sample; audio on the first few encrypted ones.
                let wanted = key_sanity::wanted_samples(cfg);
                let samples: Vec<&[u8]> = (idx..ft.layout.len())
                    .filter(|&i| ft.crypto[i].is_encrypted)
                    .take(wanted)
                    .map(|i| {
                        let start = (ft.layout[i].file_offset - region_off) as usize;
                        &region[start..start + sizes[i]]
                    })
                    .collect();
                if let Err(detail) = key_sanity::check_samples(cfg, &samples, ctx.ffmpeg) {
                    return Err(CliError::KeySanityCheckFailed { track_id: ft.track_id, detail });
                }
            }
        }
    }
    neutralize_moof(&mut region[..moof_size]);
    Ok(())
}

pub(super) fn decrypt_fmp4(
    set: &ChunkSet,
    dest: Dest,
    keys: &[String],
    ffmpeg_path: Option<&Path>,
    rebase_tfdt: bool,
) -> CliResult<()> {
    let profile = profile_enabled();
    let t0 = Instant::now();
    let total = set.len();

    let boxes = scan_boxes(set)?;
    let moov = boxes
        .iter()
        .find(|b| &b.ty == b"moov")
        .ok_or_else(|| invalid("no moov box in the input"))?;
    let moofs: Vec<&Bx> = boxes.iter().filter(|b| &b.ty == b"moof").collect();
    let Some(first_moof) = moofs.first() else {
        return Err(invalid("no moof box: --in-place/--chunks need a fragmented MP4"));
    };
    if moov.offset >= first_moof.offset {
        return Err(invalid("moov must come before the first moof"));
    }
    // Refuse IV-in-mdat fragments up front, while nothing has been written yet.
    let mut moof_buf = Vec::new();
    for (n, m) in moofs.iter().enumerate() {
        if m.size > MAX_SINGLE_READ {
            return Err(invalid("a moof box is too large"));
        }
        moof_buf.resize(m.size as usize, 0);
        set.read_at(m.offset, &mut moof_buf)?;
        if cenc_decrypt::fragment_aux_info_requires_mdat(&moof_buf) {
            return Err(warn_aux_in_mdat(Some(n)));
        }
    }
    drop(moof_buf);
    let head_len = first_moof.offset;
    if head_len > MAX_SINGLE_READ {
        return Err(invalid("init section is too large"));
    }
    let mut head = vec![0u8; head_len as usize];
    set.read_at(0, &mut head)?;
    let moov_bytes = &head[moov.offset as usize..(moov.offset + moov.size) as usize];

    let crypto_tracks = cenc_decrypt::harvest_moov_crypto(moov_bytes)?;
    let trex = cenc_decrypt::harvest_trex_defaults(moov_bytes);
    let codecs: BTreeMap<u32, crate::CodecConfig> = cenc_decrypt::harvest_moov_track_specs(moov_bytes)?
        .1
        .into_iter()
        .map(|s| (s.track_id, s.codec_config))
        .collect();
    if !crypto_tracks.iter().any(|t| t.tenc.default_is_protected != 0) {
        return Err(invalid("no protected track found (already decrypted?)"));
    }
    let mut key_map = KeyMap::new();
    for spec in keys {
        let (kid, key) = parse_key(spec)?;
        key_map.insert(kid, key);
    }
    let mut track_keys: BTreeMap<u32, [u8; 16]> = BTreeMap::new();
    for t in &crypto_tracks {
        if t.tenc.default_is_protected == 0 {
            continue;
        }
        let key = key_map.get(&t.tenc.default_kid).ok_or(CliError::Flux(
            crate::Error::InvalidInput("no content key for the track's default_KID"),
        ))?;
        track_keys.insert(t.track_id, *key);
    }
    let target_ids: Vec<u32> = crypto_tracks.iter().map(|t| t.track_id).collect();
    let ctx = Ctx {
        crypto_tracks: &crypto_tracks,
        target_ids: &target_ids,
        trex: &trex,
        keys: &track_keys,
        all_keys: &key_map,
        codecs: &codecs,
        ffmpeg: ffmpeg_path,
    };

    let region_bounds: Vec<(u64, u64)> = moofs
        .iter()
        .enumerate()
        .map(|(i, m)| (m.offset, moofs.get(i + 1).map_or(total, |n| n.offset)))
        .collect();
    if region_bounds.iter().any(|(s, e)| e - s > MAX_REGION) {
        return Err(invalid("a fragment is larger than the supported region size"));
    }
    let n_regions = region_bounds.len();
    let read_region = |i: usize| -> io::Result<Vec<u8>> {
        let (s, e) = region_bounds[i];
        let mut buf = vec![0u8; (e - s) as usize];
        set.read_at(s, &mut buf)?;
        Ok(buf)
    };

    // Wrong-key check before anything is written: decrypt the first fragments in memory only.
    if key_sanity_check_enabled() {
        let mut pending: BTreeSet<u32> = track_keys.keys().copied().collect();
        let mut dts = BTreeMap::new();
        let mut scratch = cenc_decrypt::DecryptScratch::default();
        for (i, m) in moofs.iter().enumerate().take(PREFLIGHT_MAX_REGIONS) {
            if pending.is_empty() {
                break;
            }
            let mut buf = read_region(i)?;
            process_region(&ctx, m.offset, m.size as usize, &mut buf, &mut dts, &mut scratch, &mut pending)?;
        }
    }
    if profile {
        eprintln!(
            "[profile] inplace setup: {:?} ({} moof, {} bytes, {} track(s) keyed)",
            t0.elapsed(),
            moofs.len(),
            total,
            track_keys.len()
        );
    }

    let restored = patch_init(&mut head);
    if restored == 0 {
        return Err(invalid("could not locate any encv/enca sample entry to restore"));
    }

    enum Sink {
        InPlace,
        File(io::BufWriter<fs::File>),
    }
    let buf_cap = writer_buf_capacity().max(1 << 20);
    let mut sink = match &dest {
        Dest::InPlace => Sink::InPlace,
        Dest::File(path) => {
            let mut bw = io::BufWriter::with_capacity(buf_cap, fs::File::create(path)?);
            bw.write_all(&head)?;
            Sink::File(bw)
        }
        Dest::Stdout => {
            let mut bw = io::BufWriter::with_capacity(buf_cap, stdout_file()?);
            bw.write_all(&head)?;
            Sink::File(bw)
        }
    };

    let t1 = Instant::now();
    let mut decrypt_time = Duration::ZERO;
    let (rd_tx, rd_rx) = sync_channel::<io::Result<(usize, Vec<u8>)>>(3);
    let (wr_tx, wr_rx) = sync_channel::<(u64, Vec<u8>)>(3);
    let mut result: CliResult<()> = Ok(());
    let write_time = std::thread::scope(|s| {
        let reader = s.spawn(move || {
            for i in 0..n_regions {
                let msg = read_region(i).map(|b| (i, b));
                let failed = msg.is_err();
                if rd_tx.send(msg).is_err() || failed {
                    return;
                }
            }
        });
        let writer = s.spawn(move || -> io::Result<Duration> {
            let mut spent = Duration::ZERO;
            while let Ok((off, buf)) = wr_rx.recv() {
                let t = Instant::now();
                match &mut sink {
                    Sink::InPlace => set.write_at(off, &buf)?,
                    Sink::File(bw) => bw.write_all(&buf)?,
                }
                spent += t.elapsed();
            }
            if let Sink::File(bw) = &mut sink {
                bw.flush()?;
            }
            Ok(spent)
        });

        let mut next_dts = BTreeMap::new();
        let mut scratch = cenc_decrypt::DecryptScratch::default();
        let mut no_pending = BTreeSet::new();
        let mut tfdt_base = 0u64;
        let mut tfdt_base_seen = !rebase_tfdt;
        while let Ok(msg) = rd_rx.recv() {
            let (i, mut buf) = match msg {
                Ok(v) => v,
                Err(e) => {
                    result = Err(CliError::Io(e));
                    break;
                }
            };
            let m = moofs[i];
            let t = Instant::now();
            if let Err(e) = process_region(&ctx, m.offset, m.size as usize, &mut buf, &mut next_dts, &mut scratch, &mut no_pending) {
                result = Err(e);
                break;
            }
            if rebase_tfdt {
                let moof_len = m.size as usize;
                if !tfdt_base_seen
                    && let Some(&(value_off, width)) = tfdt_offsets(&buf[..moof_len]).first()
                {
                    tfdt_base = read_tfdt_value(&buf, value_off, width);
                    tfdt_base_seen = true;
                }
                if tfdt_base_seen {
                    rebase_moof_tfdt(&mut buf[..moof_len], tfdt_base);
                }
            }
            decrypt_time += t.elapsed();
            if wr_tx.send((m.offset, buf)).is_err() {
                result = Err(invalid("writer thread died"));
                break;
            }
        }
        drop(rd_rx);
        drop(wr_tx);
        let _ = reader.join();
        match writer.join() {
            Ok(Ok(d)) => d,
            Ok(Err(e)) => {
                if result.is_ok() {
                    result = Err(CliError::Io(e));
                }
                Duration::ZERO
            }
            Err(_) => {
                if result.is_ok() {
                    result = Err(invalid("writer thread panicked"));
                }
                Duration::ZERO
            }
        }
    });

    match (&dest, &result) {
        (Dest::File(path), Err(_)) => {
            let _ = fs::remove_file(path);
        }
        // The init goes last so an interrupted run still looks encrypted rather than half clear.
        (Dest::InPlace, Ok(())) => set.write_at(0, &head)?,
        _ => {}
    }
    result?;
    if profile {
        eprintln!(
            "[profile] inplace pass: {:?} (crypto={:?}, write={:?}); grand total: {:?}",
            t1.elapsed(),
            decrypt_time,
            write_time,
            t0.elapsed()
        );
    }
    Ok(())
}
