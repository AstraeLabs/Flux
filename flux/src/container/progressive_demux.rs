//! Progressive (single-file, non-fragmented) MP4 demux

use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::init_segment::{
    ChunkLargeOffsetBox, ChunkOffsetBox, SampleSizeBox, SampleToChunkBox, StblChild,
    SyncSampleBox, TrackBox,
};
use crate::timing::{CompositionOffsetBox, TimeToSampleBox};

pub(crate) struct StblSampleLayout {
    pub(crate) file_offset: u64,
    pub(crate) size: u32,
    pub(crate) dts: i64,
    pub(crate) pts: i64,
    pub(crate) duration: u32,
    pub(crate) is_sync: bool,
}

pub(crate) fn stbl_sample_layout(trak: &TrackBox) -> Result<Vec<StblSampleLayout>> {
    let stbl = trak
        .mdia
        .as_ref()
        .and_then(|m| m.minf.as_ref())
        .and_then(|m| m.stbl.as_ref())
        .ok_or(Error::UnexpectedBox { expected: "stbl" })?;

    let stts = stbl
        .children
        .iter()
        .find_map(|c| match c {
            StblChild::Stts(b) => Some(b),
            _ => None,
        })
        .ok_or(Error::UnexpectedBox { expected: "stts" })?;
    let ctts = stbl.children.iter().find_map(|c| match c {
        StblChild::Ctts(b) => Some(b),
        _ => None,
    });
    let stss = stbl.children.iter().find_map(|c| match c {
        StblChild::Stss(b) => Some(b),
        _ => None,
    });
    let stsz = stbl
        .children
        .iter()
        .find_map(|c| match c {
            StblChild::Stsz(b) => Some(b),
            _ => None,
        })
        .ok_or(Error::UnexpectedBox { expected: "stsz" })?;
    let stsc = stbl
        .children
        .iter()
        .find_map(|c| match c {
            StblChild::Stsc(b) => Some(b),
            _ => None,
        })
        .ok_or(Error::UnexpectedBox { expected: "stsc" })?;
    let co64 = stbl.children.iter().find_map(|c| match c {
        StblChild::Co64(b) => Some(b),
        _ => None,
    });
    let stco = stbl.children.iter().find_map(|c| match c {
        StblChild::Stco(b) => Some(b),
        _ => None,
    });

    let chunk_offsets_v = chunk_offsets(co64, stco)?;
    let samples_per_chunk = expand_stsc(stsc, chunk_offsets_v.len());
    let total_samples: usize = samples_per_chunk.iter().map(|&n| n as usize).sum();

    let layout = chunk_layout(&chunk_offsets_v, &samples_per_chunk, stsz, total_samples)?;
    let durations = expand_stts(stts, total_samples)?;
    let composition_offsets = expand_ctts(ctts, total_samples)?;
    let sync_flags = expand_stss(stss, total_samples);

    let mut out = Vec::with_capacity(total_samples);
    let mut next_dts: i64 = 0;
    for i in 0..total_samples {
        let (start, size) = layout[i];
        out.push(StblSampleLayout {
            file_offset: start as u64,
            size: size as u32,
            dts: next_dts,
            pts: next_dts + composition_offsets[i] as i64,
            duration: durations[i],
            is_sync: sync_flags[i],
        });
        next_dts += durations[i] as i64;
    }
    Ok(out)
}

fn chunk_offsets(
    co64: Option<&ChunkLargeOffsetBox>,
    stco: Option<&ChunkOffsetBox>,
) -> Result<Vec<u64>> {
    if let Some(co64) = co64 {
        Ok(co64.entries.clone())
    } else if let Some(stco) = stco {
        Ok(stco.entries.iter().map(|&o| o as u64).collect())
    } else {
        Err(Error::UnexpectedBox {
            expected: "stco or co64",
        })
    }
}

fn expand_stsc(stsc: &SampleToChunkBox, num_chunks: usize) -> Vec<u32> {
    let mut table = alloc::vec![0u32; num_chunks];
    for (i, entry) in stsc.entries.iter().enumerate() {
        let start = entry.first_chunk as usize;
        let end = stsc
            .entries
            .get(i + 1)
            .map(|next| next.first_chunk as usize)
            .unwrap_or(num_chunks + 1);
        for chunk in start..end {
            if chunk >= 1 && chunk <= num_chunks {
                table[chunk - 1] = entry.samples_per_chunk;
            }
        }
    }
    table
}

fn chunk_layout(
    chunk_offsets: &[u64],
    samples_per_chunk: &[u32],
    stsz: &SampleSizeBox,
    total_samples: usize,
) -> Result<Vec<(usize, usize)>> {
    let mut layout = Vec::with_capacity(total_samples);
    let mut sample_index = 0usize;
    for (chunk, &count) in samples_per_chunk.iter().enumerate() {
        let mut cursor = chunk_offsets[chunk];
        for _ in 0..count {
            let size = sample_size(stsz, sample_index)?;
            let start = usize::try_from(cursor)
                .map_err(|_| Error::InvalidInput("chunk offset exceeds addressable range"))?;
            layout.push((start, size));
            cursor += size as u64;
            sample_index += 1;
        }
    }
    if layout.len() != total_samples {
        return Err(Error::InvalidInput(
            "stsc-derived sample count does not match chunk layout",
        ));
    }
    Ok(layout)
}

fn sample_size(stsz: &SampleSizeBox, index: usize) -> Result<usize> {
    if stsz.sample_size != 0 {
        Ok(stsz.sample_size as usize)
    } else {
        stsz.entries
            .get(index)
            .map(|&s| s as usize)
            .ok_or(Error::InvalidInput("stsz has fewer entries than samples"))
    }
}

pub(crate) fn expand_stts(stts: &TimeToSampleBox, total_samples: usize) -> Result<Vec<u32>> {
    let mut out = Vec::with_capacity(total_samples);
    for entry in &stts.entries {
        for _ in 0..entry.sample_count {
            out.push(entry.sample_delta);
        }
    }
    if out.len() != total_samples {
        return Err(Error::InvalidInput(
            "stts sample count does not match chunk layout",
        ));
    }
    Ok(out)
}

pub(crate) fn expand_ctts(
    ctts: Option<&CompositionOffsetBox>,
    total_samples: usize,
) -> Result<Vec<i32>> {
    let Some(ctts) = ctts else {
        return Ok(alloc::vec![0i32; total_samples]);
    };
    let mut out = Vec::with_capacity(total_samples);
    for entry in &ctts.entries {
        for _ in 0..entry.sample_count {
            out.push(entry.sample_offset);
        }
    }
    if out.len() != total_samples {
        return Err(Error::InvalidInput(
            "ctts sample count does not match chunk layout",
        ));
    }
    Ok(out)
}

fn expand_stss(stss: Option<&SyncSampleBox>, total_samples: usize) -> Vec<bool> {
    let Some(stss) = stss else {
        return alloc::vec![true; total_samples];
    };
    let mut flags = alloc::vec![false; total_samples];
    for &one_based in &stss.entries {
        let idx = one_based as usize;
        if idx >= 1 && idx <= total_samples {
            flags[idx - 1] = true;
        }
    }
    flags
}