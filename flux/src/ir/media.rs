//! The neutral hub IR — [`Media`].

use alloc::string::String;
use alloc::vec::Vec;

use super::Track;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SkippedTrack {
    pub fourcc: String,
    pub reason: String,
}

impl SkippedTrack {
    pub fn new(fourcc: String, reason: String) -> Self {
        Self { fourcc, reason }
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Media {
    pub tracks: Vec<Track>,
    pub movie_timescale: u32,
    pub skipped: Vec<SkippedTrack>,
}

impl Media {
    pub fn new(tracks: Vec<Track>, movie_timescale: u32) -> Self {
        Self {
            tracks,
            movie_timescale,
            skipped: Vec::new(),
        }
    }
}
