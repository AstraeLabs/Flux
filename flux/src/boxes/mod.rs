//! ISOBMFF box types shared across the demux/mux spokes

pub mod bitreader;
pub mod box_types;
pub mod init_segment;
pub mod movie_fragment;
pub mod sample_entries;
pub mod segments;
pub mod subtitle_entries;
pub mod timing;
pub mod visual_ext;

/// Capacity to pre-allocate for `count` declared elements of `elem_size` bytes when only
/// `remaining` bytes of input are left; never trusts the declared count beyond what the
/// input could actually hold.
#[inline]
pub(crate) fn bounded_capacity(count: usize, elem_size: usize, remaining: usize) -> usize {
    count.min(remaining / elem_size.max(1))
}
