//! `eventframe` — ISO BMFF / DASH Event Message Box (`emsg`): inband DASH/CMAF
//! timed events (SCTE 35 splice signalling, ID3 metadata, ad/tracking triggers).

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]

extern crate alloc;

mod emsg;
mod error;
mod version;

pub use emsg::{
    EMSG_BOX_TYPE, EMSG_FLAGS, EmsgBox, FULLBOX_HEADER_LEN, PresentationTime, SCTE35_SCHEME_PREFIX,
    STRING_TERMINATOR,
};
pub use error::{Error, Result};
pub use version::{EmsgVersion, VERSION_0, VERSION_1};
