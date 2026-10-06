//! Shared primitives for the dvb_si / dvb_t2mi / dvb_bbframe family.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod bcd;
pub mod bits;
pub mod cenc;
pub mod crc32_mpeg2;
pub mod hex;
pub mod mux;
pub mod stage;
pub mod time;
pub mod traits;

pub use cenc::CencScheme;
pub use mux::{Decrypt, Encrypt, Package, Unpackage};
pub use stage::{Demand, Stage, Timestamp};
pub use traits::{Parse, Serialize};

#[macro_export]
/// Implements `Display` for a spec type.
macro_rules! impl_spec_display {
    ($ty:ty) => {
        impl ::core::fmt::Display for $ty {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(self.name())
            }
        }
    };
    ($ty:ty, $($resv:ident),+ $(,)?) => {
        impl ::core::fmt::Display for $ty {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                match self {
                    $( Self::$resv(v) => ::core::write!(f, "{}(0x{:02X})", self.name(), v), )+
                    other => f.write_str(other.name()),
                }
            }
        }
    };
}
