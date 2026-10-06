//! [`Stage`] — the incremental-drive contract every streaming stage in the
//! workspace will adopt (media-plane migration step 1).

use core::time::Duration;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash, Default)]
/// Monotonic time in nanoseconds for one pipeline run.
pub struct Timestamp(pub u64);

impl Timestamp {

    /// The zero timestamp.
    pub const ZERO: Timestamp = Timestamp(0);

    /// Creates a timestamp from nanoseconds.
    pub const fn from_nanos(nanos: u64) -> Self {
        Timestamp(nanos)
    }

    /// Returns the value in nanoseconds.
    pub const fn as_nanos(self) -> u64 {
        self.0
    }

    /// Elapsed time since `other`, saturating at zero.
    pub const fn saturating_sub(self, other: Timestamp) -> Duration {
        Duration::from_nanos(self.0.saturating_sub(other.0))
    }

    /// Adds `nanos`, saturating at `u64::MAX`.
    pub const fn checked_add_nanos(self, nanos: u64) -> Self {
        Timestamp(self.0.saturating_add(nanos))
    }

    /// Adds `duration`, saturating at `u64::MAX`.
    pub fn saturating_add(self, duration: Duration) -> Self {
        let nanos = u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);
        self.checked_add_nanos(nanos)
    }
}

#[cfg(feature = "std")]
impl Timestamp {
    /// Timestamp of `now` relative to `base`.
    pub fn from_instant(base: std::time::Instant, now: std::time::Instant) -> Self {
        let elapsed = now.saturating_duration_since(base);
        let nanos = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
        Timestamp(nanos)
    }
}

#[non_exhaustive]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
/// How many bytes a stage wants, or that it is saturated.
pub struct Demand {
    /// Bytes the stage would like next.
    pub want_bytes: usize,
    /// Whether the stage cannot accept more input.
    pub saturated: bool,
}

impl Demand {

    /// Demand for `want_bytes` bytes.
    pub const fn new(want_bytes: usize) -> Self {
        Demand {
            want_bytes,
            saturated: false,
        }
    }

    /// Demand signalling the stage is saturated.
    pub const fn saturated() -> Self {
        Demand {
            want_bytes: 0,
            saturated: true,
        }
    }
}

/// Incremental driver contract for a streaming stage.
pub trait Stage {
    /// Borrowed input type.
    type In<'a>;
    /// Output type.
    type Out;
    /// Error type.
    type Error;

    /// Feeds `input` at time `now`.
    fn feed(&mut self, input: Self::In<'_>, now: Timestamp) -> Result<(), Self::Error>;
    /// Returns the next output, if ready.
    fn poll(&mut self) -> Option<Self::Out>;
    /// Signals end of input and flushes.
    fn finish(&mut self) -> Result<(), Self::Error>;
    /// Next time the stage must be driven.
    fn next_deadline(&self) -> Option<Timestamp>;
    /// Notifies the stage that its deadline was reached.
    fn on_deadline(&mut self, now: Timestamp);
    /// Current input demand.
    fn demand(&self) -> Demand;
}
