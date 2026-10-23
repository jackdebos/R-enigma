//! Host execution options for HC/PE attacks.
//!
//! These choose how the host runs an attack, never what it computes: they are not
//! request fields (`docs/protocol.md` §11), and a completed run produces the same
//! public output for every accepted value.

use std::num::NonZeroUsize;

/// How many worker threads an attack may use for its outer-key phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutionOptions {
    threads: NonZeroUsize,
}

impl ExecutionOptions {
    /// Largest accepted thread count.
    pub const MAX_THREADS: usize = 256;

    /// One worker thread: the outer keys run on the calling thread.
    pub const fn serial() -> Self {
        Self {
            threads: NonZeroUsize::MIN,
        }
    }

    /// `threads` workers, or `None` outside `1..=MAX_THREADS`.
    pub fn with_threads(threads: usize) -> Option<Self> {
        NonZeroUsize::new(threads)
            .filter(|threads| threads.get() <= Self::MAX_THREADS)
            .map(|threads| Self { threads })
    }

    /// Half of `available` logical CPUs, at least one and at most `MAX_THREADS`.
    pub fn half_of(available: NonZeroUsize) -> Self {
        let threads = (available.get() / 2).clamp(1, Self::MAX_THREADS);
        Self::with_threads(threads).unwrap_or_else(Self::serial)
    }

    /// Requested worker thread count.
    pub fn threads(self) -> NonZeroUsize {
        self.threads
    }
}

impl Default for ExecutionOptions {
    fn default() -> Self {
        Self::serial()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thread_bounds_and_default_half() {
        assert_eq!(ExecutionOptions::with_threads(0), None);
        assert_eq!(ExecutionOptions::with_threads(257), None);
        for threads in [1, 2, 8, 256] {
            let options = ExecutionOptions::with_threads(threads).unwrap();
            assert_eq!(options.threads().get(), threads);
        }
        assert_eq!(ExecutionOptions::default(), ExecutionOptions::serial());
        for (available, half) in [(1, 1), (2, 1), (3, 1), (12, 6), (13, 6), (1024, 256)] {
            let available = NonZeroUsize::new(available).unwrap();
            assert_eq!(ExecutionOptions::half_of(available).threads().get(), half);
        }
    }
}
