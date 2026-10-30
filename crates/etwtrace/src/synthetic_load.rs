//! A single-threaded load that makes every kind of counter tick: it chases pointers around a random cycle through 64 MB
//! (bigger than the last level cache, so loads miss), taking a branch that depends on the loaded value.

use std::time::{Duration, Instant};

pub struct SyntheticLoad {
    /// next[i] is the element visited after i.
    next: Vec<u32>,
    current: u32,
    odd: u64,
}

const ELEMENTS: u32 = 1 << 24;

impl SyntheticLoad {
    pub fn new() -> Self {
        // Sattolo's algorithm: a random permutation that is a single cycle through every element.  A fixed seed makes
        // the load the same every run.
        let mut next: Vec<u32> = (0..ELEMENTS).collect();
        let mut random = SplitMix64(42);
        for i in (1..next.len()).rev() {
            let j = usize::try_from(random.next().checked_rem(i as u64).unwrap_or(0)).unwrap_or(0);
            next.swap(i, j);
        }

        Self { next, current: 0, odd: 0 }
    }

    pub fn run(&mut self, duration: Duration) {
        let start = Instant::now();
        while start.elapsed() < duration {
            for _ in 0..4096 {
                self.current = self.next.get(self.current as usize).copied().unwrap_or(0);
                if self.current & 1 != 0 {
                    self.odd = self.odd.wrapping_add(1); // A store on one side only, so the branch stays a branch.
                }
            }
        }

        std::hint::black_box((self.current, self.odd));
    }
}

/// SplitMix64, a small, good enough random number generator.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}
