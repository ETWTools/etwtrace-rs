//! A small, fast hasher (the FxHash scheme rustc uses) for the report's integer and short string keys.  The keys come
//! from a local trace, so resistance to hash flooding is not needed, and SipHash's cost shows on hot event paths.

use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasherDefault, Hasher};

#[derive(Clone, Copy, Debug, Default)]
pub struct FxHasher {
    hash: u64,
}

const SEED: u64 = 0xf135_7aea_2e62_a9c5;

impl FxHasher {
    #[inline]
    fn add(&mut self, word: u64) {
        self.hash = self.hash.wrapping_add(word).wrapping_mul(SEED);
    }
}

impl Hasher for FxHasher {
    fn write(&mut self, bytes: &[u8]) {
        let (words, rest) = bytes.as_chunks::<8>();
        for &word in words {
            self.add(u64::from_le_bytes(word));
        }

        if !rest.is_empty() {
            let mut word = [0u8; 8];
            for (target, source) in word.iter_mut().zip(rest) {
                *target = *source;
            }

            self.add(u64::from_le_bytes(word) ^ u64::try_from(rest.len()).unwrap_or(0));
        }
    }

    fn write_u8(&mut self, value: u8) {
        self.add(u64::from(value));
    }

    fn write_u16(&mut self, value: u16) {
        self.add(u64::from(value));
    }

    fn write_u32(&mut self, value: u32) {
        self.add(u64::from(value));
    }

    fn write_u64(&mut self, value: u64) {
        self.add(value);
    }

    fn write_usize(&mut self, value: usize) {
        self.add(value as u64);
    }

    fn finish(&self) -> u64 {
        self.hash.rotate_left(26)
    }
}

pub type FxMap<K, V> = HashMap<K, V, BuildHasherDefault<FxHasher>>;
pub type FxSet<K> = HashSet<K, BuildHasherDefault<FxHasher>>;
