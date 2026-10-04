//! Test helpers.

use crate::{DIGEST, HASH_RANGE, HEADER, Hash, INFO_RANGE};
use getrandom;

/// Create a random, valid object.
pub fn random_object(buf: &mut Vec<u8>, small: bool) -> Hash {
    // Generate random 4 byte info (all are valid)
    let mut info = [0; 4];
    getrandom::fill(&mut info).unwrap();
    if small {
        info[2] = 0;
    }
    buf.resize(HEADER, 0);
    buf[INFO_RANGE].copy_from_slice(&info);

    // Resize buffer based on size in info
    let info = u32::from_le_bytes(info);
    let size = ((info & 0x00ffffff) + 1) as usize;
    buf.resize(HEADER + size, 0);

    // Fill data portion of object with random bytes
    getrandom::fill(&mut buf[HEADER..]).unwrap();

    // Compute hash and copy into buffer
    let hash = Hash::compute(&buf[DIGEST..]);
    buf[HASH_RANGE].copy_from_slice(hash.as_bytes());

    // Return hash
    hash
}

/// Create a random hash using `getrandom`.
///
/// Note it will be impossible to find any object info + data combination
/// that matches this hash.
pub fn random_hash() -> Hash {
    let mut buf = [0; DIGEST];
    getrandom::fill(&mut buf).unwrap();
    Hash::from_bytes(buf)
}

/// Flip bit in a mutable buffer.
pub fn flip_bit(buf: &mut [u8], index: usize) {
    let i = index / 8;
    let b = (index % 8) as u8;
    buf[i] ^= 1 << b; // Flip bit `b` in byte `i`
}

/// Iteration through all 1-bit flip permutations in a hash.
#[derive(Debug)]
pub struct HashBitFlipper {
    orig: Hash,
    counter: usize,
}

impl HashBitFlipper {
    /// Create a new [HashBitFlipper].
    pub fn new(orig: &Hash) -> Self {
        Self {
            orig: *orig,
            counter: 0,
        }
    }
}

impl Iterator for HashBitFlipper {
    type Item = Hash;

    fn next(&mut self) -> Option<Self::Item> {
        if self.counter < self.orig.as_bytes().len() * 8 {
            let mut bad = *self.orig.as_bytes();
            flip_bit(&mut bad, self.counter);
            self.counter += 1;
            Some(Hash::from_bytes(bad))
        } else {
            None
        }
    }
}
