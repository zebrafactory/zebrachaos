use core::ops::Range;

/// Size of hash output digest (45 bytes).
pub const DIGEST: usize = 45;

/// Size of hex-encoded hash (90 bytes).
pub const HEXDIGEST: usize = DIGEST * 2;

/// Size of Zbase32-encoded hash (72 bytes).
pub const Z32DIGEST: usize = DIGEST * 8 / 5;

/// Size of info portion of object header (4 bytes).
pub const INFO: usize = 4;

/// Size of object header (49 bytes).
pub const HEADER: usize = DIGEST + INFO;

/// Max size of an Object (2^24, 16777216 bytes)
pub const OBJECT_MAX_SIZE: usize = 16777216;

/// Location of Hash within object buffer.
pub const HASH_RANGE: Range<usize> = 0..DIGEST;

/// Location of info field within object buffer.
pub const INFO_RANGE: Range<usize> = DIGEST..DIGEST + INFO;
