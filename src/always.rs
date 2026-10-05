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

/// Minimum object size is 1 byte.
pub const DATA_MIN_LEN: usize = 1;

/// Max size of an Object (2^24, 16777216 bytes)
pub const DATA_MAX_LEN: usize = 16777216;

/// Minimum size of a valid CHAOS framed buffer (header + data).
pub const BUF_MIN_LEN: usize = HEADER + DATA_MIN_LEN;

/// Maximum size of a valid CHAOS framed buffer (header + data).
pub const BUF_MAX_LEN: usize = HEADER + DATA_MAX_LEN;

/// Location of Hash within object buffer.
pub const HASH_RANGE: Range<usize> = 0..DIGEST;

/// Location of info field within object buffer.
pub const INFO_RANGE: Range<usize> = DIGEST..DIGEST + INFO;
