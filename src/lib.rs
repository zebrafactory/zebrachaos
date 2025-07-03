//! Zebra Factory Content Hash Addressable Object Store 🦓
//!
//! This is a place holder crate till development starts for realsies.

use blake2::{Blake2b, Digest, digest::consts::U40};
use subtle::{Choice, ConstantTimeEq};

type Blake2b320 = Blake2b<U40>;

/// Size of hash output digest (40 bytes).
pub const DIGEST: usize = 40;

/// Size of hex-encoded hash (80 bytes).
pub const HEXDIGEST: usize = DIGEST * 2;

/// Size of Zbase32-encoded hash (64 bytes).
pub const Z32DIGEST: usize = DIGEST * 8 / 5;

/// Error when trying to decode a Zbase32 encoded [Hash](crate::Hash).
#[derive(Debug, PartialEq, Eq)]
pub enum Zbase32Error {
    /// The length is wrong
    BadLen(usize),

    /// Contains an invalid byte
    BadByte(u8),
}

// Encode in Zbase32.
fn zbase32_enc_into(src: &[u8], dst: &mut [u8]) {
    assert_eq!(dst.len(), src.len() * 8 / 5);
    let table = b"456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    for i in 0..src.len() / 5 {
        // Pack 40 bits into taxi (8 bits at a time)
        let a = i * 5;
        let taxi = src[a] as u64;
        let taxi = src[a + 1] as u64 | taxi << 8;
        let taxi = src[a + 2] as u64 | taxi << 8;
        let taxi = src[a + 3] as u64 | taxi << 8;
        let taxi = src[a + 4] as u64 | taxi << 8;

        // Unpack 40 bits from taxi (5 bits at a time)
        let b = i * 8;
        dst[b] = table[((taxi >> 35) & 31) as usize];
        dst[b + 1] = table[((taxi >> 30) & 31) as usize];
        dst[b + 2] = table[((taxi >> 25) & 31) as usize];
        dst[b + 3] = table[((taxi >> 20) & 31) as usize];
        dst[b + 4] = table[((taxi >> 15) & 31) as usize];
        dst[b + 5] = table[((taxi >> 10) & 31) as usize];
        dst[b + 6] = table[((taxi >> 5) & 31) as usize];
        dst[b + 7] = table[(taxi & 31) as usize];
    }
}

fn zbase32_dec_into(src: &[u8], dst: &mut [u8]) -> Result<(), Zbase32Error> {
    assert_eq!(dst.len(), DIGEST);
    if src.len() != Z32DIGEST {
        return Err(Zbase32Error::BadLen(src.len()));
    }

    fn zb32_to_u64(byte: u8) -> Result<u64, Zbase32Error> {
        match byte {
            b'4'..=b'9' => Ok((byte - b'4').into()),
            b'A'..=b'Z' => Ok((byte - b'A' + 6).into()),
            _ => Err(Zbase32Error::BadByte(byte)),
        }
    }

    for i in 0..src.len() / 8 {
        let a = i * 8;
        let taxi: u64 = zb32_to_u64(src[a])?;
        let taxi = zb32_to_u64(src[a + 1])? | taxi << 5;
        let taxi = zb32_to_u64(src[a + 2])? | taxi << 5;
        let taxi = zb32_to_u64(src[a + 3])? | taxi << 5;
        let taxi = zb32_to_u64(src[a + 4])? | taxi << 5;
        let taxi = zb32_to_u64(src[a + 5])? | taxi << 5;
        let taxi = zb32_to_u64(src[a + 6])? | taxi << 5;
        let taxi = zb32_to_u64(src[a + 7])? | taxi << 5;

        let b = i * 5;
        dst[b] = (taxi >> 32) as u8;
        dst[b + 1] = (taxi >> 24) as u8;
        dst[b + 2] = (taxi >> 16) as u8;
        dst[b + 3] = (taxi >> 8) as u8;
        dst[b + 4] = taxi as u8;
    }
    Ok(())
}

/// Error when trying to decode a hex encoded [Hash](crate::Hash).
#[derive(Debug, PartialEq, Eq)]
pub enum HexError {
    /// The length in wrong
    BadLen(usize),

    /// Contains an invalid byte
    BadByte(u8),
}

/// Buffer containing the 320-bit (40-byte) BLAKE2b hash, with ConstantTimeEq.
///
/// # Examples
///
/// ```
/// use zf_zebrachaos::Hash;
/// let hash = Hash::compute(b"hello, world");
/// ```
#[derive(Eq, Clone, Copy, PartialOrd, Ord)]
pub struct Hash {
    value: [u8; DIGEST],
}

impl Hash {
    /// Compute the 320-bit BLAKE2b hash of `input`, returning `Hash`.
    pub fn compute(input: &[u8]) -> Self {
        assert!(!input.is_empty());
        let mut hasher = Blake2b320::new();
        hasher.update(input);
        let output = hasher.finalize();
        Self::from_bytes(output.into())
    }

    /// Load from a slice
    pub fn from_slice(slice: &[u8]) -> Result<Self, core::array::TryFromSliceError> {
        Ok(Self::from_bytes(slice.try_into()?))
    }

    /// Create from bytes.
    pub const fn from_bytes(value: [u8; DIGEST]) -> Self {
        Self { value }
    }

    /// The raw bytes of the `Hash`.
    pub const fn as_bytes(&self) -> &[u8; DIGEST] {
        &self.value
    }

    /// Constant time check of whether every byte is a zero.
    pub fn is_zeros(&self) -> bool {
        // FIXME: Do this without comparing to another [u8; DIGEST]
        self.value.ct_eq(&[0; DIGEST]).into()
    }

    /// Decode a `Hash` from lowercase hexadecimal.
    pub fn from_hex(hex: impl AsRef<[u8]>) -> Result<Self, HexError> {
        // Totally copied from blake3::Hash::from_hex()
        fn hex_val(byte: u8) -> Result<u8, HexError> {
            match byte {
                b'a'..=b'f' => Ok(byte - b'a' + 10),
                b'0'..=b'9' => Ok(byte - b'0'),
                _ => Err(HexError::BadByte(byte)),
            }
        }
        let hex_bytes: &[u8] = hex.as_ref();
        if hex_bytes.len() != HEXDIGEST {
            return Err(HexError::BadLen(hex_bytes.len()));
        }
        let mut hash_bytes: [u8; DIGEST] = [0; DIGEST];
        for i in 0..DIGEST {
            hash_bytes[i] = 16 * hex_val(hex_bytes[2 * i])? + hex_val(hex_bytes[2 * i + 1])?;
        }
        Ok(Self::from_bytes(hash_bytes))
    }

    /// Encode in lowercase hexidecimal
    pub fn to_hex(&self) -> arrayvec::ArrayString<HEXDIGEST> {
        // Totally copied from blake3::Hash.to_hex()
        let mut hex = arrayvec::ArrayString::new();
        let table = b"0123456789abcdef";
        for &b in self.value.iter() {
            hex.push(table[(b >> 4) as usize] as char);
            hex.push(table[(b & 0xf) as usize] as char);
        }
        hex
    }

    /// Decode Zbase32 encoded Hash.
    pub fn from_z32(src: &[u8]) -> Result<Self, Zbase32Error> {
        let mut dst = [0; DIGEST];
        zbase32_dec_into(src, &mut dst)?;
        Ok(Self::from_bytes(dst))
    }

    /// Encode in Zbase32.
    pub fn to_z32(&self) -> [u8; Z32DIGEST] {
        let mut z32 = [0; Z32DIGEST];
        zbase32_enc_into(&self.value, &mut z32);
        z32
    }

    /// Encode as Zbase32 String
    pub fn to_z32_string(&self) -> String {
        let mut z32 = vec![0; Z32DIGEST];
        zbase32_enc_into(&self.value, &mut z32);
        String::from_utf8(z32).unwrap()
    }
}

impl ConstantTimeEq for Hash {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.value.ct_eq(&other.value)
    }
}

impl PartialEq for Hash {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl core::hash::Hash for Hash {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.value.hash(state)
    }
}

impl core::fmt::Debug for Hash {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let z32 = self.to_z32_string();
        f.debug_tuple("Hash").field(&z32).finish()
    }
}

impl core::fmt::Display for Hash {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str(&self.to_z32_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {}
}
