//! Zebra Factory Content Hash Addressable Object Store 🦓
//!
//! This is a place holder crate till development starts for realsies.

use blake2::{Blake2b, Digest, digest::consts::U45};
use core::ops::Range;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read, Seek};
use subtle::{Choice, ConstantTimeEq};

#[cfg(target_os = "windows")]
use std::os::windows::fs::FileExt;

#[cfg(not(target_os = "windows"))]
use std::os::unix::fs::FileExt;

type Blake2b360 = Blake2b<U45>;

/// Size of hash output digest (45 bytes).
pub const DIGEST: usize = 45;

pub const INFO: usize = 4;

pub const HEADER: usize = DIGEST + INFO;

pub const HASH_RANGE: Range<usize> = 0..DIGEST;
pub const INFO_RANGE: Range<usize> = DIGEST..DIGEST + INFO;

/// Size of hex-encoded hash (90 bytes).
pub const HEXDIGEST: usize = DIGEST * 2;

/// Size of Zbase32-encoded hash (72 bytes).
pub const Z32DIGEST: usize = DIGEST * 8 / 5;

/// Max size of an Object (2^24, 16777216 bytes)
pub const OBJECT_MAX_SIZE: usize = 16777216;

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

/// Buffer containing the 360-bit (45-byte) BLAKE2b hash, with ConstantTimeEq.
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
    /// Compute the 360-bit BLAKE2b hash of `input`, returning `Hash`.
    pub fn compute(input: &[u8]) -> Self {
        assert!(!input.is_empty());
        let mut hasher = Blake2b360::new();
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

fn build_info(size: usize, kind: u8) -> Result<u32, ObjectError> {
    if !(1..=OBJECT_MAX_SIZE).contains(&size) {
        Err(ObjectError::Size)
    } else {
        Ok((size - 1) as u32 | (kind as u32) << 24)
    }
}

fn build_header(data: &[u8], kind: u8) -> Result<(Hash, u32), ObjectError> {
    let info = build_info(data.len(), kind)?;
    let mut hasher = Blake2b360::new();
    hasher.update(&info.to_le_bytes());
    hasher.update(data);
    let output = hasher.finalize();
    let hash = Hash::from_bytes(output.into());
    Ok((hash, info))
}

fn extract_info(buf: &[u8]) -> (usize, u8) {
    let info = u32::from_le_bytes(buf.try_into().unwrap());
    let size = ((info & 0x00ffffff) + 1) as usize;
    let kind = (info >> 24) as u8;
    (size, kind)
}

fn extract_header(buf: &[u8]) -> Result<(Hash, usize, u8), ObjectError> {
    if buf.len() < HEADER {
        Err(ObjectError::Header)
    } else {
        let hash = Hash::from_slice(&buf[0..DIGEST]).unwrap();
        let (size, kind) = extract_info(&buf[INFO_RANGE]);
        Ok((hash, size, kind))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ObjectError {
    Header,
    Size,
    Content,
}

#[derive(Debug, Eq)]
pub struct Object<'a> {
    hash: Hash,
    kind: u8,
    data: &'a [u8],
}

impl<'a> Object<'a> {
    pub fn new(buf: &'a [u8]) -> Result<Self, ObjectError> {
        let (hash, size, kind) = extract_header(buf)?;
        if buf.len() < HEADER + size {
            return Err(ObjectError::Size);
        }
        let data = &buf[HEADER..HEADER + size];
        assert_eq!(data.len(), size);
        let computed = Hash::compute(data);
        if hash != computed {
            Err(ObjectError::Content)
        } else {
            Ok(Self { hash, kind, data })
        }
    }

    pub fn build(data: &'a [u8], kind: u8) -> Result<Self, ObjectError> {
        let (hash, info) = build_header(data, kind)?;
        Ok(Self { hash, kind, data })
    }

    pub fn hash(&self) -> &Hash {
        &self.hash
    }

    pub fn size(&self) -> usize {
        self.data.len()
    }

    pub fn kind(&self) -> u8 {
        self.kind
    }

    pub fn data(&self) -> &[u8] {
        self.data
    }
}

impl<'a> PartialEq for Object<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

pub struct ObjectBuf {
    buf: Vec<u8>,
}

impl ObjectBuf {
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(HEADER + 4096),
        }
    }

    pub fn as_mut_header(&mut self) -> &mut [u8] {
        &mut self.buf[0..HEADER]
    }

    pub fn as_mut_data(&mut self) -> &mut [u8] {
        let (size, _) = extract_info(&self.buf[INFO_RANGE]);
        self.buf.resize(HEADER + size, 0);
        &mut self.buf[HEADER..]
    }

    pub fn as_mut_buf(&mut self, size: usize) -> &mut [u8] {
        self.buf.resize(HEADER + size, 0);
        &mut self.buf
    }

    pub fn object(&self) -> Result<Object<'_>, ObjectError> {
        Object::new(&self.buf)
    }
}

fn read_retry(file: &mut BufReader<File>, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut read = 0;
    loop {
        let new = file.read(&mut buf[read..])?;
        read += new;
        if read == buf.len() || new == 0 {
            return Ok(read);
        }
    }
}

pub struct Entry {
    size: usize,
    offset: u64,
}

impl Entry {
    pub fn new(size: usize, offset: u64) -> Self {
        Self { size, offset }
    }
}

pub struct Store {
    file: std::fs::File,
    index: HashMap<Hash, Entry>,
    offset: u64,
}

impl Store {
    pub fn reindex(&mut self, object_buf: &mut ObjectBuf) -> std::io::Result<()> {
        self.index.clear();
        self.offset = 0;
        self.file.rewind()?;
        let mut file = BufReader::with_capacity(1024 * 128, self.file.try_clone()?);
        loop {
            if read_retry(&mut file, object_buf.as_mut_header())? < HEADER {
                return Ok(());
            }
            file.read_exact(object_buf.as_mut_data())?;
            let object = object_buf.object().unwrap();
            let entry = Entry::new(object.size(), self.offset);
            self.index.insert(*object.hash(), entry);
            self.offset += (HEADER + object.size()) as u64;
        }
        Ok(())
    }

    pub fn load(&mut self, object_buf: &mut ObjectBuf, hash: &Hash) -> std::io::Result<bool> {
        if let Some(entry) = self.index.get(hash) {
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_info() {
        assert_eq!(build_info(0, 0), Err(ObjectError::Size));
        assert_eq!(build_info(0, 255), Err(ObjectError::Size));
        assert_eq!(build_info(OBJECT_MAX_SIZE + 1, 0), Err(ObjectError::Size));
        assert_eq!(build_info(OBJECT_MAX_SIZE + 1, 255), Err(ObjectError::Size));

        assert_eq!(build_info(1, 0), Ok(0));
        assert_eq!(build_info(1, 255), Ok(255 << 24));
        assert_eq!(
            build_info(OBJECT_MAX_SIZE, 0),
            Ok((OBJECT_MAX_SIZE - 1) as u32)
        );
        assert_eq!(build_info(OBJECT_MAX_SIZE, 255), Ok(u32::MAX));
    }

    #[test]
    fn test_extract_info() {
        assert_eq!(extract_info(&[0, 0, 0, 0]), (1, 0));
        assert_eq!(extract_info(&[0, 0, 0, 255]), (1, 255));
        assert_eq!(extract_info(&[1, 0, 0, 0]), (2, 0));
        assert_eq!(extract_info(&[1, 0, 0, 255]), (2, 255));
        assert_eq!(extract_info(&[255, 255, 255, 0]), (OBJECT_MAX_SIZE, 0));
        assert_eq!(extract_info(&[255, 255, 255, 255]), (OBJECT_MAX_SIZE, 255));
    }

    #[test]
    fn test_object() {
        assert_eq!(Object::new(&[]), Err(ObjectError::Header));
        assert_eq!(Object::new(&[0; HEADER]), Err(ObjectError::Size));
        assert_eq!(Object::new(&[0; HEADER + 1]), Err(ObjectError::Content));

        let mut buf = [0; HEADER + 1];
        let hash = Hash::compute(&[0]);
        buf[0..DIGEST].copy_from_slice(hash.as_bytes());
        let obj = Object::new(&buf).unwrap();
        assert_eq!(obj.hash(), &hash);
        assert_eq!(obj.size(), 1);
        assert_eq!(obj.kind(), 0);
        assert_eq!(obj.data(), &[0; 1]);

        let mut buf = [0; HEADER + 2];
        let hash = Hash::compute(&[0; 2]);
        buf[0..DIGEST].copy_from_slice(hash.as_bytes());
        buf[DIGEST] = 1;
        let obj = Object::new(&buf).unwrap();
        assert_eq!(obj.hash(), &hash);
        assert_eq!(obj.size(), 2);
        assert_eq!(obj.kind(), 0);
        assert_eq!(obj.data(), &[0; 2]);

        assert_eq!(Object::new(&buf[0..HEADER + 1]), Err(ObjectError::Size));
    }
}
