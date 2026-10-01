use crate::Hash;
use crate::always::*;

/// Error returned when building and validating objects.
#[derive(Debug, PartialEq)]
pub enum ObjectError {
    /// Length of full buffer does not match expected value.
    BufLen,

    /// Buffer length outside `(HEADER + 1..HEADER + OBJECT_MAX_SIZE)`
    BufLenBounds,

    /// Bytes needed for header are not available in buffer.
    HeaderLen,

    /// Length of object data does not match expected value.
    DataLen,

    /// Length of object data is zero or greater than `OBJECT_MAX_SIZE`.
    DataLenBounds,

    /// Content hash does not match hash in framing buffer.
    Content,

    /// Hash computed over object info and data does not match expected hash.
    Hash,
}

/// The CHOAS framing header (hash, size, kind).
///
/// # Examples
///
/// ```
/// use zf_zebrachaos::{HEADER, ObjectHeader};
///
/// let kind = 1;
/// let data = b"The object's data";
/// let header = ObjectHeader::build(kind, data).unwrap();
/// assert_eq!(header.size(), 17);
/// assert_eq!(header.kind(), 1);
/// let mut buf = [0; HEADER];
/// header.write_to_buf(&mut buf).unwrap();
/// let header_again = ObjectHeader::read_from_buf(&buf).unwrap();
/// assert_eq!(header, header_again);
/// ```
#[derive(Debug, PartialEq, Clone)]
pub struct ObjectHeader {
    hash: Hash,
    info: u32,
}

impl ObjectHeader {
    /// New instance.
    pub fn new(hash: Hash, info: u32) -> Self {
        Self { hash, info }
    }

    /// Compute hash and info corresponding to `kind` and `data`.
    pub fn build(kind: u8, data: &[u8]) -> Result<Self, ObjectError> {
        if !(1..=OBJECT_MAX_SIZE).contains(&data.len()) {
            Err(ObjectError::DataLenBounds)
        } else {
            let info = (data.len() - 1) as u32 | (kind as u32) << 24;
            let hash = Hash::compute_with_info(info, data);
            Ok(Self { hash, info })
        }
    }

    /// Valadite object data against this header.
    ///
    /// If you need access to this `ObjectHeader` instance  and `buf` after this method succeeds,
    /// use [Object::header()] and [Object::data()].
    pub fn validate_object<'a>(self, buf: &'a [u8]) -> Result<Object<'a>, ObjectError> {
        if self.full_size() != buf.len() {
            Err(ObjectError::BufLen)
        } else if self.hash != Hash::compute(&buf[DIGEST..]) {
            Err(ObjectError::Hash)
        } else {
            Ok(Object { header: self, buf })
        }
    }

    /// Valadite object data against this header.
    pub fn verify(self, data: &[u8]) -> Result<ObjectHeader, ObjectError> {
        if self.size() != data.len() {
            Err(ObjectError::DataLen)
        } else if self.hash != Hash::compute_with_info(self.info, data) {
            Err(ObjectError::Hash)
        } else {
            Ok(self)
        }
    }

    /// Reference to the [crate::Hash] of the corresponding object.
    pub fn hash(&self) -> &Hash {
        &self.hash
    }

    /// Info bytes (size + kind)
    pub fn info(&self) -> u32 {
        self.info
    }

    /// Size of object data in bytes (extracted from info field).
    pub fn size(&self) -> usize {
        ((self.info & 0x00ffffff) + 1) as usize
    }

    /// Size of full object (header + data)
    pub fn full_size(&self) -> usize {
        HEADER + self.size()
    }

    /// Object kind (extracted from info field).
    pub fn kind(&self) -> u8 {
        (self.info >> 24) as u8
    }

    /// Consume instance, returning hash.
    pub fn into_hash(self) -> Hash {
        self.hash
    }

    /// Read and extract 49 byte [ObjectHeader] from a buffer.
    pub fn read_from_buf(buf: &[u8]) -> Result<Self, ObjectError> {
        if buf.len() < HEADER {
            Err(ObjectError::HeaderLen)
        } else {
            let hash = Hash::from_slice(&buf[HASH_RANGE]).unwrap();
            let info = u32::from_le_bytes(buf[INFO_RANGE].try_into().unwrap());
            Ok(Self { hash, info })
        }
    }

    /// Write
    pub fn write_to_buf(&self, buf: &mut [u8]) -> Result<(), ObjectError> {
        if buf.len() < HEADER {
            Err(ObjectError::HeaderLen)
        } else {
            buf[HASH_RANGE].copy_from_slice(self.hash.as_bytes());
            buf[INFO_RANGE].copy_from_slice(&self.info.to_le_bytes());
            Ok(())
        }
    }
}

/// Object.
#[derive(Debug, PartialEq)]
pub struct Object<'a> {
    header: ObjectHeader,
    buf: &'a [u8],
}

impl<'a> Object<'a> {
    pub fn validate(buf: &'a [u8]) -> Result<Self, ObjectError> {
        let header = ObjectHeader::read_from_buf(buf)?;
        header.validate_object(buf)
    }

    pub fn into_header(self) -> ObjectHeader {
        self.header
    }

    pub fn header(&self) -> &ObjectHeader {
        &self.header
    }

    pub fn as_buf(&self) -> &[u8] {
        self.buf
    }

    pub fn as_data(&self) -> &[u8] {
        &self.buf[HEADER..]
    }
}

pub fn finalize_object<'a>(kind: u8, buf: &'a mut [u8]) -> Result<Object<'a>, ObjectError> {
    if !(BUFFER_MIN_SIZE..=BUFFER_MAX_SIZE).contains(&buf.len()) {
        Err(ObjectError::BufLenBounds)
    } else {
        let header = ObjectHeader::build(kind, &buf[HEADER..])?;
        header.write_to_buf(buf)?;
        Ok(Object { header, buf })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testhelpers::random_hash;
    use getrandom;
    use std::collections::HashSet;

    #[test]
    fn test_objectheader_build() {
        assert_eq!(ObjectHeader::build(0, &[]), Err(ObjectError::DataLenBounds));
        let mut buf = Vec::with_capacity(OBJECT_MAX_SIZE + 1);
        buf.resize(OBJECT_MAX_SIZE + 1, 0);
        assert_eq!(
            ObjectHeader::build(0, &buf),
            Err(ObjectError::DataLenBounds)
        );

        // buf.len() == OBJECT_MAX_SIZE, kind == 0
        buf.resize(OBJECT_MAX_SIZE, 0);
        let header = ObjectHeader::build(0, &buf).unwrap();
        assert_eq!(
            header.hash(),
            &Hash::from_z32(
                b"JQB5YVD8CFCYE8U7RWETQG6AEVKQ9IMBLQMI7YWUXALXUZ75THLNOI6NUJ7KQXJDFFTYE9R8"
            )
            .unwrap()
        );
        assert_eq!(header.size(), OBJECT_MAX_SIZE);
        assert_eq!(header.kind(), 0);

        // buf.len() == OBJECT_MAX_SIZE, kind == 255
        let header = ObjectHeader::build(255, &buf).unwrap(); // Now with kind=255
        assert_eq!(
            header.hash(),
            &Hash::from_z32(
                b"AVB4LLC5H5CT9GFMEC95GPHBXYBUMYBLBEJR7DA9NAV7GKPJN8XMVYD6JPWZHFGKMXWOLHUN"
            )
            .unwrap()
        );
        assert_eq!(header.size(), OBJECT_MAX_SIZE);
        assert_eq!(header.kind(), 255);

        // buf.len() == 1, kind == 0
        let header = ObjectHeader::build(0, &[0; 1]).unwrap();
        assert_eq!(
            header.hash(),
            &Hash::from_z32(
                b"YGTGOPMKOD7MTSKCPJAV4MH5YR6RJRDPHGTGUS5NVWTCRVIMJIXPEZFDHGPFYFCNPSOA8FRY"
            )
            .unwrap()
        );
        assert_eq!(header.size(), 1);
        assert_eq!(header.kind(), 0);

        // buf.len() == 1, kind == 255
        let header = ObjectHeader::build(255, &[0; 1]).unwrap();
        assert_eq!(
            header.hash(),
            &Hash::from_z32(
                b"SPTBWZITNEAYLFZPHS44L5KFNVG8JMGF9ZZB8NHQSOJUI65PR7HH6X7TELW77OMYPQ68KF8B"
            )
            .unwrap()
        );
        assert_eq!(header.size(), 1);
        assert_eq!(header.kind(), 255);
    }

    #[test]
    fn test_objectheader_validate_object() {
        let data = b"How is Rust so awesome, question mark";
        let header = ObjectHeader::build(42, data).unwrap();
        let mut buf = vec![0; HEADER];
        header.write_to_buf(&mut buf).unwrap();
        buf.extend_from_slice(data);
        let obj = header.validate_object(&mut buf).unwrap();
        assert_eq!(obj.as_data(), data);

        let header = obj.into_header();
        buf.extend_from_slice(b"b");
        assert_eq!(
            header.validate_object(&mut buf).unwrap_err(),
            ObjectError::BufLen
        );
    }

    #[test]
    fn test_objectheader_read_from_buf() {
        assert_eq!(
            ObjectHeader::read_from_buf(&[]),
            Err(ObjectError::HeaderLen)
        );
        assert_eq!(
            ObjectHeader::read_from_buf(&[42; HEADER - 1]),
            Err(ObjectError::HeaderLen)
        );
        let header = ObjectHeader::read_from_buf(&[42; HEADER]).unwrap();
        assert_eq!(header.hash(), &Hash::from_bytes([42; DIGEST]));
        assert_eq!(header.size(), 2763307);
        assert_eq!(header.kind(), 42);

        let header = ObjectHeader::read_from_buf(&[0; HEADER]).unwrap();
        assert_eq!(header.hash(), &Hash::from_bytes([0; DIGEST]));
        assert_eq!(header.size(), 1);
        assert_eq!(header.kind(), 0);

        let header = ObjectHeader::read_from_buf(&[255; HEADER]).unwrap();
        assert_eq!(header.hash(), &Hash::from_bytes([255; DIGEST]));
        assert_eq!(header.size(), OBJECT_MAX_SIZE);
        assert_eq!(header.kind(), 255);
    }

    #[test]
    fn test_objectheader_write_to_buf() {
        let hash = random_hash();
        let info = 69;
        let header = ObjectHeader::new(hash.clone(), info);
        assert_eq!(header.size(), 70);
        assert_eq!(header.kind(), 0);
        assert_eq!(header.write_to_buf(&mut []), Err(ObjectError::HeaderLen));
        assert_eq!(
            header.write_to_buf(&mut [0; HEADER - 1]),
            Err(ObjectError::HeaderLen)
        );

        let mut buf = [0; HEADER];
        header.write_to_buf(&mut buf).unwrap();
        assert_eq!(&buf[0..DIGEST], hash.as_bytes());
        assert_eq!(&buf[INFO_RANGE], &[69, 0, 0, 0]);

        let mut buf = [0; HEADER + 21];
        header.write_to_buf(&mut buf).unwrap();
        assert_eq!(&buf[0..DIGEST], hash.as_bytes());
        assert_eq!(&buf[INFO_RANGE], &[69, 0, 0, 0]);
        assert_eq!(&buf[HEADER..], &[0; 21]);
    }

    #[test]
    fn test_objectheader_roundtrip() {
        for _ in 0..420 {
            let mut src = [0; HEADER];
            getrandom::fill(&mut src).unwrap();
            let src = src;
            let header = ObjectHeader::read_from_buf(&src).unwrap();
            let mut dst = [0; HEADER];
            assert_ne!(src, dst);
            header.write_to_buf(&mut dst).unwrap();
            assert_eq!(src, dst);
        }
    }

    #[test]
    fn test_finalize_object() {
        let mut set: HashSet<Hash> = HashSet::with_capacity(512);
        let mut buf = Vec::with_capacity(BUFFER_MAX_SIZE + 1);
        for kind in 0..=255 {
            assert_eq!(
                finalize_object(kind, &mut []).unwrap_err(),
                ObjectError::BufLenBounds
            );
            assert_eq!(
                finalize_object(kind, &mut [0; HEADER]).unwrap_err(),
                ObjectError::BufLenBounds
            );
            buf.clear();
            buf.resize(HEADER + 1, 0);
            let obj = finalize_object(kind, &mut buf).unwrap();
            assert_eq!(obj.header().kind(), kind);
            assert_eq!(obj.header.size(), 1);
            assert!(set.insert(obj.into_header().into_hash()));
            assert_eq!(buf[HEADER - 1], kind);

            buf.resize(BUFFER_MAX_SIZE, 0);
            let obj = finalize_object(kind, &mut buf).unwrap();
            assert_eq!(obj.header().kind(), kind);
            assert_eq!(obj.header().size(), OBJECT_MAX_SIZE);
            assert!(set.insert(obj.into_header().into_hash()));
            assert_eq!(buf[HEADER - 1], kind);

            buf.resize(BUFFER_MAX_SIZE + 1, 0);
            assert_eq!(
                finalize_object(kind, &mut buf).unwrap_err(),
                ObjectError::BufLenBounds
            );
        }
    }
}
