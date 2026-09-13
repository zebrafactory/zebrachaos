use crate::Hash;
use crate::always::*;

#[derive(Debug, PartialEq)]
pub enum ObjectError {
    EmptyBuffer,
    ShortBuffer,
    BufferSize,
    Header,
    Hash,
    Size,
    DataLen,
}

#[derive(Debug, PartialEq)]
pub struct ObjectHeader {
    hash: Hash,
    info: u32,
}

impl ObjectHeader {
    pub fn new(hash: Hash, info: u32) -> Self {
        Self { hash, info }
    }

    pub fn build(kind: u8, data: &[u8]) -> Result<Self, ObjectError> {
        if !(1..=OBJECT_MAX_SIZE).contains(&data.len()) {
            Err(ObjectError::DataLen)
        } else {
            let info = (data.len() - 1) as u32 | (kind as u32) << 24;
            let hash = Hash::compute_with_info(info, data);
            Ok(Self { hash, info })
        }
    }

    pub fn hash(&self) -> &Hash {
        &self.hash
    }

    pub fn size(&self) -> usize {
        ((self.info & 0x00ffffff) + 1) as usize
    }

    pub fn kind(&self) -> u8 {
        (self.info >> 24) as u8
    }

    pub fn read_from_buf(buf: &[u8]) -> Result<Self, ObjectError> {
        if buf.len() < HEADER {
            Err(ObjectError::Header)
        } else {
            let hash = Hash::from_slice(&buf[HASH_RANGE]).unwrap();
            let infobuf: [u8; 4] = buf[INFO_RANGE].try_into().unwrap();
            let info = u32::from_le_bytes(infobuf);
            Ok(Self { hash, info })
        }
    }

    pub fn write_to_buf(&self, buf: &mut [u8]) -> Result<(), ObjectError> {
        if buf.len() < HEADER {
            Err(ObjectError::Header)
        } else {
            buf[HASH_RANGE].copy_from_slice(self.hash.as_bytes());
            buf[INFO_RANGE].copy_from_slice(&self.info.to_le_bytes());
            Ok(())
        }
    }
}

pub struct Object<'a> {
    buf: &'a [u8],
}

pub struct MutObject<'a> {
    buf: &'a mut [u8],
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashing::random_hash;

    #[test]
    fn test_objectheader_build() {
        assert_eq!(ObjectHeader::build(0, &[]), Err(ObjectError::DataLen));
        let mut buf = Vec::with_capacity(OBJECT_MAX_SIZE + 1);
        buf.resize(OBJECT_MAX_SIZE + 1, 0);
        assert_eq!(ObjectHeader::build(0, &buf), Err(ObjectError::DataLen));

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
    fn test_objectheader_read_from_buf() {
        assert_eq!(ObjectHeader::read_from_buf(&[]), Err(ObjectError::Header));
        assert_eq!(
            ObjectHeader::read_from_buf(&[42; HEADER - 1]),
            Err(ObjectError::Header)
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
    fn test_objectheader_write_to_buf() {}
}
