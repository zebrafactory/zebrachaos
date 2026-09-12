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
}

pub struct ObjectHeader {
    hash: Hash,
    info: u32,
}

impl ObjectHeader {
    pub fn hash(&self) -> &Hash {
        &self.hash
    }

    pub fn size(&self) -> usize {
        ((self.info & 0x00ffffff) + 1) as usize
    }

    pub fn kind(&self) -> u8 {
        (self.info >> 24) as u8
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
    let hash = Hash::compute_with_info(info, data);
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

pub fn build_object_header(kind: u8, data: &[u8]) {}

pub struct Object<'a> {
    buf: &'a [u8],
}

pub struct MutObject<'a> {
    buf: &'a mut [u8],
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
}
