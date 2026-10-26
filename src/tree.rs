use crate::{Hash, MutObject};
use std::collections::HashMap;
use std::io;

#[derive(Debug, PartialEq)]
pub enum TreeError {
    EmptyName,
    NameLen(usize, usize),
    NameLenBounds(usize),
    NameUtf8(std::string::FromUtf8Error),
    DirCapacityExceeded,
}

impl TreeError {
    /// Consume error, embedding it in an `io::Error`.
    pub fn into_io_error(self) -> io::Error {
        io::Error::other(self)
    }
}

impl core::fmt::Display for TreeError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str(&format!("TreeError::{self:?}"))
    }
}

impl core::error::Error for TreeError {}

/// Value in the directory map.
#[derive(Debug, PartialEq)]
pub enum Item {
    EmptyDir,
    EmptyFile,
    Dir(Hash),
    File(Hash),
    ExeFile(Hash),
    SymLink(String),
}

impl Item {
    pub fn kind_byte(&self) -> u8 {
        match self {
            Self::EmptyDir => 0,
            Self::EmptyFile => 1,
            Self::Dir(_) => 2,
            Self::File(_) => 3,
            Self::ExeFile(_) => 4,
            Self::SymLink(_) => 5,
        }
    }
}

fn minus_one_encode(size: usize) -> Result<u8, TreeError> {
    if (1..=256).contains(&size) {
        Ok((size - 1) as u8)
    } else {
        Err(TreeError::NameLenBounds(size))
    }
}

fn minus_one_decode(encoded_size: u8) -> usize {
    encoded_size as usize + 1
}

fn decode_name(buf: &[u8]) -> Result<String, TreeError> {
    if buf.is_empty() {
        Err(TreeError::EmptyName)
    } else {
        let size = minus_one_decode(buf[0]);
        let buf = &buf[1..];
        if buf.len() < size {
            Err(TreeError::NameLen(size, buf.len()))
        } else {
            let mut key = Vec::with_capacity(size);
            key.extend_from_slice(&buf[..size]);
            match String::from_utf8(key) {
                Ok(name) => Ok(name),
                Err(utf8_err) => Err(TreeError::NameUtf8(utf8_err)),
            }
        }
    }
}

fn encode_name_into(name: &str, obj: &mut MutObject) -> Result<(), TreeError> {
    let encoded_size = minus_one_encode(name.len())?;
    for buf in [&[encoded_size], name.as_bytes()] {
        match obj.try_extend_from_slice(buf) {
            Ok(_) => {}
            Err(_) => return Err(TreeError::DirCapacityExceeded),
        }
    }
    Ok(())
}

fn encode_item_into(item: &Item, obj: &mut MutObject) -> Result<(), TreeError> {
    match obj.try_extend_from_slice(&[item.kind_byte()]) {
        Ok(_) => {}
        Err(_) => return Err(TreeError::DirCapacityExceeded),
    }
    match item {
        Item::EmptyDir | Item::EmptyFile => {}
        Item::Dir(hash) | Item::File(hash) | Item::ExeFile(hash) => {
            match obj.try_extend_from_slice(hash.as_bytes()) {
                Ok(_) => {}
                Err(_) => return Err(TreeError::DirCapacityExceeded),
            }
        }
        Item::SymLink(name) => {
            encode_name_into(name, obj)?;
        }
    }
    Ok(())
}

/// A directory.
pub struct Directory {
    map: HashMap<String, Item>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DATA_MAX_LEN;
    use crate::testhelpers::random_hash;

    #[test]
    fn test_minus_one_encoding_roundtrip() {
        assert_eq!(minus_one_encode(0), Err(TreeError::NameLenBounds(0)));
        assert_eq!(minus_one_encode(1), Ok(0));
        assert_eq!(minus_one_encode(256), Ok(255));
        assert_eq!(minus_one_encode(257), Err(TreeError::NameLenBounds(257)));
        for size in 1..257 {
            assert_eq!(minus_one_encode(size), Ok((size - 1) as u8));
            let encoded = minus_one_encode(size).unwrap();
            assert_eq!(minus_one_decode(encoded), size);
        }
        for encoded in 0..=255 {
            assert_eq!(minus_one_decode(encoded), encoded as usize + 1);
        }
    }

    #[test]
    fn test_decode_name() {
        assert_eq!(decode_name(&[]), Err(TreeError::EmptyName));
        assert_eq!(decode_name(&[0]), Err(TreeError::NameLen(1, 0)));
        assert_eq!(decode_name(&[1]), Err(TreeError::NameLen(2, 0)));
        assert_eq!(decode_name(&[1, 65]), Err(TreeError::NameLen(2, 1)));
        assert_eq!(decode_name(&[0, 65]), Ok(String::from("A")));
        assert_eq!(decode_name(&[2, 66, 65]), Err(TreeError::NameLen(3, 2)));
        assert_eq!(decode_name(&[1, 66, 65]), Ok(String::from("BA")));
        assert_eq!(decode_name(&[0, 66, 65]), Ok(String::from("B")));
    }

    #[test]
    fn test_encode_name_into() {
        let mut buf = Vec::new();
        let mut obj = MutObject::new(&mut buf);
        assert_eq!(
            encode_name_into("", &mut obj),
            Err(TreeError::NameLenBounds(0))
        );
        assert_eq!(obj.remaining(), DATA_MAX_LEN);
        assert_eq!(
            encode_name_into(&String::from_utf8(vec![65; 257]).unwrap(), &mut obj),
            Err(TreeError::NameLenBounds(257))
        );
        assert_eq!(obj.remaining(), DATA_MAX_LEN);
        assert!(encode_name_into("A", &mut obj).is_ok());
        assert!(encode_name_into("BA", &mut obj).is_ok());
        let obj = obj.finalize(1).unwrap();
        assert_eq!(obj.as_data(), &[0, 65, 1, 66, 65]);
    }

    #[test]
    fn test_encode_item_into() {
        let hash = random_hash();
        let mut buf = Vec::new();
        {
            let mut obj = MutObject::new(&mut buf);
            let item = Item::EmptyDir;
            encode_item_into(&item, &mut obj).unwrap();
            let obj = obj.finalize(0).unwrap();
            assert_eq!(obj.as_data(), &[0]);
        }
        {
            let mut obj = MutObject::new(&mut buf);
            let item = Item::EmptyFile;
            encode_item_into(&item, &mut obj).unwrap();
            let obj = obj.finalize(0).unwrap();
            assert_eq!(obj.as_data(), &[1]);
        }
        {
            let mut obj = MutObject::new(&mut buf);
            let item = Item::Dir(hash.clone());
            encode_item_into(&item, &mut obj).unwrap();
            let obj = obj.finalize(0).unwrap();
            assert_eq!(obj.as_data()[0], 2);
            assert_eq!(&obj.as_data()[1..], hash.as_bytes());
        }
        {
            let mut obj = MutObject::new(&mut buf);
            let item = Item::File(hash.clone());
            encode_item_into(&item, &mut obj).unwrap();
            let obj = obj.finalize(0).unwrap();
            assert_eq!(obj.as_data()[0], 3);
            assert_eq!(&obj.as_data()[1..], hash.as_bytes());
        }
        {
            let mut obj = MutObject::new(&mut buf);
            let item = Item::ExeFile(hash.clone());
            encode_item_into(&item, &mut obj).unwrap();
            let obj = obj.finalize(0).unwrap();
            assert_eq!(obj.as_data()[0], 4);
            assert_eq!(&obj.as_data()[1..], hash.as_bytes());
        }
        {
            let mut obj = MutObject::new(&mut buf);
            let item = Item::SymLink(String::from("A"));
            encode_item_into(&item, &mut obj).unwrap();
            let obj = obj.finalize(0).unwrap();
            assert_eq!(obj.as_data()[0], 5);
            assert_eq!(&obj.as_data()[1..], &[0, 65]);
        }
        {
            let mut obj = MutObject::new(&mut buf);
            let item = Item::SymLink(String::from_utf8(vec![65; 256]).unwrap());
            encode_item_into(&item, &mut obj).unwrap();
            let obj = obj.finalize(0).unwrap();
            assert_eq!(obj.as_data()[0], 5);
            assert_eq!(obj.as_data()[1], 255);
            assert_eq!(&obj.as_data()[2..], &[65; 256]);
        }
    }
}
