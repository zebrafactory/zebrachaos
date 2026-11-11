use crate::{DIGEST, Hash, MutObject};
use std::collections::HashMap;
use std::io;

#[derive(Debug, PartialEq)]
pub enum TreeError {
    EmptyName,
    NameLen(usize, usize),
    NameLenBounds(usize),
    NameUtf8(std::string::FromUtf8Error),
    DuplicateName(String, Item),
    EmptyItem,
    ItemKind(u8),
    ItemHashLen(usize, usize),
    EmptyDirectory,
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

    pub fn len(&self) -> usize {
        1 + match self {
            Self::EmptyDir => 0,
            Self::EmptyFile => 0,
            Self::Dir(_) | Self::File(_) | Self::ExeFile(_) => DIGEST,
            Self::SymLink(name) => 1 + name.len(),
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

fn decode_hash(buf: &[u8]) -> Result<Hash, TreeError> {
    if buf.len() < DIGEST {
        Err(TreeError::ItemHashLen(DIGEST, buf.len()))
    } else {
        Ok(Hash::from_slice(&buf[..DIGEST]).unwrap())
    }
}

fn decode_item(buf: &[u8]) -> Result<Item, TreeError> {
    if buf.is_empty() {
        Err(TreeError::EmptyItem)
    } else {
        let kind = buf[0];
        let buf = &buf[1..];
        match kind {
            0 => Ok(Item::EmptyDir),
            1 => Ok(Item::EmptyFile),
            2 => Ok(Item::Dir(decode_hash(buf)?)),
            3 => Ok(Item::File(decode_hash(buf)?)),
            4 => Ok(Item::ExeFile(decode_hash(buf)?)),
            5 => Ok(Item::SymLink(decode_name(buf)?)),
            _ => Err(TreeError::ItemKind(kind)),
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

impl Directory {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    pub fn insert(&mut self, name: String, item: Item) -> Result<(), TreeError> {
        minus_one_encode(name.len())?;
        if self.map.contains_key(&name) {
            Err(TreeError::DuplicateName(name, item))
        } else {
            self.map.insert(name, item);
            Ok(())
        }
    }

    pub fn serialize_into(&self, obj: &mut MutObject) -> Result<(), TreeError> {
        if self.map.is_empty() {
            Err(TreeError::EmptyDirectory)
        } else {
            let mut pairs = Vec::from_iter(self.map.iter());
            pairs.sort_by(|a, b| a.0.cmp(b.0));
            for (name, item) in pairs.iter() {
                encode_name_into(&name, obj)?;
                encode_item_into(&item, obj)?;
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DATA_MAX_LEN;
    use crate::testhelpers::random_hash;

    #[test]
    fn test_item_len() {
        assert_eq!(Item::EmptyDir.len(), 1);
        assert_eq!(Item::EmptyFile.len(), 1);
        assert_eq!(Item::Dir(random_hash()).len(), 1 + DIGEST);
        assert_eq!(Item::File(random_hash()).len(), 1 + DIGEST);
        assert_eq!(Item::ExeFile(random_hash()).len(), 1 + DIGEST);
        assert_eq!(Item::SymLink(String::from("B")).len(), 3);
        let name = String::from_utf8(vec![0x42; 256]).unwrap();
        assert_eq!(Item::SymLink(name).len(), 258);
    }

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
    fn test_decode_hash() {
        assert_eq!(decode_hash(&[]), Err(TreeError::ItemHashLen(DIGEST, 0)));
    }

    #[test]
    fn test_decode_item() {
        assert_eq!(decode_item(&[]), Err(TreeError::EmptyItem));
        for bad_kind in 6_u8..=255 {
            assert_eq!(decode_item(&[bad_kind]), Err(TreeError::ItemKind(bad_kind)));
        }
        for kind in [2, 3, 4] {
            assert_eq!(decode_item(&[kind]), Err(TreeError::ItemHashLen(DIGEST, 0)));
            assert_eq!(
                decode_item(&[kind; DIGEST]),
                Err(TreeError::ItemHashLen(DIGEST, DIGEST - 1))
            );
        }
        assert_eq!(decode_item(&[5]), Err(TreeError::EmptyName));
        assert_eq!(decode_item(&[5, 0]), Err(TreeError::NameLen(1, 0)));
        assert_eq!(decode_item(&[5, 1, 0x42]), Err(TreeError::NameLen(2, 1)));
        assert_eq!(decode_item(&[5, 255]), Err(TreeError::NameLen(256, 0)));
        assert_eq!(
            decode_item(&[5, 255, 0x42]),
            Err(TreeError::NameLen(256, 1))
        );

        assert_eq!(decode_item(&[0]), Ok(Item::EmptyDir));
        assert_eq!(decode_item(&[1]), Ok(Item::EmptyFile));
        assert_eq!(
            decode_item(&[2; DIGEST + 1]),
            Ok(Item::Dir(Hash::from_bytes([2; DIGEST])))
        );
        assert_eq!(
            decode_item(&[3; DIGEST + 1]),
            Ok(Item::File(Hash::from_bytes([3; DIGEST])))
        );
        assert_eq!(
            decode_item(&[4; DIGEST + 1]),
            Ok(Item::ExeFile(Hash::from_bytes([4; DIGEST])))
        );
        assert_eq!(
            decode_item(&[5, 0, 0x42]),
            Ok(Item::SymLink(String::from("B")))
        );
        let mut buf = vec![5, 255];
        buf.extend_from_slice(&[0x42; 256]);
        assert_eq!(
            decode_item(&buf),
            Ok(Item::SymLink(String::from_utf8(vec![0x42; 256]).unwrap()))
        )
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

    #[test]
    fn test_directory_new() {
        let d = Directory::new();
        assert!(d.map.is_empty());
    }

    #[test]
    fn test_directory_insert() {
        let mut d = Directory::new();

        // Empty name
        assert_eq!(
            d.insert(String::from(""), Item::EmptyDir).unwrap_err(),
            TreeError::NameLenBounds(0)
        );
        assert!(d.map.is_empty());

        // Name is too long
        assert_eq!(
            d.insert(String::from_utf8(vec![0x42; 257]).unwrap(), Item::EmptyDir)
                .unwrap_err(),
            TreeError::NameLenBounds(257)
        );
        assert!(d.map.is_empty());

        // New max length name "BBBB..."
        let bees = String::from_utf8(vec![0x42; 256]).unwrap();
        assert!(d.insert(bees.clone(), Item::EmptyDir).is_ok());
        assert_eq!(d.map.len(), 1);
        assert_eq!(d.map.get(&bees), Some(&Item::EmptyDir));

        // Duplicate of same max length name
        assert_eq!(
            d.insert(bees.clone(), Item::EmptyFile).unwrap_err(),
            TreeError::DuplicateName(bees.clone(), Item::EmptyFile)
        );
        assert_eq!(d.map.len(), 1);
        assert_eq!(d.map.get(&bees), Some(&Item::EmptyDir));

        // Min length name "B"
        let b = String::from_utf8(vec![0x42; 1]).unwrap();
        assert_eq!(&b, "B");
        assert!(d.insert(b.clone(), Item::EmptyFile).is_ok());
        assert_eq!(d.map.len(), 2);
        assert_eq!(d.map.get(&bees), Some(&Item::EmptyDir));
        assert_eq!(d.map.get(&b), Some(&Item::EmptyFile));

        // Duplicate of same min length name
        assert_eq!(
            d.insert(b.clone(), Item::EmptyDir).unwrap_err(),
            TreeError::DuplicateName(b.clone(), Item::EmptyDir)
        );
        assert_eq!(d.map.len(), 2);
        assert_eq!(d.map.get(&bees), Some(&Item::EmptyDir));
        assert_eq!(d.map.get(&b), Some(&Item::EmptyFile));
    }

    #[test]
    fn test_directory_serialize_into() {
        let mut d = Directory::new();
        {
            let mut buf = Vec::new();
            let mut obj = MutObject::new(&mut buf);
            assert_eq!(d.serialize_into(&mut obj), Err(TreeError::EmptyDirectory));
        }
        d.insert(String::from("src"), Item::EmptyDir).unwrap();
        {
            let mut buf = Vec::new();
            let mut obj = MutObject::new(&mut buf);
            assert_eq!(d.serialize_into(&mut obj), Ok(()));
            let obj = obj.finalize(1).unwrap();
            assert_eq!(obj.as_data(), b"\x02src\x00");
        }
        d.insert(String::from("REAMDE.md"), Item::EmptyFile)
            .unwrap();
        {
            let mut buf = Vec::new();
            let mut obj = MutObject::new(&mut buf);
            assert_eq!(d.serialize_into(&mut obj), Ok(()));
            let obj = obj.finalize(1).unwrap();
            assert_eq!(obj.as_data(), b"\x08REAMDE.md\x01\x02src\x00");
        }
        d.insert(String::from("foo"), Item::SymLink(String::from("bars")))
            .unwrap();
        {
            let mut buf = Vec::new();
            let mut obj = MutObject::new(&mut buf);
            assert_eq!(d.serialize_into(&mut obj), Ok(()));
            let obj = obj.finalize(1).unwrap();
            assert_eq!(
                obj.as_data(),
                b"\x08REAMDE.md\x01\x02foo\x05\x03bars\x02src\x00"
            );
        }
    }
}
