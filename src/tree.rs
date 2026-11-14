use crate::{DIGEST, Hash, MutObject, Object};
use std::collections::HashMap;
use std::io;

#[derive(Debug, PartialEq)]
pub enum TreeError {
    NameLenBounds(usize),
    NameUtf8(std::string::FromUtf8Error),
    BadName(String),
    DuplicateName(String, Item),
    ItemKind(u8),
    EmptyDirectory,
    DirCapacityExceeded,
    DataNotAvailable(usize, usize),
    DataNotConsumed(usize),
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
    SymLink(Vec<String>),
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

fn decode_name(reader: &mut ObjectReader) -> Result<String, TreeError> {
    let size = minus_one_decode(reader.take(1)?[0]);
    let mut key = Vec::with_capacity(size);
    key.extend_from_slice(reader.take(size)?);
    match String::from_utf8(key) {
        Ok(name) => Ok(name),
        Err(utf8_err) => Err(TreeError::NameUtf8(utf8_err)),
    }
}

fn decode_symlink(reader: &mut ObjectReader) -> Result<Vec<String>, TreeError> {
    let count = minus_one_decode(reader.take(1)?[0]);
    let mut symlink = Vec::with_capacity(count);
    for _ in 0..count {
        symlink.push(decode_name(reader)?);
    }
    Ok(symlink)
}

fn decode_hash(reader: &mut ObjectReader) -> Result<Hash, TreeError> {
    Ok(Hash::from_slice(reader.take(DIGEST)?).unwrap())
}

fn decode_item(reader: &mut ObjectReader) -> Result<Item, TreeError> {
    let kind = reader.take(1)?[0];
    match kind {
        0 => Ok(Item::EmptyDir),
        1 => Ok(Item::EmptyFile),
        2 => Ok(Item::Dir(decode_hash(reader)?)),
        3 => Ok(Item::File(decode_hash(reader)?)),
        4 => Ok(Item::ExeFile(decode_hash(reader)?)),
        5 => Ok(Item::SymLink(decode_symlink(reader)?)),
        _ => Err(TreeError::ItemKind(kind)),
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

fn encode_symlink_into(symlink: &[String], obj: &mut MutObject) -> Result<(), TreeError> {
    let encoded_count = minus_one_encode(symlink.len())?;
    match obj.try_extend_from_slice(&[encoded_count]) {
        Ok(_) => {}
        Err(_) => return Err(TreeError::DirCapacityExceeded),
    }
    for name in symlink {
        encode_name_into(name, obj)?;
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
        Item::SymLink(symlink) => {
            encode_symlink_into(symlink, obj)?;
        }
    }
    Ok(())
}

pub struct ObjectReader<'a> {
    buf: &'a [u8],
}

impl<'a> ObjectReader<'a> {
    #[cfg(test)]
    fn raw(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    pub fn new(obj: &'a Object) -> Self {
        Self { buf: obj.as_data() }
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn remaining(&self) -> usize {
        self.buf.len()
    }

    pub fn take(&mut self, amount: usize) -> Result<&[u8], TreeError> {
        if self.buf.len() < amount {
            Err(TreeError::DataNotAvailable(amount, self.buf.len()))
        } else {
            let ret = &self.buf[..amount];
            self.buf = &self.buf[amount..];
            Ok(ret)
        }
    }

    pub fn peak(&self, amount: usize) -> Result<&[u8], TreeError> {
        if self.buf.len() < amount {
            Err(TreeError::DataNotAvailable(amount, self.buf.len()))
        } else {
            Ok(&self.buf[..amount])
        }
    }

    pub fn finish(self) -> Result<(), TreeError> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(TreeError::DataNotConsumed(self.buf.len()))
        }
    }
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
        if &name == "." || &name == ".." {
            Err(TreeError::BadName(name))
        } else if self.map.contains_key(&name) {
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

    pub fn deserialize_from(obj: &Object) -> Result<Self, TreeError> {
        let mut directory = Directory::new();
        let mut reader = ObjectReader::new(obj);
        while !reader.is_empty() {
            let name = decode_name(&mut reader)?;
            let item = decode_item(&mut reader)?;
            directory.insert(name, item)?;
        }
        reader.finish()?;
        Ok(directory)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testhelpers::random_hash;
    use crate::{DATA_MAX_LEN, HEADER, finalize_object};

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
        let mut reader = ObjectReader::raw(&[]);
        assert_eq!(
            decode_name(&mut reader),
            Err(TreeError::DataNotAvailable(1, 0))
        );
        let mut reader = ObjectReader::raw(&[0]);
        assert_eq!(
            decode_name(&mut reader),
            Err(TreeError::DataNotAvailable(1, 0))
        );
        let mut reader = ObjectReader::raw(&[1]);
        assert_eq!(
            decode_name(&mut reader),
            Err(TreeError::DataNotAvailable(2, 0))
        );
        let mut reader = ObjectReader::raw(&[1, 0x41]);
        assert_eq!(
            decode_name(&mut reader),
            Err(TreeError::DataNotAvailable(2, 1))
        );

        let mut reader = ObjectReader::raw(&[0, 0x42]);
        assert_eq!(decode_name(&mut reader), Ok(String::from("B")));
        let mut reader = ObjectReader::raw(&[0, 0x42, 0x41]);
        assert_eq!(decode_name(&mut reader), Ok(String::from("B")));
        let mut reader = ObjectReader::raw(&[1, 0x42, 0x41]);
        assert_eq!(decode_name(&mut reader), Ok(String::from("BA")));

        let mut reader = ObjectReader::raw(&[2, 0x42, 0x41]);
        assert_eq!(
            decode_name(&mut reader),
            Err(TreeError::DataNotAvailable(3, 2))
        );
    }

    #[test]
    fn test_decode_symlink() {
        assert_eq!(
            decode_symlink(&mut ObjectReader::raw(&[])),
            Err(TreeError::DataNotAvailable(1, 0))
        );
        assert_eq!(
            decode_symlink(&mut ObjectReader::raw(&[0])),
            Err(TreeError::DataNotAvailable(1, 0))
        );
        assert_eq!(
            decode_symlink(&mut ObjectReader::raw(&[0, 0])),
            Err(TreeError::DataNotAvailable(1, 0))
        );
        assert_eq!(
            decode_symlink(&mut ObjectReader::raw(&[0, 1])),
            Err(TreeError::DataNotAvailable(2, 0))
        );
        assert_eq!(
            decode_symlink(&mut ObjectReader::raw(&[0, 1])),
            Err(TreeError::DataNotAvailable(2, 0))
        );
        assert_eq!(
            decode_symlink(&mut ObjectReader::raw(&[0, 0, 0x42])),
            Ok(vec![String::from("B")])
        );
        assert_eq!(
            decode_symlink(&mut ObjectReader::raw(&[0, 1, 0x42, 0x41])),
            Ok(vec![String::from("BA")])
        );
        assert_eq!(
            decode_symlink(&mut ObjectReader::raw(&[1, 0, 0x42, 0, 0x41])),
            Ok(vec![String::from("B"), String::from("A")])
        );
        assert_eq!(
            decode_symlink(&mut ObjectReader::raw(&[
                1, 2, 0x42, 0x41, 0x44, 1, 0x41, 0x42
            ])),
            Ok(vec![String::from("BAD"), String::from("AB")])
        );
    }

    #[test]
    fn test_decode_hash() {
        let mut reader = ObjectReader::raw(&[]);
        assert_eq!(
            decode_hash(&mut reader),
            Err(TreeError::DataNotAvailable(DIGEST, 0))
        );
        let mut reader = ObjectReader::raw(&[69; 1]);
        assert_eq!(
            decode_hash(&mut reader),
            Err(TreeError::DataNotAvailable(DIGEST, 1))
        );
        let mut reader = ObjectReader::raw(&[69; DIGEST - 1]);
        assert_eq!(
            decode_hash(&mut reader),
            Err(TreeError::DataNotAvailable(DIGEST, DIGEST - 1))
        );
        let mut reader = ObjectReader::raw(&[69; DIGEST]);
        assert_eq!(decode_hash(&mut reader), Ok(Hash::from_bytes([69; DIGEST])));
    }

    #[test]
    fn test_decode_item() {
        let mut reader = ObjectReader::raw(&[]);
        assert_eq!(
            decode_item(&mut reader),
            Err(TreeError::DataNotAvailable(1, 0))
        );
        for bad_kind in 6..=255 {
            let buf = [bad_kind; 1];
            let mut reader = ObjectReader::raw(&buf);
            assert_eq!(decode_item(&mut reader), Err(TreeError::ItemKind(bad_kind)));
        }

        for kind in [2, 3, 4] {
            let buf = [kind; 1];
            let mut reader = ObjectReader::raw(&buf);
            assert_eq!(
                decode_item(&mut reader),
                Err(TreeError::DataNotAvailable(DIGEST, 0))
            );
            let buf = [kind; DIGEST];
            let mut reader = ObjectReader::raw(&buf);
            assert_eq!(
                decode_item(&mut reader),
                Err(TreeError::DataNotAvailable(DIGEST, DIGEST - 1))
            );
        }

        let buf = [5];
        let mut reader = ObjectReader::raw(&buf);
        assert_eq!(
            decode_item(&mut reader),
            Err(TreeError::DataNotAvailable(1, 0))
        );

        let buf = [5, 0];
        let mut reader = ObjectReader::raw(&buf);
        assert_eq!(
            decode_item(&mut reader),
            Err(TreeError::DataNotAvailable(1, 0))
        );

        let buf = [5, 1];
        let mut reader = ObjectReader::raw(&buf);
        assert_eq!(
            decode_item(&mut reader),
            Err(TreeError::DataNotAvailable(1, 0))
        );

        let buf = [5, 0, 1, 0x42];
        let mut reader = ObjectReader::raw(&buf);
        assert_eq!(
            decode_item(&mut reader),
            Err(TreeError::DataNotAvailable(2, 1))
        );

        let buf = [5, 0, 255];
        let mut reader = ObjectReader::raw(&buf);
        assert_eq!(
            decode_item(&mut reader),
            Err(TreeError::DataNotAvailable(256, 0))
        );

        let buf = [5, 0, 255, 0x42];
        let mut reader = ObjectReader::raw(&buf);
        assert_eq!(
            decode_item(&mut reader),
            Err(TreeError::DataNotAvailable(256, 1))
        );

        let buf = [0];
        let mut reader = ObjectReader::raw(&buf);
        assert_eq!(decode_item(&mut reader), Ok(Item::EmptyDir));

        let buf = [1];
        let mut reader = ObjectReader::raw(&buf);
        assert_eq!(decode_item(&mut reader), Ok(Item::EmptyFile));

        let buf = [2; DIGEST + 1];
        let mut reader = ObjectReader::raw(&buf);
        assert_eq!(
            decode_item(&mut reader),
            Ok(Item::Dir(Hash::from_bytes([2; DIGEST])))
        );

        let buf = [3; DIGEST + 1];
        let mut reader = ObjectReader::raw(&buf);
        assert_eq!(
            decode_item(&mut reader),
            Ok(Item::File(Hash::from_bytes([3; DIGEST])))
        );

        let buf = [4; DIGEST + 1];
        let mut reader = ObjectReader::raw(&buf);
        assert_eq!(
            decode_item(&mut reader),
            Ok(Item::ExeFile(Hash::from_bytes([4; DIGEST])))
        );

        let buf = [5, 0, 0, 0x42];
        let mut reader = ObjectReader::raw(&buf);
        assert_eq!(
            decode_item(&mut reader),
            Ok(Item::SymLink(vec![String::from("B")]))
        );
        let mut buf = vec![5, 0, 255];
        buf.extend_from_slice(&[0x42; 256]);
        let buf = buf;
        let mut reader = ObjectReader::raw(&buf);
        assert_eq!(
            decode_item(&mut reader),
            Ok(Item::SymLink(vec![
                String::from_utf8(vec![0x42; 256]).unwrap()
            ]))
        )
    }

    #[test]
    fn test_encode_name_into() {
        let mut buf = Vec::new();
        let mut obj = MutObject::new(1, &mut buf);
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
        let obj = obj.finalize().unwrap();
        assert_eq!(obj.as_data(), &[0, 65, 1, 66, 65]);
    }

    #[test]
    fn test_encode_item_into() {
        let hash = random_hash();
        let mut buf = Vec::new();
        {
            let mut obj = MutObject::new(0, &mut buf);
            let item = Item::EmptyDir;
            encode_item_into(&item, &mut obj).unwrap();
            let obj = obj.finalize().unwrap();
            assert_eq!(obj.as_data(), &[0]);
        }
        {
            let mut obj = MutObject::new(0, &mut buf);
            let item = Item::EmptyFile;
            encode_item_into(&item, &mut obj).unwrap();
            let obj = obj.finalize().unwrap();
            assert_eq!(obj.as_data(), &[1]);
        }
        {
            let mut obj = MutObject::new(0, &mut buf);
            let item = Item::Dir(hash.clone());
            encode_item_into(&item, &mut obj).unwrap();
            let obj = obj.finalize().unwrap();
            assert_eq!(obj.as_data()[0], 2);
            assert_eq!(&obj.as_data()[1..], hash.as_bytes());
        }
        {
            let mut obj = MutObject::new(0, &mut buf);
            let item = Item::File(hash.clone());
            encode_item_into(&item, &mut obj).unwrap();
            let obj = obj.finalize().unwrap();
            assert_eq!(obj.as_data()[0], 3);
            assert_eq!(&obj.as_data()[1..], hash.as_bytes());
        }
        {
            let mut obj = MutObject::new(0, &mut buf);
            let item = Item::ExeFile(hash.clone());
            encode_item_into(&item, &mut obj).unwrap();
            let obj = obj.finalize().unwrap();
            assert_eq!(obj.as_data()[0], 4);
            assert_eq!(&obj.as_data()[1..], hash.as_bytes());
        }
        {
            let mut obj = MutObject::new(0, &mut buf);
            let item = Item::SymLink(vec![String::from("A")]);
            encode_item_into(&item, &mut obj).unwrap();
            let obj = obj.finalize().unwrap();
            assert_eq!(obj.as_data()[0], 5);
            assert_eq!(&obj.as_data()[1..], &[0, 0, 65]);
        }
        {
            let mut obj = MutObject::new(1, &mut buf);
            let item = Item::SymLink(vec![String::from_utf8(vec![65; 256]).unwrap()]);
            encode_item_into(&item, &mut obj).unwrap();
            let obj = obj.finalize().unwrap();
            assert_eq!(obj.as_data()[0], 5);
            assert_eq!(obj.as_data()[1], 0);
            assert_eq!(obj.as_data()[2], 255);
            assert_eq!(&obj.as_data()[3..], &[65; 256]);
        }
    }

    #[test]
    fn test_objectreader() {
        let mut data = vec![0; 64];
        getrandom::fill(&mut data).unwrap();
        let data = data;
        let mut buf = vec![0; HEADER + 64];
        buf[HEADER..].copy_from_slice(&data);
        let obj = finalize_object(42, &mut buf).unwrap();

        {
            let mut reader = ObjectReader::new(&obj);
            assert_eq!(reader.buf, &data);
            assert_eq!(reader.remaining(), 64);
            assert_eq!(reader.peak(64).unwrap(), &data);
            assert_eq!(reader.buf, &data);
            assert_eq!(reader.remaining(), 64);

            assert_eq!(
                reader.take(65).unwrap_err(),
                TreeError::DataNotAvailable(65, 64)
            );
            assert_eq!(reader.buf, &data);
            assert_eq!(reader.remaining(), 64);

            assert_eq!(
                reader.peak(65).unwrap_err(),
                TreeError::DataNotAvailable(65, 64)
            );
            assert_eq!(reader.buf, &data);
            assert_eq!(reader.remaining(), 64);

            assert_eq!(reader.take(16).unwrap(), &data[..16]);
            assert_eq!(reader.buf, &data[16..]);
            assert_eq!(reader.remaining(), 48);

            assert_eq!(
                reader.take(49).unwrap_err(),
                TreeError::DataNotAvailable(49, 48)
            );
            assert_eq!(reader.buf, &data[16..]);
            assert_eq!(reader.remaining(), 48);

            assert_eq!(reader.take(48).unwrap(), &data[16..]);
            assert_eq!(reader.buf, &[]);
            assert_eq!(reader.remaining(), 0);
            assert!(reader.finish().is_ok());
        }

        {
            let reader = ObjectReader::new(&obj);
            assert_eq!(reader.finish().unwrap_err(), TreeError::DataNotConsumed(64));
        }

        {
            let mut reader = ObjectReader::new(&obj);
            assert_eq!(reader.take(63).unwrap(), &data[..63]);
            assert_eq!(reader.remaining(), 1);
            assert_eq!(reader.finish().unwrap_err(), TreeError::DataNotConsumed(1));
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

        // "." and ".." are now allowed
        assert_eq!(
            d.insert(String::from("."), Item::EmptyDir).unwrap_err(),
            TreeError::BadName(String::from("."))
        );
        assert!(d.map.is_empty());
        assert_eq!(
            d.insert(String::from(".."), Item::EmptyDir).unwrap_err(),
            TreeError::BadName(String::from(".."))
        );
        assert!(d.map.is_empty());

        // Max length name "BBBB..."
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
            let mut obj = MutObject::new(1, &mut buf);
            assert_eq!(d.serialize_into(&mut obj), Err(TreeError::EmptyDirectory));
        }
        d.insert(String::from("src"), Item::EmptyDir).unwrap();
        {
            let mut buf = Vec::new();
            let mut obj = MutObject::new(1, &mut buf);
            assert_eq!(d.serialize_into(&mut obj), Ok(()));
            let obj = obj.finalize().unwrap();
            assert_eq!(obj.as_data(), b"\x02src\x00");
        }
        d.insert(String::from("REAMDE.md"), Item::EmptyFile)
            .unwrap();
        {
            let mut buf = Vec::new();
            let mut obj = MutObject::new(1, &mut buf);
            assert_eq!(d.serialize_into(&mut obj), Ok(()));
            let obj = obj.finalize().unwrap();
            assert_eq!(obj.as_data(), b"\x08REAMDE.md\x01\x02src\x00");
        }
        d.insert(
            String::from("foo"),
            Item::SymLink(vec![String::from("bars")]),
        )
        .unwrap();
        {
            let mut buf = Vec::new();
            let mut obj = MutObject::new(1, &mut buf);
            assert_eq!(d.serialize_into(&mut obj), Ok(()));
            let obj = obj.finalize().unwrap();
            assert_eq!(
                obj.as_data(),
                b"\x08REAMDE.md\x01\x02foo\x05\x00\x03bars\x02src\x00"
            );
        }
    }
}
