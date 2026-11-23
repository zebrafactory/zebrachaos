// See https://git-scm.com/book/en/v2/Git-Internals-Git-Objects

use crate::{
    DATA_MAX_LEN, DIGEST, HEADER, Hash, Kind, MutObject, Object, ObjectError, Store,
    TREE_MAX_DEPTH, create_for_append, finalize_object,
};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::{
    fs::Permissions,
    os::unix::fs::{PermissionsExt, symlink},
};

/// Error encountered when decoding or encoding a tree.
#[derive(Debug, PartialEq)]
pub enum TreeError {
    NameLenBounds(usize),
    NameUtf8(std::string::FromUtf8Error),
    BadName(String),
    DuplicateName(String, Item),
    ItemKind(u8),
    EmptyTree,
    TreeCapacityExceeded,
    DataNotAvailable(usize, usize),
    DataNotConsumed(usize),
    ObjectNotFound(Hash),
    ObjectError(ObjectError),
    TreeDepth(usize),
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

impl From<ObjectError> for TreeError {
    fn from(obj_err: ObjectError) -> Self {
        Self::ObjectError(obj_err)
    }
}

/// Value in the directory map.
#[derive(Debug, PartialEq)]
pub enum Item {
    /// An empty directory.
    EmptyTree,

    /// An empty file.
    EmptyFile,

    /// A directory.
    Tree(Hash),

    /// A file stored across 1 or more objects.
    File(Hash),

    /// Same as a File, except executable.
    ExeFile(Hash),

    /// A symbolic link (FIXME: should perhaps store this in an object to match Git).
    SymLink(Vec<String>),
}

impl Item {
    pub fn kind_byte(&self) -> u8 {
        match self {
            Self::EmptyTree => 0,
            Self::EmptyFile => 1,
            Self::Tree(_) => 2,
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
    let mut names = Vec::with_capacity(count);
    for _ in 0..count {
        names.push(decode_name(reader)?);
    }
    Ok(names)
}

fn decode_hash(reader: &mut ObjectReader) -> Result<Hash, TreeError> {
    Ok(Hash::from_slice(reader.take(DIGEST)?).unwrap())
}

fn decode_item(reader: &mut ObjectReader) -> Result<Item, TreeError> {
    let kind = reader.take(1)?[0];
    match kind {
        0 => Ok(Item::EmptyTree),
        1 => Ok(Item::EmptyFile),
        2 => Ok(Item::Tree(decode_hash(reader)?)),
        3 => Ok(Item::File(decode_hash(reader)?)),
        4 => Ok(Item::ExeFile(decode_hash(reader)?)),
        5 => Ok(Item::SymLink(decode_symlink(reader)?)),
        _ => Err(TreeError::ItemKind(kind)),
    }
}

fn encode_name(name: &str, obj: &mut MutObject) -> Result<(), TreeError> {
    let encoded_size = minus_one_encode(name.len())?;
    for buf in [&[encoded_size], name.as_bytes()] {
        match obj.try_extend_from_slice(buf) {
            Ok(_) => {}
            Err(_) => return Err(TreeError::TreeCapacityExceeded),
        }
    }
    Ok(())
}

fn encode_symlink(symlink: &[String], obj: &mut MutObject) -> Result<(), TreeError> {
    let encoded_count = minus_one_encode(symlink.len())?;
    match obj.try_extend_from_slice(&[encoded_count]) {
        Ok(_) => {}
        Err(_) => return Err(TreeError::TreeCapacityExceeded),
    }
    for name in symlink {
        encode_name(name, obj)?;
    }
    Ok(())
}

fn encode_item(item: &Item, obj: &mut MutObject) -> Result<(), TreeError> {
    match obj.try_extend_from_slice(&[item.kind_byte()]) {
        Ok(_) => {}
        Err(_) => return Err(TreeError::TreeCapacityExceeded),
    }
    match item {
        Item::EmptyTree | Item::EmptyFile => {}
        Item::Tree(hash) | Item::File(hash) | Item::ExeFile(hash) => {
            match obj.try_extend_from_slice(hash.as_bytes()) {
                Ok(_) => {}
                Err(_) => return Err(TreeError::TreeCapacityExceeded),
            }
        }
        Item::SymLink(target) => {
            encode_symlink(target, obj)?;
        }
    }
    Ok(())
}

/// Consume data in an [Object].
///
/// # Examples
///
/// ```
/// use zf_zebrachaos::{Kind, MutObject, ObjectReader, TreeError};
///
/// let mut buf = Vec::new();
/// let mut obj = MutObject::new(Kind::Data, &mut buf);
/// obj.try_extend_from_slice(b"hello, world").unwrap();
/// let obj = obj.finalize().unwrap();
/// let mut reader = ObjectReader::new(&obj);
/// assert!(!reader.is_empty());
/// assert_eq!(reader.take(12).unwrap(), b"hello, world");
/// assert!(reader.is_empty());
/// assert_eq!(reader.take(1).unwrap_err(), TreeError::DataNotAvailable(1, 0));
/// ```
#[derive(Debug)]
pub struct ObjectReader<'a> {
    buf: &'a [u8],
}

impl<'a> ObjectReader<'a> {
    #[cfg(test)]
    fn raw(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    /// Initialize reader with all of object's data.
    ///
    /// As valid objects always have at least 1 byte of data, a new reader never starts empty.
    pub fn new(obj: &'a Object) -> Self {
        Self { buf: obj.as_data() }
    }

    /// Returns `true` if data is fully consumed.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Bytes of data remaining.
    pub fn remaining(&self) -> usize {
        self.buf.len()
    }

    /// If available, consume `amount` bytes from buffer.
    pub fn take(&mut self, amount: usize) -> Result<&[u8], TreeError> {
        if self.buf.len() < amount {
            Err(TreeError::DataNotAvailable(amount, self.buf.len()))
        } else {
            let taken = &self.buf[..amount];
            self.buf = &self.buf[amount..];
            Ok(taken)
        }
    }

    /// If avialable, peak at next *amount* bytes in buffer, without consuming any bytes.
    pub fn peak(&self, amount: usize) -> Result<&[u8], TreeError> {
        if self.buf.len() < amount {
            Err(TreeError::DataNotAvailable(amount, self.buf.len()))
        } else {
            Ok(&self.buf[..amount])
        }
    }

    /// Enusre full data was consumed.
    ///
    /// Fixme: this shoud perhaps be a Drop trait.
    pub fn finish(self) -> Result<(), TreeError> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(TreeError::DataNotConsumed(self.buf.len()))
        }
    }
}

/// A list of hashes pointing to other [Kind::Data] or [Kind::MegaData] objects.
#[derive(Debug)]
pub struct MegaData {
    leaves: Vec<Hash>,
}

impl MegaData {
    pub fn new() -> Self {
        Self { leaves: Vec::new() }
    }

    pub fn as_vec(&self) -> &Vec<Hash> {
        &self.leaves
    }

    pub fn push(&mut self, hash: Hash) {
        self.leaves.push(hash);
    }

    pub fn serialize_into(&self, obj: &mut MutObject) -> Result<(), TreeError> {
        if self.leaves.is_empty() {
            Err(TreeError::EmptyTree)
        } else {
            for hash in &self.leaves {
                obj.try_extend_from_slice(hash.as_bytes()).unwrap();
            }
            Ok(())
        }
    }

    pub fn finalize_into<'a>(self, buf: &'a mut Vec<u8>) -> Result<Object<'a>, TreeError> {
        let mut obj = MutObject::new(Kind::MegaData, buf);
        self.serialize_into(&mut obj)?;
        Ok(obj.finalize().unwrap())
    }

    pub fn deserialize_from(obj: &Object) -> Result<Self, TreeError> {
        match obj.header().check_kind(Kind::MegaData) {
            Ok(_) => {
                let mut big_data = Self::new();
                let mut reader = ObjectReader::new(obj);
                while !reader.is_empty() {
                    big_data.push(decode_hash(&mut reader)?);
                }
                reader.finish()?;
                Ok(big_data)
            }
            Err(obj_err) => Err(obj_err.into()),
        }
    }
}

/// A directory-like map. similar to a Git Tree object.
///
/// # Examples
///
/// ```
/// use zf_zebrachaos::{Item, Kind, Tree};
///
/// let mut tree = Tree::new();
/// tree.insert(String::from("README.md"), Item::EmptyFile).unwrap();
/// tree.insert(String::from("tests"), Item::EmptyTree).unwrap();
/// let mut buf = Vec::new();
/// let header = tree.finalize_into(&mut buf).unwrap().into_header();
/// assert_eq!(header.try_kind().unwrap(), Kind::Tree);
/// ```
pub struct Tree {
    map: HashMap<String, Item>,
}

impl Default for Tree {
    fn default() -> Self {
        Self::new()
    }
}

impl Tree {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    pub fn as_map(&self) -> &HashMap<String, Item> {
        &self.map
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
            Err(TreeError::EmptyTree)
        } else {
            let mut pairs = Vec::from_iter(self.map.iter());
            pairs.sort_by(|a, b| a.0.cmp(b.0));
            for (name, item) in pairs.iter() {
                encode_name(name, obj)?;
                encode_item(item, obj)?;
            }
            Ok(())
        }
    }

    pub fn finalize_into<'a>(self, buf: &'a mut Vec<u8>) -> Result<Object<'a>, TreeError> {
        let mut obj = MutObject::new(Kind::Tree, buf);
        self.serialize_into(&mut obj)?;
        Ok(obj.finalize().unwrap())
    }

    pub fn deserialize_from(obj: &Object) -> Result<Self, TreeError> {
        match obj.header().check_kind(Kind::Tree) {
            Ok(_) => {
                let mut directory = Tree::new();
                let mut reader = ObjectReader::new(obj);
                while !reader.is_empty() {
                    let name = decode_name(&mut reader)?;
                    let item = decode_item(&mut reader)?;
                    directory.insert(name, item)?;
                }
                reader.finish()?;
                Ok(directory)
            }
            Err(obj_err) => Err(obj_err.into()),
        }
    }
}

/// Save/restore a directory tree to/from a filesystem.
#[derive(Debug)]
pub struct Repository {
    store: Store,
    buf: Vec<u8>,
}

impl Repository {
    /// Wrap a [Store].
    pub fn new(store: Store) -> Self {
        Self {
            store,
            buf: Vec::new(),
        }
    }

    /// Consume instance and return underlying [Store].
    pub fn into_store(self) -> Store {
        self.store
    }

    fn restore_file(&mut self, hash: &Hash, path: &Path) -> io::Result<File> {
        if let Some(result) = self.store.load(hash, &mut self.buf) {
            let obj = result?;
            let mut file = create_for_append(path)?;
            match obj.header().try_kind() {
                Ok(Kind::Data) => {
                    file.write_all(obj.as_data())?;
                    Ok(file)
                }
                Ok(Kind::MegaData) => {
                    let mega_data = match MegaData::deserialize_from(&obj) {
                        Ok(mega_data) => mega_data,
                        Err(tree_err) => return Err(tree_err.into_io_error()),
                    };
                    for leaf_hash in mega_data.as_vec() {
                        // FIXME: probably should add a depth counter to MegaData. Also, currently we only
                        // support MegaData trees 1-deep.
                        if let Some(result) =
                            self.store.load_kind(Kind::Data, leaf_hash, &mut self.buf)
                        {
                            let obj = result?;
                            file.write_all(obj.as_data())?;
                        } else {
                            return Err(TreeError::ObjectNotFound(*leaf_hash).into_io_error());
                        }
                    }
                    Ok(file)
                }
                _ => panic!("oh no"),
            }
        } else {
            Err(TreeError::ObjectNotFound(*hash).into_io_error())
        }
    }

    #[cfg(unix)]
    fn restore_executable_file(&mut self, hash: &Hash, path: &Path) -> io::Result<()> {
        let file = self.restore_file(hash, path)?;
        file.set_permissions(Permissions::from_mode(0o700))?;
        Ok(())
    }

    #[cfg(windows)]
    fn restore_executable_file(&mut self, hash: &Hash, path: &Path) -> io::Result<()> {
        self.restore_file(hash, path)?;
        Ok(())
    }

    #[cfg(unix)]
    fn restore_symlink(&mut self, value: &Vec<String>, path: &Path) -> io::Result<()> {
        let mut target = PathBuf::new();
        for name in value {
            target.push(name);
        }
        symlink(&target, path)?;
        Ok(())
    }

    #[cfg(windows)]
    fn restore_symlink(&mut self, _value: &Vec<String>, _path: &Path) -> io::Result<()> {
        Ok(())
    }

    fn load_directory(&mut self, hash: &Hash) -> io::Result<Tree> {
        if let Some(result) = self.store.load_kind(Kind::Tree, hash, &mut self.buf) {
            let obj = result?;
            match Tree::deserialize_from(&obj) {
                Ok(dir) => Ok(dir),
                Err(tree_err) => Err(tree_err.into_io_error()),
            }
        } else {
            Err(TreeError::ObjectNotFound(*hash).into_io_error())
        }
    }

    fn restore_inner(&mut self, hash: &Hash, path: &Path, depth: usize) -> io::Result<()> {
        if depth >= TREE_MAX_DEPTH {
            return Err(TreeError::TreeDepth(depth).into_io_error());
        }
        let dir = self.load_directory(hash)?;
        for (name, item) in dir.as_map() {
            let sub_path = path.join(name);
            match item {
                Item::EmptyTree => {
                    fs::create_dir(&sub_path)?;
                }
                Item::EmptyFile => {
                    create_for_append(&sub_path)?;
                }
                Item::Tree(sub_hash) => {
                    fs::create_dir(&sub_path)?;
                    self.restore_inner(sub_hash, &sub_path, depth + 1)?;
                }
                Item::File(sub_hash) => {
                    self.restore_file(sub_hash, &sub_path)?;
                }
                Item::ExeFile(sub_hash) => {
                    self.restore_executable_file(sub_hash, &sub_path)?;
                }
                Item::SymLink(target) => {
                    self.restore_symlink(target, &sub_path)?;
                }
            }
        }
        Ok(())
    }

    /// Restore a tree into an empty directory.
    pub fn restore(&mut self, hash: &Hash, dir: &Path) -> io::Result<()> {
        self.restore_inner(hash, dir, 0)
    }

    fn snapshot_inner(&mut self, dir: &Path, depth: usize) -> io::Result<Item> {
        if depth >= TREE_MAX_DEPTH {
            return Err(TreeError::TreeDepth(depth).into_io_error());
        }
        let mut directory = Tree::new();
        for result in fs::read_dir(dir)? {
            let entry = result?;
            let metadata = entry.metadata()?;
            let name = entry.file_name().to_str().unwrap().to_string();
            let item = if metadata.is_symlink() {
                let pb = fs::read_link(entry.path())?;
                let mut target = Vec::new();
                for p in &pb {
                    target.push(p.to_str().unwrap().to_string());
                }
                Item::SymLink(target)
            } else if metadata.is_file() {
                match metadata.len() {
                    0 => Item::EmptyFile,
                    n if n > DATA_MAX_LEN as u64 => {
                        let mut file = File::options().read(true).open(entry.path())?;
                        let mut big_data = MegaData::new();
                        let mut remaining = n;
                        while remaining > 0 {
                            let amount = core::cmp::min(remaining, DATA_MAX_LEN as u64);
                            remaining -= amount;
                            self.buf.resize(HEADER + amount as usize, 0);
                            file.read_exact(&mut self.buf[HEADER..])?;
                            let obj = finalize_object(Kind::Data as u8, &mut self.buf).unwrap();
                            self.store.save(&obj)?;
                            let hash = *obj.header().hash();
                            big_data.push(hash);
                        }
                        let obj = big_data.finalize_into(&mut self.buf).unwrap();
                        self.store.save(&obj)?;
                        Item::File(*obj.header().hash())
                    }
                    n => {
                        self.buf.resize(HEADER + n as usize, 0);
                        let mut file = File::options().read(true).open(entry.path())?;
                        file.read_exact(&mut self.buf[HEADER..])?;
                        let obj = finalize_object(Kind::Data as u8, &mut self.buf).unwrap();
                        self.store.save(&obj)?;
                        Item::File(*obj.header().hash())
                    }
                }
            } else if metadata.is_dir() {
                self.snapshot_inner(&entry.path(), depth + 1)?
            } else {
                panic!("oh, shit!");
            };
            directory.insert(name, item).unwrap();
        }
        if directory.as_map().is_empty() {
            Ok(Item::EmptyTree)
        } else {
            let obj = directory.finalize_into(&mut self.buf).unwrap();
            self.store.save(&obj)?;
            Ok(Item::Tree(*obj.header().hash()))
        }
    }

    /// Snapshot a directory and save the tree into the store.
    pub fn snapshot(&mut self, dir: &Path) -> io::Result<Item> {
        self.snapshot_inner(dir, 0)
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
        assert_eq!(decode_item(&mut reader), Ok(Item::EmptyTree));

        let buf = [1];
        let mut reader = ObjectReader::raw(&buf);
        assert_eq!(decode_item(&mut reader), Ok(Item::EmptyFile));

        let buf = [2; DIGEST + 1];
        let mut reader = ObjectReader::raw(&buf);
        assert_eq!(
            decode_item(&mut reader),
            Ok(Item::Tree(Hash::from_bytes([2; DIGEST])))
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
    fn test_encode_name() {
        let mut buf = Vec::new();
        let mut obj = MutObject::new(Kind::Control, &mut buf);
        assert_eq!(encode_name("", &mut obj), Err(TreeError::NameLenBounds(0)));
        assert_eq!(obj.remaining(), DATA_MAX_LEN);
        assert_eq!(
            encode_name(&String::from_utf8(vec![65; 257]).unwrap(), &mut obj),
            Err(TreeError::NameLenBounds(257))
        );
        assert_eq!(obj.remaining(), DATA_MAX_LEN);
        assert!(encode_name("A", &mut obj).is_ok());
        assert!(encode_name("BA", &mut obj).is_ok());
        let obj = obj.finalize().unwrap();
        assert_eq!(obj.as_data(), &[0, 65, 1, 66, 65]);
    }

    #[test]
    fn test_encode_item() {
        let hash = random_hash();
        let mut buf = Vec::new();
        {
            let mut obj = MutObject::new(Kind::Control, &mut buf);
            let item = Item::EmptyTree;
            encode_item(&item, &mut obj).unwrap();
            let obj = obj.finalize().unwrap();
            assert_eq!(obj.as_data(), &[0]);
        }
        {
            let mut obj = MutObject::new(Kind::Control, &mut buf);
            let item = Item::EmptyFile;
            encode_item(&item, &mut obj).unwrap();
            let obj = obj.finalize().unwrap();
            assert_eq!(obj.as_data(), &[1]);
        }
        {
            let mut obj = MutObject::new(Kind::Control, &mut buf);
            let item = Item::Tree(hash.clone());
            encode_item(&item, &mut obj).unwrap();
            let obj = obj.finalize().unwrap();
            assert_eq!(obj.as_data()[0], 2);
            assert_eq!(&obj.as_data()[1..], hash.as_bytes());
        }
        {
            let mut obj = MutObject::new(Kind::Control, &mut buf);
            let item = Item::File(hash.clone());
            encode_item(&item, &mut obj).unwrap();
            let obj = obj.finalize().unwrap();
            assert_eq!(obj.as_data()[0], 3);
            assert_eq!(&obj.as_data()[1..], hash.as_bytes());
        }
        {
            let mut obj = MutObject::new(Kind::Control, &mut buf);
            let item = Item::ExeFile(hash.clone());
            encode_item(&item, &mut obj).unwrap();
            let obj = obj.finalize().unwrap();
            assert_eq!(obj.as_data()[0], 4);
            assert_eq!(&obj.as_data()[1..], hash.as_bytes());
        }
        {
            let mut obj = MutObject::new(Kind::Control, &mut buf);
            let item = Item::SymLink(vec![String::from("A")]);
            encode_item(&item, &mut obj).unwrap();
            let obj = obj.finalize().unwrap();
            assert_eq!(obj.as_data()[0], 5);
            assert_eq!(&obj.as_data()[1..], &[0, 0, 65]);
        }
        {
            let mut obj = MutObject::new(Kind::Data, &mut buf);
            let item = Item::SymLink(vec![String::from_utf8(vec![65; 256]).unwrap()]);
            encode_item(&item, &mut obj).unwrap();
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
    fn test_tree_new() {
        let d = Tree::new();
        assert!(d.map.is_empty());
    }

    #[test]
    fn test_tree_insert() {
        let mut d = Tree::new();

        // Empty name
        assert_eq!(
            d.insert(String::from(""), Item::EmptyTree).unwrap_err(),
            TreeError::NameLenBounds(0)
        );
        assert!(d.map.is_empty());

        // Name is too long
        assert_eq!(
            d.insert(String::from_utf8(vec![0x42; 257]).unwrap(), Item::EmptyTree)
                .unwrap_err(),
            TreeError::NameLenBounds(257)
        );
        assert!(d.map.is_empty());

        // "." and ".." are now allowed
        assert_eq!(
            d.insert(String::from("."), Item::EmptyTree).unwrap_err(),
            TreeError::BadName(String::from("."))
        );
        assert!(d.map.is_empty());
        assert_eq!(
            d.insert(String::from(".."), Item::EmptyTree).unwrap_err(),
            TreeError::BadName(String::from(".."))
        );
        assert!(d.map.is_empty());

        // Max length name "BBBB..."
        let bees = String::from_utf8(vec![0x42; 256]).unwrap();
        assert!(d.insert(bees.clone(), Item::EmptyTree).is_ok());
        assert_eq!(d.map.len(), 1);
        assert_eq!(d.map.get(&bees), Some(&Item::EmptyTree));

        // Duplicate of same max length name
        assert_eq!(
            d.insert(bees.clone(), Item::EmptyFile).unwrap_err(),
            TreeError::DuplicateName(bees.clone(), Item::EmptyFile)
        );
        assert_eq!(d.map.len(), 1);
        assert_eq!(d.map.get(&bees), Some(&Item::EmptyTree));

        // Min length name "B"
        let b = String::from_utf8(vec![0x42; 1]).unwrap();
        assert_eq!(&b, "B");
        assert!(d.insert(b.clone(), Item::EmptyFile).is_ok());
        assert_eq!(d.map.len(), 2);
        assert_eq!(d.map.get(&bees), Some(&Item::EmptyTree));
        assert_eq!(d.map.get(&b), Some(&Item::EmptyFile));

        // Duplicate of same min length name
        assert_eq!(
            d.insert(b.clone(), Item::EmptyTree).unwrap_err(),
            TreeError::DuplicateName(b.clone(), Item::EmptyTree)
        );
        assert_eq!(d.map.len(), 2);
        assert_eq!(d.map.get(&bees), Some(&Item::EmptyTree));
        assert_eq!(d.map.get(&b), Some(&Item::EmptyFile));
    }

    #[test]
    fn test_tree_serialize_into() {
        let mut d = Tree::new();
        {
            let mut buf = Vec::new();
            let mut obj = MutObject::new(Kind::Data, &mut buf);
            assert_eq!(d.serialize_into(&mut obj), Err(TreeError::EmptyTree));
        }
        d.insert(String::from("src"), Item::EmptyTree).unwrap();
        {
            let mut buf = Vec::new();
            let mut obj = MutObject::new(Kind::Data, &mut buf);
            assert_eq!(d.serialize_into(&mut obj), Ok(()));
            let obj = obj.finalize().unwrap();
            assert_eq!(obj.as_data(), b"\x02src\x00");
        }
        d.insert(String::from("REAMDE.md"), Item::EmptyFile)
            .unwrap();
        {
            let mut buf = Vec::new();
            let mut obj = MutObject::new(Kind::Data, &mut buf);
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
            let mut obj = MutObject::new(Kind::Data, &mut buf);
            assert_eq!(d.serialize_into(&mut obj), Ok(()));
            let obj = obj.finalize().unwrap();
            assert_eq!(
                obj.as_data(),
                b"\x08REAMDE.md\x01\x02foo\x05\x00\x03bars\x02src\x00"
            );
        }
    }

    #[test]
    fn test_repository_max_depth() {
        let tmp = tempfile::TempDir::new().unwrap();
        let filename = tmp.path().join("chaos.data");
        let mut repo = Repository::new(Store::create(&filename).unwrap());
        let hash = random_hash();
        let path = tmp.path().join("foo.bar");
        let too_big = TREE_MAX_DEPTH + 1;
        assert_eq!(
            repo.restore_inner(&hash, &path, too_big)
                .unwrap_err()
                .into_inner()
                .unwrap()
                .downcast()
                .unwrap(),
            Box::new(TreeError::TreeDepth(too_big))
        );
        assert_eq!(
            repo.snapshot_inner(&path, too_big)
                .unwrap_err()
                .into_inner()
                .unwrap()
                .downcast()
                .unwrap(),
            Box::new(TreeError::TreeDepth(too_big))
        );
    }
}
