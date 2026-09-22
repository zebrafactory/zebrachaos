use crate::{Hash, ObjectHeader};
use std::collections::HashMap;

/// A value in the [Index] map.
pub struct Entry {
    /// The 4 byte object info (3 byte size + 1 byte kind).
    pub info: u32,

    /// File offset at which the object header starts.
    pub offset: u64,
}

impl Entry {
    /// Construct an [Entry].
    pub fn new(info: u32, offset: u64) -> Self {
        Self { info, offset }
    }
}

// This is what is retrieved from an [Index].
pub struct Item {
    pub header: ObjectHeader,
    pub offset: u64,
}

impl Item {
    /// Construct a new [Item].
    pub fn new(header: ObjectHeader, offset: u64) -> Self {
        Self { header, offset }
    }
}

/// An in-memmory index using [std::collections::HashMap].
pub struct Index {
    map: HashMap<Hash, Entry>,
}

impl Index {
    /// Create a new, empty index.
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    /// Lookup an entry by object hash.
    pub fn get(&self, hash: &Hash) -> Option<Item> {
        if let Some(entry) = self.map.get(hash) {
            let header = ObjectHeader::new(hash.clone(), entry.info);
            Some(Item::new(header, entry.offset))
        } else {
            None
        }
    }

    /// Add a new entry in the index using provided header and offset.
    pub fn insert(&mut self, header: ObjectHeader, offset: u64) {
        let entry = Entry::new(header.info(), offset);
        if let Some(previous) = self.map.insert(header.hash().clone(), entry) {
            panic!("Duplicate key in Index: {}", header.hash());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashing::random_hash;

    #[test]
    fn test_index_new() {
        let index = Index::new();
        assert!(index.map.is_empty());
    }

    #[test]
    fn test_index_insert() {
        let mut index = Index::new();
        let header0 = ObjectHeader::new(random_hash(), 41);
        let header1 = ObjectHeader::new(random_hash(), 68);
        index.insert(header0.clone(), 0);
        index.insert(header1.clone(), 420);
    }
}
