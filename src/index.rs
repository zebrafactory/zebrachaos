use crate::{HEADER, Hash, Object, ObjectHeader};
use std::collections::HashMap;

pub struct Entry {
    pub info: u32,
    pub offset: u64,
}

impl Entry {
    pub fn new(info: u32, offset: u64) -> Self {
        Self { info, offset }
    }
}

pub struct Item {
    pub header: ObjectHeader,
    pub offset: u64,
}

impl Item {
    pub fn new(header: ObjectHeader, offset: u64) -> Self {
        Self { header, offset }
    }
}

pub struct Index {
    map: HashMap<Hash, Entry>,
}

impl Index {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    pub fn get(&self, hash: &Hash) -> Option<Item> {
        if let Some(entry) = self.map.get(hash) {
            let header = ObjectHeader::new(hash.clone(), entry.info);
            Some(Item::new(header, entry.offset))
        } else {
            None
        }
    }

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
