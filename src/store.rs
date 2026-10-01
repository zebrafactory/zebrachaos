use crate::{HEADER, Hash, Object, ObjectHeader, read_exact_at};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufReader, Read, Seek, Write};

pub struct ObjectIter<'a, R: Read> {
    file: &'a mut R,
    buf: &'a mut Vec<u8>,
    is_closed: bool,
}

impl<'a, R: Read> ObjectIter<'a, R> {
    pub fn new(file: &'a mut R, buf: &'a mut Vec<u8>) -> Self {
        Self {
            file,
            buf,
            is_closed: false,
        }
    }
}

impl<'a, R: Read> Iterator for ObjectIter<'a, R> {
    type Item = io::Result<ObjectHeader>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.is_closed {
            None
        } else {
            self.is_closed = true;
            self.buf.resize(HEADER, 0);
            match self.file.read(self.buf) {
                Ok(0) => None,
                Ok(HEADER) => {
                    // All headers are valid as long as they are the correct length, so just .unwrap()
                    let header = ObjectHeader::read_from_buf(self.buf).unwrap();
                    self.buf.resize(HEADER + header.size(), 0);
                    match self.file.read_exact(&mut self.buf[HEADER..]) {
                        Ok(_) => {
                            // But that doesn't mean we have the correct corresponding object data
                            match header.verify(&self.buf[HEADER..]) {
                                Ok(header) => {
                                    self.is_closed = false;
                                    Some(Ok(header))
                                }
                                Err(_) => Some(Err(io::Error::other("hash no matchy matchy"))),
                            }
                        }
                        Err(err) => Some(Err(err)),
                    }
                }
                Ok(_n) => Some(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "could not read full header",
                ))),
                Err(err) => Some(Err(err)),
            }
        }
    }
}

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

pub struct Store {
    file: File,
    map: HashMap<Hash, Entry>,
    offset: u64,
}

impl Store {
    pub fn new(file: File) -> Self {
        Self {
            file,
            map: HashMap::new(),
            offset: 0,
        }
    }

    pub fn reindex(&mut self) -> io::Result<()> {
        self.map.clear();
        self.offset = 0;
        self.file.rewind()?;
        let mut file = BufReader::with_capacity(64 * 1024, self.file.try_clone()?);
        let mut buf = Vec::new();
        for result in ObjectIter::new(&mut file, &mut buf) {
            let header = result?;
            let entry = Entry::new(header.info(), self.offset);
            self.offset += (HEADER + header.size()) as u64;
            self.map.insert(header.into_hash(), entry);
        }
        Ok(())
    }

    pub fn save(&mut self, obj: &Object) -> io::Result<bool> {
        if let Some(_entry) = self.map.get(obj.header().hash()) {
            Ok(false)
        } else {
            self.file.write_all(obj.as_buf())?;
            let entry = Entry::new(obj.header().info(), self.offset);
            self.map.insert(*obj.header().hash(), entry);
            self.offset += obj.header().full_size() as u64;
            Ok(true)
        }
    }

    pub fn load<'a>(&self, hash: &Hash, buf: &'a mut Vec<u8>) -> io::Result<Object<'a>> {
        match self.map.get(hash) {
            Some(entry) => {
                let header = ObjectHeader::new(*hash, entry.info);
                buf.resize(header.full_size(), 0);
                read_exact_at(&self.file, buf, entry.offset)?;
                match header.validate_object(buf) {
                    Ok(obj) => Ok(obj),
                    Err(_obj_err) => Err(io::Error::other("hash no match")),
                }
            }
            None => Err(io::Error::other("crap")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testhelpers::random_object;
    use crate::{BUFFER_MAX_SIZE, DIGEST, Hash, OBJECT_MAX_SIZE};
    use getrandom;
    use tempfile;

    #[test]
    fn test_object_iter_case_0() {
        // read() should not be called when ObjectIter.is_closed is true
        struct MockFile {}

        impl Read for MockFile {
            fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                panic!("should not be called");
            }
        }

        let mut file = MockFile {};
        let mut buf = Vec::new();
        {
            let mut iter = ObjectIter::new(&mut file, &mut buf);
            assert!(!iter.is_closed);
            iter.is_closed = true;
            assert!(iter.next().is_none());
            assert!(iter.is_closed);
        }
    }

    #[test]
    fn test_object_iter_case_1() {
        // Empty file, read() returns Ok(0) on first call
        let mut file = tempfile::tempfile().unwrap();
        let mut buf = Vec::new();
        {
            let mut iter = ObjectIter::new(&mut file, &mut buf);
            assert!(!iter.is_closed);
            assert!(iter.next().is_none());
            assert!(iter.is_closed);
            assert!(iter.next().is_none());
            assert!(iter.is_closed);
        }
        assert_eq!(file.stream_position().unwrap(), 0);
        assert_eq!(&buf, &[0; HEADER]);
    }

    #[test]
    fn test_object_iter_case_2() {
        // Single byte in file... This will return Some(Err(err)) as this is
        // a partially written object that cannot be validated
        let mut file = tempfile::tempfile().unwrap();
        let mut buf = Vec::new();
        file.write_all(b"4").unwrap();
        file.rewind().unwrap();
        {
            let mut iter = ObjectIter::new(&mut file, &mut buf);
            assert!(!iter.is_closed);
            assert_eq!(
                iter.next().unwrap().unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
            assert!(iter.is_closed);
        }
        assert_eq!(buf.len(), HEADER);
        assert_ne!(&buf, &[0; HEADER]);
        assert_eq!(&buf[..1], b"4");
        assert_eq!(&buf[1..], &[0; HEADER - 1]);
        assert_eq!(file.stream_position().unwrap(), 1);
    }

    #[test]
    fn test_object_iter_case_3() {
        // file is HEADER bytes long, but is missing expected 1 byte of object data
        let mut file = tempfile::tempfile().unwrap();
        let mut buf = Vec::new();
        file.write_all(&[0; HEADER]).unwrap();
        file.rewind().unwrap();
        {
            let mut iter = ObjectIter::new(&mut file, &mut buf);
            assert!(!iter.is_closed);
            assert_eq!(
                iter.next().unwrap().unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
            assert!(iter.is_closed);
        }
        assert_eq!(buf.len(), HEADER + 1);
        assert_eq!(&buf, &[0; HEADER + 1]);
    }

    #[test]
    fn test_object_iter_case_4() {
        // file is (HEADER + 1) bytes long, but hash is wrong
        let mut file = tempfile::tempfile().unwrap();
        let mut buf = Vec::new();
        file.write_all(&[0; HEADER + 1]).unwrap();
        file.rewind().unwrap();
        {
            let mut iter = ObjectIter::new(&mut file, &mut buf);
            assert!(!iter.is_closed);
            assert_eq!(
                iter.next().unwrap().unwrap_err().kind(),
                io::ErrorKind::Other
            );
            assert!(iter.is_closed);
        }
        assert_eq!(buf.len(), HEADER + 1);
        assert_eq!(&buf, &[0; HEADER + 1]);
    }

    #[test]
    fn test_object_iter_case_5() {
        // One valid 1-byte object
        let mut file = tempfile::tempfile().unwrap();
        let mut buf = vec![0; HEADER + 1];
        buf[HEADER..].copy_from_slice(&[69; 1]);
        let hash = Hash::compute_with_info(0, &[69; 1]);
        buf[..DIGEST].copy_from_slice(hash.as_bytes());
        file.write_all(&buf).unwrap();
        file.rewind().unwrap();
        {
            let mut iter = ObjectIter::new(&mut file, &mut buf);
            assert!(!iter.is_closed);
            let header = iter.next().unwrap().unwrap();
            assert!(!iter.is_closed);
            assert_eq!(header.hash(), &hash);
            assert_eq!(header.size(), 1);
            assert_eq!(header.kind(), 0);
            assert!(iter.next().is_none());
            assert!(iter.is_closed);
        }
        assert_eq!(buf.len(), HEADER);
    }

    #[test]
    fn test_object_iter_case_6() {
        // One valid OBJECT_MAX_SIZE byte object
        let mut file = tempfile::tempfile().unwrap();
        let mut buf = vec![255; HEADER + OBJECT_MAX_SIZE];
        let hash = Hash::compute(&buf[DIGEST..]);
        buf[..DIGEST].copy_from_slice(hash.as_bytes());
        file.write_all(&buf).unwrap();
        file.rewind().unwrap();
        {
            let mut iter = ObjectIter::new(&mut file, &mut buf);
            assert!(!iter.is_closed);
            let header = iter.next().unwrap().unwrap();
            assert!(!iter.is_closed);
            assert_eq!(header.hash(), &hash);
            assert_eq!(header.size(), OBJECT_MAX_SIZE);
            assert_eq!(header.kind(), 255);
            assert!(iter.next().is_none());
            assert!(iter.is_closed);
        }
        assert_eq!(buf.len(), HEADER);
    }

    fn object_iter_test_helper(count: usize, small: bool) {
        let mut file = tempfile::tempfile().unwrap();
        let mut buf = vec![0; HEADER + OBJECT_MAX_SIZE];

        let mut total_size = 0_u64;
        let mut hashlist: Vec<Hash> = Vec::with_capacity(count);
        for _ in 0..count {
            let hash = random_object(&mut buf, small);
            total_size += buf.len() as u64;
            hashlist.push(hash);
            file.write_all(&buf).unwrap();
        }

        // All good
        file.rewind().unwrap();
        for (i, result) in ObjectIter::new(&mut file, &mut buf).enumerate() {
            let header = result.unwrap();
            assert_eq!(&hashlist[i], header.hash());
        }
        {
            let mut iter = ObjectIter::new(&mut file, &mut buf);
            assert!(iter.next().is_none());
        }
        assert_eq!(file.stream_position().unwrap(), total_size);

        // One extra byte is present (partially written header)
        file.write_all(b"4").unwrap();
        file.rewind().unwrap();
        buf.clear();
        {
            let mut iter = ObjectIter::new(&mut file, &mut buf);
            for i in 0..count {
                let header = iter.next().unwrap().unwrap();
                assert_eq!(&hashlist[i], header.hash());
            }
            assert!(!iter.is_closed);
            assert_eq!(
                iter.next().unwrap().unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
            assert!(iter.is_closed);
            assert!(iter.next().is_none());
        }
        assert_eq!(file.stream_position().unwrap(), total_size + 1);

        // Final byte is missing
        file.set_len(total_size - 1).unwrap();
        file.rewind().unwrap();
        buf.clear();
        {
            let mut iter = ObjectIter::new(&mut file, &mut buf);
            for i in 0..count - 1 {
                let header = iter.next().unwrap().unwrap();
                assert_eq!(&hashlist[i], header.hash());
            }
            assert!(!iter.is_closed);
            assert_eq!(
                iter.next().unwrap().unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
            assert!(iter.is_closed);
            assert!(iter.next().is_none());
        }
        assert_eq!(file.stream_position().unwrap(), total_size - 1);

        // Final 32 bytes are missing
        file.set_len(total_size - 32).unwrap();
        file.rewind().unwrap();
        buf.clear();
        {
            let mut iter = ObjectIter::new(&mut file, &mut buf);
            for i in 0..count - 1 {
                let header = iter.next().unwrap().unwrap();
                assert_eq!(&hashlist[i], header.hash());
            }
            assert!(!iter.is_closed);
            assert_eq!(
                iter.next().unwrap().unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
            assert!(iter.is_closed);
            assert!(iter.next().is_none());
        }
        assert_eq!(file.stream_position().unwrap(), total_size - 32);

        // Final 32 bytes are new random data, making hash wrong
        let mut rando = [0; 32];
        getrandom::fill(&mut rando).unwrap();
        file.write_all(&rando).unwrap();
        file.rewind().unwrap();
        buf.clear();
        {
            let mut iter = ObjectIter::new(&mut file, &mut buf);
            for i in 0..count - 1 {
                let header = iter.next().unwrap().unwrap();
                assert_eq!(&hashlist[i], header.hash());
            }
            assert!(!iter.is_closed);
            assert_eq!(
                iter.next().unwrap().unwrap_err().kind(),
                io::ErrorKind::Other
            );
            assert!(iter.is_closed);
            assert!(iter.next().is_none());
        }
        assert_eq!(file.stream_position().unwrap(), total_size);
    }

    #[test]
    fn test_object_iter_case_7() {
        // Large number of valid small objects
        object_iter_test_helper(1024, true);
    }

    #[test]
    fn test_object_iter_case_8() {
        // Small number of valid large objects
        object_iter_test_helper(42, false);
    }

    #[test]
    fn test_store_reindex() {
        let file = tempfile::tempfile().unwrap();
        let mut store = Store::new(file);
        assert!(store.reindex().is_ok());
        let count = 69;
        let mut buf = Vec::new();
        let mut hashlist: Vec<Hash> = Vec::new();
        for _ in 0..count {
            let hash = random_object(&mut buf, false);
            hashlist.push(hash);
            store.file.write_all(&buf).unwrap();
        }
        assert!(store.map.is_empty());
        for hash in &hashlist {
            assert_eq!(
                store.load(&hash, &mut buf).unwrap_err().kind(),
                io::ErrorKind::Other
            );
        }
        assert!(store.reindex().is_ok());
        assert_eq!(store.map.len(), count);
        assert_eq!(store.file.stream_position().unwrap(), store.offset);
        for hash in &hashlist {
            assert!(store.map.contains_key(hash));
            assert!(store.load(&hash, &mut buf).is_ok());
        }
    }

    #[test]
    fn test_store_save_load() {
        let file = tempfile::tempfile().unwrap();
        let mut store = Store::new(file);
        let mut buf = Vec::with_capacity(BUFFER_MAX_SIZE);
        let count = 32;
        let mut hashlist = Vec::with_capacity(count);
        for _ in 0..count {
            let hash = random_object(&mut buf, false);
            {
                let obj = Object::validate(&buf).unwrap();
                store.save(&obj).unwrap();
            }
            buf.clear();
            {
                let obj = store.load(&hash, &mut buf).unwrap();
                assert_eq!(obj.header().hash(), &hash);
            }
            assert_eq!(hash, Hash::compute(&buf[DIGEST..]));
            hashlist.push(hash);
        }

        for hash in &hashlist {
            let obj = store.load(hash, &mut buf).unwrap();
            assert_eq!(hash, &Hash::compute(&obj.as_buf()[DIGEST..]));
        }
    }
}
