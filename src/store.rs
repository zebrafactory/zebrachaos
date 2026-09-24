use crate::fsutil::{create_for_append, open_for_append, read_exact_at};
use crate::{HEADER, Hash, Index, Item, Object, ObjectError, ObjectHeader, ObjectHeaderResult};
use std::fs::File;
use std::io::{self, Read, Seek, Write};

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
                    let header = ObjectHeader::read_from_buf(&self.buf).unwrap();
                    self.buf.resize(HEADER + header.size(), 0);
                    match self.file.read_exact(&mut self.buf[HEADER..]) {
                        Err(err) => Some(Err(err)),
                        Ok(_) => {
                            // But that doesn't mean we have valid object data
                            match header.verify(&self.buf[HEADER..]) {
                                Err(obj_err) => {
                                    Some(Err(io::Error::other("hash no matchy matchy")))
                                }
                                Ok(header) => {
                                    self.is_closed = false;
                                    Some(Ok(header))
                                }
                            }
                        }
                    }
                }
                Ok(n) => Some(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "could not read full header",
                ))),
                Err(err) => Some(Err(err)),
            }
        }
    }
}

pub struct Store {
    file: File,
    index: Index,
}

impl Store {
    pub fn save(&mut self, object: &Object) -> io::Result<bool> {
        if let Some(item) = self.index.get(object.header().hash()) {
            Ok(false)
        } else {
            let mut header = [0; HEADER];
            object.header().write_to_buf(&mut header).unwrap();
            self.file.write_all(&header)?;
            self.file.write_all(object.data())?;
            Ok(true)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use getrandom;
    use tempfile;

    #[test]
    fn test_object_iter_case_0() {
        // read() should not be called when ObjectIter.is_closed is true
        struct MockFile {}

        impl Read for MockFile {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
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
        // Single byte if file... This will return Some(Err(err)) as this is
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
}
