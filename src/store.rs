use crate::fsutil::{create_for_append, open_for_append, read_exact_at};
use crate::{HEADER, Hash, Index, Item, Object, ObjectError, ObjectHeader, ObjectHeaderResult};
use std::fs::File;
use std::io::{self, Read, Seek, Write};

pub struct ObjectStreamIter<'a, R: Read> {
    file: &'a mut R,
    buf: &'a mut Vec<u8>,
    is_closed: bool,
}

impl<'a, R: Read> ObjectStreamIter<'a, R> {
    pub fn new(file: &'a mut R, buf: &'a mut Vec<u8>) -> Self {
        Self {
            file,
            buf,
            is_closed: false,
        }
    }
}

impl<'a, R: Read> Iterator for ObjectStreamIter<'a, R> {
    type Item = io::Result<ObjectHeaderResult>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.is_closed {
            None
        } else {
            self.buf.resize(HEADER, 0);
            self.is_closed = true;
            match self.file.read(self.buf) {
                Ok(0) => None,
                Ok(n) => Some(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "could not read full header",
                ))),
                Err(err) => Some(Err(err)),
                Ok(HEADER) => {
                    // All headers are valid as long as they are the correct length, so just .unwrap()
                    let header = ObjectHeader::read_from_buf(&self.buf).unwrap();
                    self.buf.resize(HEADER + header.size(), 0);
                    match self.file.read_exact(&mut self.buf[HEADER..]) {
                        Err(err) => Some(Err(err)),
                        Ok(_) => {
                            // But that doesn't mean we have valid object data
                            let result = header.verify(&self.buf[HEADER..]);
                            if result.is_ok() {
                                self.is_closed = false;
                            }
                            Some(Ok(result))
                        }
                    }
                }
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
    use tempfile;

    #[test]
    fn test_store() {
        let mut file = tempfile::tempfile().unwrap();
        let mut buf = Vec::new();

        {
            let mut iter = ObjectStreamIter::new(&mut file, &mut buf);
            assert!(!iter.is_closed);
            assert!(iter.next().is_none());
            assert!(iter.is_closed);
        }
    }
}
