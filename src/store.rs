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

    fn next_inner(&mut self) -> io::Result<ObjectHeaderResult> {
        self.buf.resize(HEADER, 0);
        self.file.read_exact(&mut self.buf)?;

        // All headers are valid as long as they are the correct length, so just .unwrap()
        let header = ObjectHeader::read_from_buf(&self.buf).unwrap();
        self.buf.resize(HEADER + header.size(), 0);
        self.file.read_exact(&mut self.buf[HEADER..])?;

        // But that doesn't mean we have the correct corresponding obejct data, so this can fail.
        match header.verify(&self.buf[HEADER..]) {
            Err(err) => {
                self.is_closed = true;
                Ok(Err(err))
            }
            Ok(_) => Ok(Ok(header)),
        }
    }
}

impl<'a, R: Read> Iterator for ObjectStreamIter<'a, R> {
    type Item = io::Result<ObjectHeaderResult>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.is_closed {
            None
        } else {
            match self.next_inner() {
                Err(io_err) => {
                    self.is_closed = true;
                    Some(Err(io_err))
                }
                Ok(header_result) => Some(Ok(header_result)),
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
    }
}
