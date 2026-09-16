use crate::{HEADER, Hash, Index, Item, Object, ObjectHeader};
use std::fs::File;
use std::io::{self, Read, Seek, Write};

#[cfg(not(windows))]
use std::os::unix::fs::FileExt;

#[cfg(windows)]
use std::os::windows::fs::FileExt;

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

    #[cfg(not(windows))]
    #[inline]
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        self.file.read_exact_at(buf, offset)
    }

    #[cfg(windows)]
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        // FIXME: There should totally be a seek_read_exact() method for Winders.
        let mut buf = buf;
        let mut offset = offset;
        while !buf.is_empty() {
            match self.file.seek_read(buf, offset) {
                Ok(0) => {
                    break;
                }
                Ok(n) => {
                    buf = &mut buf[n..];
                    offset += n as u64;
                }
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    return Err(e);
                }
            }
        }
        if !buf.is_empty() {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "failed to read object header plus object data",
            ))
        } else {
            Ok(())
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
