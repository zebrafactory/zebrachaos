use crate::{HEADER, Hash, Index, Item, Object, ObjectHeader};
use std::fs::File;
use std::io::{self, Read, Seek, Write};
use std::os::unix::fs::FileExt;

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

    pub fn read_entry(&self, item: &Item, buf: &mut Vec<u8>) -> io::Result<()> {
        buf.resize(item.header.size(), 0);
        self.file.read_exact_at(buf, item.offset)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_store() {}
}
