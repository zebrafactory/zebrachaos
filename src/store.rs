use crate::fsutil::{create_for_append, open_for_append, read_exact_at};
use crate::{HEADER, Hash, Index, Item, Object, ObjectHeader};
use std::fs::File;
use std::io::{self, Read, Seek, Write};

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
