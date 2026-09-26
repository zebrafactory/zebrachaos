// File system related utilities.

use std::fs::File;
use std::io;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::FileExt;

#[cfg(windows)]
use std::os::windows::fs::FileExt;

#[cfg(unix)]
pub fn read_exact_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<()> {
    file.read_exact_at(buf, offset)
}

// FIXME: There should totally be a seek_read_exact() method for the Winders.
// https://github.com/rust-lang/libs-team/issues/634
// And now there totally is a seek_read_exact() method in Rust nightly!
// https://github.com/rust-lang/rust/issues/162868

#[cfg(all(windows, feature = "nightly"))]
pub fn read_exact_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<()> {
    file.seek_read_exact(buf, offset)
}

#[cfg(all(windows, not(feature = "nightly")))]
pub fn read_exact_at(file: &File, mut buf: &mut [u8], mut offset: u64) -> io::Result<()> {
    while !buf.is_empty() {
        match file.seek_read(buf, offset) {
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
            "failed to fill buffer",
        ))
    } else {
        Ok(())
    }
}

pub fn create_for_append(path: &Path) -> io::Result<File> {
    File::options()
        .read(true)
        .append(true)
        .create_new(true)
        .open(path)
}

pub fn open_for_append(path: &Path) -> io::Result<File> {
    File::options().read(true).append(true).open(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Hash, OBJECT_MAX_SIZE};
    use getrandom;
    use std::collections::HashMap;
    use std::io::Write;
    use tempfile;

    #[test]
    #[cfg(all(windows, feature = "nightly"))]
    fn test_seek_read_exact_seek_write_all() {
        // Make sure windows FileExt.seek_read_exact(), .seek_write_all() are available
        let mut file = tempfile::tempfile().unwrap();
        let mut data = [0; 420];
        getrandom::fill(&mut data).unwrap();
        let data = data;
        file.seek_write_all(&data, 0).unwrap();
        let mut buf = [0; 42];
        file.seek_read_exact(&mut buf, 22);
        assert_eq(&buf, &data[22..64]);
        assert_eq!(file.stream_position().unwrap(), 64);
    }

    #[test]
    fn test_read_exact_at() {
        let mut file = tempfile::tempfile().unwrap();
        let mut buf = vec![0; OBJECT_MAX_SIZE];
        let r = read_exact_at(&mut file, &mut buf, 0);
        assert!(r.is_err());

        getrandom::fill(&mut buf).unwrap();
        let hash = Hash::compute(&buf);
        let hash2 = Hash::compute(&buf[69..]);
        let hash3 = Hash::compute(&buf[69..OBJECT_MAX_SIZE - 42]);
        file.write_all(&buf).unwrap();
        buf.clear();
        buf.resize(OBJECT_MAX_SIZE, 0);

        read_exact_at(&mut file, &mut buf, 0).unwrap();
        assert_eq!(Hash::compute(&buf), hash);

        buf.clear();
        buf.resize(OBJECT_MAX_SIZE - 69, 0);
        assert!(read_exact_at(&mut file, &mut buf, 70).is_err());
        read_exact_at(&mut file, &mut buf, 69).unwrap();
        assert_eq!(Hash::compute(&buf), hash2);

        buf.clear();
        buf.resize(OBJECT_MAX_SIZE - 69 - 42, 0);
        read_exact_at(&mut file, &mut buf, 69).unwrap();
        assert_eq!(Hash::compute(&buf), hash3);
    }

    #[test]
    fn test_create_for_append() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let filename = tmpdir.path().join("foo");
        assert!(create_for_append(&filename).is_ok());
        assert!(create_for_append(&filename).is_err());
    }

    #[test]
    fn test_open_for_append() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let filename = tmpdir.path().join("foo");
        assert!(open_for_append(&filename).is_err());
        assert!(create_for_append(&filename).is_ok());
        assert!(open_for_append(&filename).is_ok());
    }

    #[test]
    fn test_positional_reads_plus_append_only_writes() {
        // Make sure we are getting the same semantics cross-platform.
        // Note seek_read() moves the freakin' cursor, but in theory
        // we should get the same write behavior if we open in append mode.

        let tmpdir = tempfile::TempDir::new().unwrap();
        let filename = tmpdir.path().join("foo.data");

        let count = 128;
        let mut map: HashMap<Hash, (usize, u64)> = HashMap::new();
        let mut data: Vec<u8> = Vec::with_capacity(65536);
        let mut offset = 0;

        let mut file = create_for_append(&filename).unwrap();
        for _ in 0..count {
            let mut sizebuf = [0; 2];
            getrandom::fill(&mut sizebuf).unwrap();
            let size = u16::from_le_bytes(sizebuf) as usize + 1;
            assert!((1..=65536).contains(&size));

            data.resize(size, 0);
            getrandom::fill(&mut data).unwrap();
            let hash = Hash::compute(&data);
            file.write_all(&data).unwrap();
            assert!(map.insert(hash, (size, offset)).is_none());
            offset += size as u64;

            for (hash, (size, off)) in &map {
                data.resize(*size, 0);
                read_exact_at(&file, &mut data, *off).unwrap();
                assert_eq!(hash, &Hash::compute(&data));
            }
        }

        let mut file = open_for_append(&filename).unwrap();
        for _ in 0..count {
            let mut sizebuf = [0; 2];
            getrandom::fill(&mut sizebuf).unwrap();
            let size = u16::from_le_bytes(sizebuf) as usize + 1;
            assert!((1..=65536).contains(&size));

            data.resize(size, 0);
            getrandom::fill(&mut data).unwrap();
            let hash = Hash::compute(&data);
            file.write_all(&data).unwrap();
            assert!(map.insert(hash, (size, offset)).is_none());
            offset += size as u64;

            for (hash, (size, off)) in &map {
                data.resize(*size, 0);
                read_exact_at(&file, &mut data, *off).unwrap();
                assert_eq!(hash, &Hash::compute(&data));
            }
        }
    }
}
