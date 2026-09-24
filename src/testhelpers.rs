use crate::{DIGEST, HASH_RANGE, HEADER, Hash, INFO_RANGE};
use getrandom;

pub fn random_object(buf: &mut Vec<u8>, small: bool) -> Hash {
    // Generate random 4 byte info (all are valid)
    let mut info = [0; 4];
    getrandom::fill(&mut info).unwrap();
    if small {
        info[2] = 0;
    }
    buf.resize(HEADER, 0);
    buf[INFO_RANGE].copy_from_slice(&info);

    // Resize buffer based on size in info
    let info = u32::from_le_bytes(info);
    let size = ((info & 0x00ffffff) + 1) as usize;
    buf.resize(HEADER + size, 0);

    // Fill data portion of object with random bytes
    getrandom::fill(&mut buf[HEADER..]).unwrap();

    // Compute hash and copy into buffer
    let hash = Hash::compute(&buf[DIGEST..]);
    buf[HASH_RANGE].copy_from_slice(hash.as_bytes());

    // Return hash
    hash
}

pub fn random_hash() -> Hash {
    let mut buf = [0; DIGEST];
    getrandom::fill(&mut buf).unwrap();
    Hash::from_bytes(buf)
}
