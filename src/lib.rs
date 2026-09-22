#![cfg_attr(all(windows, nightly), feature(seek_read_exact_seek_write_all))]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

//! 🦓 🤪 ZebraChaos: A Git-like Content Hash Addressable Object Store.
//!
//!

mod always;
mod fsutil;
mod hashing;
mod index;
mod object;
mod store;

pub use always::{
    DIGEST, HASH_RANGE, HEADER, HEXDIGEST, INFO, INFO_RANGE, OBJECT_MAX_SIZE, Z32DIGEST,
};
pub use hashing::Hash;
pub use index::{Index, Item};
pub use object::{Object, ObjectError, ObjectHeader, ObjectHeaderResult, ObjectResult};
