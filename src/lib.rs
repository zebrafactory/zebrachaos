#![forbid(unsafe_code)]
//#![warn(missing_docs)]
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

#[cfg(test)]
pub mod testhelpers;

pub use always::{
    DIGEST, HASH_RANGE, HEADER, HEXDIGEST, INFO, INFO_RANGE, OBJECT_MAX_SIZE, Z32DIGEST,
};
pub use fsutil::{create_for_append, open_for_append, read_exact_at};
pub use hashing::Hash;
pub use index::{Index, Item};
pub use object::{Object, ObjectError, ObjectHeader, ObjectHeaderResult, ObjectResult};
pub use store::{ObjectIter, Store};
