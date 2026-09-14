#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

//! 🦓 🤪 ZebraChaos: A Git-like Content Hash Addressable Object Store.
//!
//!

mod always;
mod hashing;
mod object;

pub use always::{
    DIGEST, HASH_RANGE, HEADER, HEXDIGEST, INFO, INFO_RANGE, OBJECT_MAX_SIZE, Z32DIGEST,
};
pub use hashing::Hash;
pub use object::{Object, ObjectError, ObjectHeader};
