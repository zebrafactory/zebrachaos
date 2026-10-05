#![forbid(unsafe_code, unused_must_use, rustdoc::broken_intra_doc_links)]
#![warn(missing_docs)]
#![cfg_attr(
    all(windows, feature = "nightly"),
    feature(seek_read_exact_seek_write_all)
)]
#![cfg_attr(all(test, windows, feature = "nightly"), feature(core_io_borrowed_buf))]

//! 🦓 🤪 ZebraChaos: A Git-like Content Hash Addressable Object Store.
//!
//!

mod always;
mod fsutil;
mod hashing;
mod object;
mod store;

#[cfg(test)]
pub mod testhelpers;

pub use always::{
    BUF_MAX_LEN, BUF_MIN_LEN, DATA_MAX_LEN, DATA_MIN_LEN, DIGEST, HASH_RANGE, HEADER, HEXDIGEST,
    INFO, INFO_RANGE, Z32DIGEST,
};
pub use fsutil::{create_for_append, open_for_append, read_exact_at};
pub use hashing::Hash;
pub use object::{Object, ObjectError, ObjectHeader, finalize_object};
pub use store::{ObjectIter, Store};
