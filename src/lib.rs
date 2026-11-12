#![forbid(unsafe_code, unused_must_use, rustdoc::broken_intra_doc_links)]
#![warn(missing_docs)]
#![cfg_attr(
    all(windows, feature = "nightly"),
    feature(seek_read_exact_seek_write_all)
)]
#![cfg_attr(all(test, windows, feature = "nightly"), feature(core_io_borrowed_buf))]

//! # 🦓 🤪 ZebraChaos: A Content Hash Addressable Object Store.
//!
//! ZebraChaos is for storing filesystem shapshots as Merkle trees. It's a lot like Git, minus all
//! the higher level version control features.
//!
//! In combitation with [ZebraChain](https://github.com/zebrafactory/zebrachain), ZebraChaos is designed
//! to tighted up the security of software build and delivery systems.
//!
//! ##  🚀 Quickstart
//!
//! ```
//! use tempfile;
//! use zf_zebrachaos::{MutObject, Store};
//!
//! let tmpdir = tempfile::TempDir::new().unwrap();
//! let filename = tmpdir.path().join("chaos.data");
//! let mut buf = Vec::new();
//!
//! let hash = {
//!    // Create a store and save our first object:
//!    let mut store = Store::create(&filename).unwrap();
//!    let mut obj = MutObject::new(42, &mut buf);
//!    obj.try_extend_from_slice(b"hello, world").unwrap();
//!    let obj = obj.finalize().unwrap();
//!    assert!(store.save(&obj).unwrap());
//!
//!    // If we save the same object again, we get Ok(false):
//!    assert!(!store.save(&obj).unwrap());
//!    *obj.header().hash()
//! };
//!
//! // Reopen the `Store` load `Object` like this:
//! let mut store = Store::open(&filename).unwrap();
//! let obj = store.load(&hash, &mut buf).unwrap().unwrap();
//! assert_eq!(obj.as_data(), b"hello, world");
//! assert_eq!(obj.header().kind(), 42)
//! ```

mod always;
mod fsutil;
mod hashing;
mod object;
mod store;
mod tree;

#[cfg(test)]
pub mod testhelpers;

pub use always::{
    BUF_MAX_LEN, BUF_MIN_LEN, DATA_MAX_LEN, DATA_MIN_LEN, DIGEST, HASH_RANGE, HEADER, HEXDIGEST,
    INFO, INFO_RANGE, Z32DIGEST,
};
pub use fsutil::{create_for_append, open_for_append, read_exact_at};
pub use hashing::{Hash, HexError, Zbase32Error};
pub use object::{Info, MutObject, Object, ObjectError, ObjectHeader, finalize_object};
pub use store::{ObjectIter, Store};
pub use tree::{Directory, Item, TreeError};
