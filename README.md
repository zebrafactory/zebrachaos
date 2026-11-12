# 🦓 🤪 ZebraChaos: A Content Hash Addressable Object Store.

[![Build Status](https://github.com/zebrafactory/zebrachaos/actions/workflows/rust.yml/badge.svg)](https://github.com/zebrafactory/zebrachaos/actions)

ZebraChaos is for storing filesystem shapshots as Merkle trees. It's a lot like Git, minus all
the higher level version control features.

In combitation with [ZebraChain](https://github.com/zebrafactory/zebrachain), ZebraChaos is designed
to tighted up the security of software build and delivery systems.

## Roadmap

* MVP for saving/loading objects, and encoding/decoding filesystem trees

* FUSE driver for read-only, verify-on-read file system

* Make ZebraChaos `#![no_std]` compatible (with crate feature)

* Rust for Linux kernel driver for mounting by hash a read-only, verify-on-read file system

* Read-write capable FUSE driver

* Read-write capable Rust for Linux kernel driver


## 📜 License

The crate is licensed under either of:

* [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
* [MIT license](http://opensource.org/licenses/MIT)

at your option.

## 🧑‍🏭 Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

## 🤖 AI/LLM Contribution Policy

An open source software project thrives best when a large number of human brains have a deep,
ongoing, and evolving understanding of the project's code, documentation, and procedures.

To understand your contribution, you must write it. Therefore, AI/LLM generated contributions
are not welcome.

## 🖖 Code of Conduct

We follow the [Rust Code of Conduct](http://www.rust-lang.org/conduct.html),
with the following additional clauses:

* We respect the rights to privacy and anonymity for contributors and people in
  the community.  If someone wishes to contribute under a pseudonym different to
  their primary identity, that wish is to be respected by all contributors.

## 🦀 MSRV Policy

The Minimum Supported Rust Version is whatever the current stable Rust release is when a ZebraChaos
release is made.

## 🦀 SemVer Policy

There will be one. There is not one yet and there wont be one till the 0.1.0 release.
